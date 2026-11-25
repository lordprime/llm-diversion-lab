"""The model gateway's proxy: a per-run, inference-only passthrough in front of Ollama.

It is the security boundary between untrusted agent cells and the shared GPU model
server. Each cell's LLM tap forwards here; nothing else in a cell can reach it.

A request passes only if it carries a live run key (``Authorization: Bearer``,
``x-api-key`` or ``api-key``, whichever the client sends), uses an allow-listed
endpoint (:mod:`control.gateway.policy`) and names its run's model. It then goes to
``LAB_OLLAMA_URL`` with its body byte for byte and only allow-listed headers (never the
run key), and the answer streams back chunk by chunk, also byte for byte, so the tap
records exactly what Ollama sent. Model lists (``/api/tags``, ``/v1/models``) are the
one exception: the gateway answers them itself, narrowed to the run's models. Every
refusal is the gateway's own JSON answer,
``{"error": {"type": "gateway_refused", "reason": ...}}``, and the tap records it like
any other response.

Limits that keep a hostile client or a stuck upstream from holding the gateway: a
request body cap and a deadline for receiving it, connect and per-read timeouts to
Ollama, and an overall deadline per request that also ends a stream that drips. A
stream cut short is never ended cleanly: the client sees a broken response, not a
complete-looking one.
"""

from __future__ import annotations

import json
import logging
from typing import Final

import anyio
import httpx
from starlette.datastructures import Headers
from starlette.requests import ClientDisconnect, Request
from starlette.responses import JSONResponse, Response
from starlette.types import Receive, Scope, Send

from control.gateway.asgi import UPSTREAM_ERROR, BodyReader, Refused, serve_lifespan
from control.gateway.config import GatewayConfig
from control.gateway.keys import RunGrant, RunKeys
from control.gateway.policy import (
    Decision,
    Endpoint,
    EndpointPolicy,
    Listing,
    ModelPolicy,
    ModelRefused,
)

__all__ = ["FORWARD_HEADERS", "HOP_BY_HOP", "KEY_HEADERS", "ModelProxy"]

log = logging.getLogger(__name__)

#: The headers a client may pass on to Ollama. Everything else stays behind: the run
#: key, cookies, forwarding and hop-by-hop headers.
FORWARD_HEADERS: Final = (
    "content-type",
    "accept",
    "user-agent",
    "anthropic-version",
    "anthropic-beta",
    "openai-beta",
)
#: Where a client may put its run key.
KEY_HEADERS: Final = ("authorization", "x-api-key", "api-key")
#: Response headers that describe one connection, not the body.
HOP_BY_HOP: Final = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "content-length",
    }
)
#: The most a model list from Ollama may weigh.
MAX_LISTING_BYTES: Final = 4 << 20


class _UpstreamStream:
    """An ASGI response that relays an open upstream response chunk by chunk.

    The client going away cancels the relay at once and closes the upstream
    connection, so Ollama stops generating. Past the deadline, or when Ollama breaks
    off, the relay stops without ending the body: the server then drops the
    connection and the client sees an incomplete response.
    """

    def __init__(self, upstream: httpx.Response, deadline: float, label: str) -> None:
        self._upstream = upstream
        self._deadline = deadline
        self._label = label

    def _headers(self) -> list[tuple[bytes, bytes]]:
        named = {
            token.strip().lower()
            for value in self._upstream.headers.get_list("connection")
            for token in value.split(",")
        }
        out = []
        for name, value in self._upstream.headers.raw:
            lower = name.lower()
            if lower.decode("latin-1") not in HOP_BY_HOP | named:
                out.append((lower, value))
        return out

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await send(
                {
                    "type": "http.response.start",
                    "status": self._upstream.status_code,
                    "headers": self._headers(),
                }
            )
            async with anyio.create_task_group() as group:
                group.start_soon(self._watch, receive, group.cancel_scope)
                await self._relay(send)
                group.cancel_scope.cancel()
        finally:
            with anyio.CancelScope(shield=True):
                await self._upstream.aclose()

    async def _watch(self, receive: Receive, scope: anyio.CancelScope) -> None:
        while (await receive())["type"] != "http.disconnect":
            pass
        log.info("gateway: %s: the client went away mid-stream; closing upstream", self._label)
        scope.cancel()

    async def _relay(self, send: Send) -> None:
        chunks = self._upstream.aiter_raw()
        sent = 0
        while True:
            remaining = max(self._deadline - anyio.current_time(), 0.0)
            try:
                with anyio.fail_after(remaining):
                    chunk = await anext(chunks)
            except StopAsyncIteration:
                break
            except TimeoutError:
                log.warning("gateway: %s: request deadline passed mid-stream; cut off", self._label)
                return
            except httpx.HTTPError as exc:
                log.warning("gateway: %s: upstream broke off: %s", self._label, type(exc).__name__)
                return
            if chunk:
                sent += len(chunk)
                try:
                    await send({"type": "http.response.body", "body": chunk, "more_body": True})
                except OSError:
                    return  # the client is gone
        await send({"type": "http.response.body", "body": b"", "more_body": False})
        log.info("gateway: %s -> %d (%d bytes)", self._label, self._upstream.status_code, sent)


class ModelProxy:
    """The cell-facing ASGI app: authenticate, check, forward, stream back."""

    def __init__(
        self,
        config: GatewayConfig,
        keys: RunKeys,
        *,
        policy: EndpointPolicy | None = None,
    ) -> None:
        self._config = config
        self._keys = keys
        self._policy = policy or EndpointPolicy()
        self._bodies = BodyReader(config.max_body_bytes, config.body_timeout_s)
        self._client: httpx.AsyncClient | None = None

    async def startup(self) -> None:
        if self._client is None:
            timeout = httpx.Timeout(
                connect=self._config.connect_timeout_s,
                read=self._config.read_timeout_s,
                write=self._config.body_timeout_s,
                pool=self._config.connect_timeout_s,
            )
            # no redirects and no proxy settings from the environment: Ollama only
            self._client = httpx.AsyncClient(
                timeout=timeout, follow_redirects=False, trust_env=False
            )

    async def shutdown(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "lifespan":
            await serve_lifespan(receive, send, self.startup, self.shutdown)
            return
        if scope["type"] != "http":
            return  # no websockets: the server refuses the handshake
        try:
            response = await self._handle(Request(scope, receive))
        except ClientDisconnect:
            return
        await response(scope, receive, send)

    async def _handle(self, request: Request) -> Response | _UpstreamStream:
        raw = request.scope.get("raw_path")
        path = raw.partition(b"?")[0].decode("latin-1") if isinstance(raw, bytes) else ""
        label = f"{request.method} {path[:100]!r}"
        try:
            grant = self._authenticate(request.headers)
            label = f"run {grant.run_id} {label}"
            endpoint = self._route(request, path, grant)
            encoding = request.headers.get("content-encoding", "identity").strip().lower()
            if encoding != "identity":
                raise Refused(415, "compressed request bodies are not accepted")
            body = await self._bodies.read(request)
            if endpoint.names_model:
                self._check_model(grant, endpoint, body)
            if endpoint.listing is not None:
                return await self._listing(endpoint, grant)
            return await self._forward(endpoint, request, body, label)
        except Refused as refused:
            log.warning("gateway: %s refused %d: %s", label, refused.status, refused.reason)
            return refused.response()

    def _authenticate(self, headers: Headers) -> RunGrant:
        keys: set[str] = set()
        for name in KEY_HEADERS:
            for raw in headers.getlist(name):
                value = raw.strip()
                if name == "authorization":
                    scheme, _, value = value.partition(" ")
                    if scheme.lower() != "bearer":
                        raise Refused(401, "unsupported authorization scheme")
                    value = value.strip()
                if value:
                    keys.add(value)
        if not keys:
            raise Refused(401, "no run key")
        if len(keys) > 1:
            raise Refused(401, "conflicting run keys")
        grant = self._keys.lookup(keys.pop())
        if grant is None:
            raise Refused(401, "unknown, revoked or expired run key")
        return grant

    def _route(self, request: Request, path: str, grant: RunGrant) -> Endpoint:
        query = request.scope.get("query_string", b"").decode("latin-1")
        ruling = self._policy.decide(request.method, path, query, embeddings=grant.embeddings)
        if ruling.decision is Decision.DENY or ruling.endpoint is None:
            raise Refused(404, ruling.reason)
        return ruling.endpoint

    @staticmethod
    def _check_model(grant: RunGrant, endpoint: Endpoint, body: bytes) -> None:
        try:
            model = ModelPolicy(grant.models).check(body, endpoint.path)
        except ModelRefused as refused:
            raise Refused(403, refused.reason) from None
        if model is None:
            raise Refused(403, "the request names no model")

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("the proxy has not started")
        return self._client

    async def _open(self, request: httpx.Request) -> tuple[httpx.Response, float]:
        """Send ``request`` to Ollama; the response with its body still to read."""
        deadline = anyio.current_time() + self._config.max_request_s
        try:
            with anyio.fail_after(self._config.max_request_s):
                response = await self._http().send(request, stream=True)
        except (httpx.TimeoutException, TimeoutError):
            raise Refused(504, "the model server did not answer in time", UPSTREAM_ERROR) from None
        except httpx.HTTPError:
            raise Refused(502, "the model server is unavailable", UPSTREAM_ERROR) from None
        return response, deadline

    async def _forward(
        self, endpoint: Endpoint, request: Request, body: bytes, label: str
    ) -> _UpstreamStream:
        headers = {n: v for n in FORWARD_HEADERS if (v := request.headers.get(n)) is not None}
        headers["accept-encoding"] = "identity"
        query = request.scope.get("query_string", b"").decode("latin-1")
        url = self._config.upstream_base + endpoint.path + (f"?{query}" if query else "")
        upstream = self._http().build_request(endpoint.method, url, headers=headers, content=body)
        response, deadline = await self._open(upstream)
        return _UpstreamStream(response, deadline, label)

    async def _listing(self, endpoint: Endpoint, grant: RunGrant) -> Response:
        """Ollama's model list, narrowed to the run's models (the gateway's own answer)."""
        upstream = self._http().build_request(
            "GET",
            self._config.upstream_base + endpoint.path,
            headers={"accept": "application/json", "accept-encoding": "identity"},
        )
        response, _ = await self._open(upstream)
        try:
            if response.status_code != 200:
                raise Refused(
                    502, f"the model server answered {response.status_code}", UPSTREAM_ERROR
                )
            content = b""
            async for chunk in response.aiter_raw():
                content += chunk
                if len(content) > MAX_LISTING_BYTES:
                    raise Refused(502, "the model list is too large", UPSTREAM_ERROR)
        except httpx.HTTPError:
            raise Refused(502, "the model server broke off", UPSTREAM_ERROR) from None
        finally:
            await response.aclose()
        field_name = "models" if endpoint.listing is Listing.OLLAMA_TAGS else "data"
        id_name = "name" if endpoint.listing is Listing.OLLAMA_TAGS else "id"
        try:
            document = json.loads(content)
            entries = document[field_name]
            if not isinstance(entries, list):
                raise TypeError(field_name)
        except (ValueError, TypeError, KeyError):
            raise Refused(502, "the model server's list is malformed", UPSTREAM_ERROR) from None
        allowed = ModelPolicy(grant.models).allowed
        kept = [e for e in entries if isinstance(e, dict) and e.get(id_name) in allowed]
        return JSONResponse({**document, field_name: kept})
