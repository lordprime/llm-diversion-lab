"""HTTP callback catcher: a catch-all ASGI app that records every request.

Any method, any path, any Host. For every request it records, on stream
``catcher-http`` (:mod:`cell.catcher.callback_log`), one :class:`Callback` with the
method, the request target exactly as sent (raw path plus ``?query``) in ``url``, the
query string, the Host, the ordered raw header list, the body and the source IP, and
only then answers with one fixed, neutral response, identical across
arms: ``200`` ``{"ok":true}`` (``content-type: application/json``). A WebSocket
handshake is recorded the same way (method ``GET``) and answered with the same
response where the server supports it, else closed.

Bodies are bounded: at most :data:`MAX_INLINE_BODY` (64 KiB) is kept inline
(``body_b64``); the rest is read and discarded, while ``body_size`` and
``body_sha256`` are computed over the *whole* body and ``body_truncated`` records the
cut. Token search sees only the inline part. Together with uvicorn's
``limit_concurrency`` (:data:`LIMIT_CONCURRENCY`; excess connections get 503) this
bounds memory, so an agent "exfiltrating a dump" to the lab URL is recorded instead of
getting the catcher OOM-killed.

``token``/``placement_id`` are set only when a well-formed token verifies against the
run's manifest (:meth:`~cell.catcher.classify.TokenIndex.find`). Texts are searched in
this order and the first verified token wins: the path (``/r/<token>``), the Host
(``<token>.cb.lab.test``), the query, the body, then header values. Otherwise both are
``None`` and the request is still recorded. The catcher holds no secrets and never
classifies leaks; the labeller does that later from the raw evidence.

If the event cannot be stored the request fails (500) instead of being answered and
``catcher: cannot record HTTP request ...`` is printed to stderr
(:func:`~cell.catcher.callback_log.report_record_failure`), which makes the runner
mark the run ``RECORDING_FAILED``: evidence loss is loud. HTTPS is not served in M0.

Run (one process per cell; it serves every port itself so one ``seq`` counter is
used)::

    python -m cell.catcher.http_app

with the :class:`~cell.catcher.callback_log.CatcherConfig` variables plus
``LAB_CATCHER_HTTP_PORTS`` (default ``80,8080``) and ``LAB_CATCHER_BIND`` (default
all interfaces).
"""

from __future__ import annotations

import base64
import hashlib
import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import partial
from typing import Final

from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send

from cell.catcher.callback_log import (
    CATCHER_HTTP_STREAM,
    HTTP_EVENTS_FILE,
    CallbackLog,
    CatcherConfig,
    parse_port,
    report_record_failure,
)
from cell.catcher.classify import TokenIndex
from control.core.models import Callback, CallbackChannel

__all__ = [
    "FIXED_BODY",
    "FIXED_HEADERS",
    "FIXED_STATUS",
    "LIMIT_CONCURRENCY",
    "MAX_INLINE_BODY",
    "BodyReader",
    "CatcherApp",
    "HttpContact",
    "ReceivedBody",
    "contact_from_scope",
    "http_callback",
    "main",
    "parse_ports",
]

#: The one response every request gets, in every arm.
FIXED_STATUS: Final = 200
FIXED_BODY: Final = b'{"ok":true}'
FIXED_HEADERS: Final = (
    (b"content-type", b"application/json"),
    (b"content-length", str(len(FIXED_BODY)).encode("ascii")),
)
#: Most body bytes kept inline per request; the rest is hashed, counted and dropped.
MAX_INLINE_BODY: Final = 64 * 1024
#: uvicorn ``limit_concurrency``: worst-case inline memory is about cap x this.
LIMIT_CONCURRENCY: Final = 64


@dataclass(frozen=True, slots=True)
class ReceivedBody:
    """A request body as recorded: the inline prefix plus size and hash of the whole."""

    inline: bytes
    size: int
    sha256: str

    @property
    def truncated(self) -> bool:
        return self.size > len(self.inline)

    @classmethod
    def of(cls, data: bytes, cap: int = MAX_INLINE_BODY) -> ReceivedBody:
        reader = BodyReader(cap)
        reader.feed(data)
        return reader.result()


class BodyReader:
    """Incrementally keeps the first ``cap`` bytes and hashes/counts all of them."""

    def __init__(self, cap: int = MAX_INLINE_BODY) -> None:
        if cap < 0:
            raise ValueError("cap must be non-negative")
        self._cap = cap
        self._inline = bytearray()
        self._size = 0
        self._sha = hashlib.sha256()

    def feed(self, chunk: bytes) -> None:
        self._size += len(chunk)
        self._sha.update(chunk)
        room = self._cap - len(self._inline)
        if room > 0:
            self._inline += chunk[:room]

    def result(self) -> ReceivedBody:
        return ReceivedBody(bytes(self._inline), self._size, self._sha.hexdigest())


@dataclass(frozen=True, slots=True)
class HttpContact:
    """What the catcher saw of one HTTP request."""

    ts: datetime
    method: str
    target: str
    path: str
    query: str | None
    host: str | None
    headers: tuple[tuple[str, str], ...]
    body: ReceivedBody
    source_ip: str | None


def _latin1(value: object) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("latin-1")
    return str(value)


def contact_from_scope(scope: Scope, body: ReceivedBody, ts: datetime) -> HttpContact:
    """Build an :class:`HttpContact` from an ASGI ``http``/``websocket`` scope (pure)."""
    raw_path = scope.get("raw_path")
    path = _latin1(raw_path) if raw_path else str(scope.get("path") or "/")
    query = _latin1(scope.get("query_string") or b"")
    headers = tuple((_latin1(n), _latin1(v)) for n, v in scope.get("headers") or [])
    host = next((v for n, v in headers if n.lower() == "host"), None)
    client = scope.get("client")
    return HttpContact(
        ts=ts,
        method=str(scope.get("method") or "GET"),
        target=f"{path}?{query}" if query else path,
        path=path,
        query=query or None,
        host=host,
        headers=headers,
        body=body,
        source_ip=str(client[0]) if client else None,
    )


def http_callback(contact: HttpContact, seq: int, *, run_id: str, tokens: TokenIndex) -> Callback:
    """The :class:`Callback` event for one request (pure; tokens from the inline body)."""
    texts = [
        contact.path,
        contact.host or "",
        contact.query or "",
        contact.body.inline.decode("utf-8", errors="replace"),
        *(value for _, value in contact.headers),
    ]
    match = tokens.find(texts)
    return Callback(
        run_id=run_id,
        stream=CATCHER_HTTP_STREAM,
        seq=seq,
        ts=contact.ts,
        channel=CallbackChannel.HTTP,
        source_ip=contact.source_ip,
        token=match[0] if match else None,
        placement_id=match[1] if match else None,
        method=contact.method,
        url=contact.target,
        host=contact.host,
        headers=list(contact.headers),
        query=contact.query,
        body_b64=base64.b64encode(contact.body.inline).decode("ascii"),
        body_size=contact.body.size,
        body_sha256=contact.body.sha256,
        body_truncated=contact.body.truncated,
    )


async def _read_body(receive: Receive, cap: int) -> ReceivedBody:
    """Read the whole body, keeping at most ``cap`` bytes (a disconnect ends it early)."""
    reader = BodyReader(cap)
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        reader.feed(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return reader.result()


class CatcherApp:
    """The catch-all ASGI application for one run."""

    def __init__(
        self,
        config: CatcherConfig,
        log: CallbackLog | None = None,
        *,
        max_inline_body: int = MAX_INLINE_BODY,
    ) -> None:
        self._config = config
        self._cap = max_inline_body
        self._log = log or CallbackLog(
            config.run_id, CATCHER_HTTP_STREAM, config.evidence_dir / HTTP_EVENTS_FILE
        )

    @property
    def log(self) -> CallbackLog:
        return self._log

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        kind = scope["type"]
        if kind == "lifespan":
            await self._lifespan(receive, send)
        elif kind == "http":
            ts = datetime.now(UTC)
            body = await _read_body(receive, self._cap)
            await self._record(contact_from_scope(scope, body, ts))
            await send(
                {"type": "http.response.start", "status": FIXED_STATUS, "headers": FIXED_HEADERS}
            )
            await send({"type": "http.response.body", "body": FIXED_BODY})
        elif kind == "websocket":
            ts = datetime.now(UTC)
            await receive()  # websocket.connect
            await self._record(contact_from_scope(scope, ReceivedBody.of(b""), ts))
            if "websocket.http.response" in (scope.get("extensions") or {}):
                await send(
                    {
                        "type": "websocket.http.response.start",
                        "status": FIXED_STATUS,
                        "headers": FIXED_HEADERS,
                    }
                )
                await send({"type": "websocket.http.response.body", "body": FIXED_BODY})
            else:
                await send({"type": "websocket.close", "code": 1000})

    async def _record(self, contact: HttpContact) -> None:
        build = partial(
            http_callback, contact, run_id=self._config.run_id, tokens=self._config.tokens
        )
        try:
            await run_in_threadpool(self._log.record, build)
        except Exception as exc:
            report_record_failure("HTTP request", exc)
            raise

    @staticmethod
    async def _lifespan(receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


# --------------------------------------------------------------------------- entrypoint


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse ``LAB_CATCHER_HTTP_PORTS`` (comma-separated, at least one, no duplicates)."""
    ports = [parse_port(p, "LAB_CATCHER_HTTP_PORTS") for p in value.split(",") if p.strip()]
    if not ports:
        raise ValueError("LAB_CATCHER_HTTP_PORTS: no ports")
    if len(set(ports)) != len(ports):
        raise ValueError("LAB_CATCHER_HTTP_PORTS: duplicate port")
    return tuple(ports)


def main() -> None:  # pragma: no cover - exercised in the cell, not in unit tests
    import uvicorn

    config = CatcherConfig.from_env(os.environ)
    ports = parse_ports(os.environ.get("LAB_CATCHER_HTTP_PORTS", "80,8080"))
    bind = os.environ.get("LAB_CATCHER_BIND", "")
    family = socket.AF_INET6 if ":" in bind else socket.AF_INET
    sockets = [socket.create_server((bind, port), family=family) for port in ports]
    server = uvicorn.Server(
        uvicorn.Config(
            CatcherApp(config),
            lifespan="on",
            proxy_headers=False,  # record the real peer, never X-Forwarded-For
            limit_concurrency=LIMIT_CONCURRENCY,  # bounds memory: ~cap x concurrency
            server_header=False,
            access_log=False,
            log_level="info",
        )
    )
    server.run(sockets=sockets)


if __name__ == "__main__":  # pragma: no cover
    main()
