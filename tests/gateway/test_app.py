"""The gateway over real sockets: a fake Ollama behind it, hostile clients in front."""

from __future__ import annotations

import base64
import contextlib
import gc
import hashlib
import json
import secrets
import select
import socket
import subprocess
import sys
import threading
import time
import tracemalloc
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from control.gateway.admin import AdminApi
from control.gateway.app import ModelProxy
from control.gateway.config import GatewayConfig, GatewayConfigError, Listener
from control.gateway.keys import RunKeys, key_sha256
from control.gateway.policy import MAX_JSON_SEPARATORS
from control.gateway.server import Gateway
from tests.gateway.conftest import (
    NDJSON_CHUNKS,
    SHOW,
    SSE_CHUNKS,
    DripServer,
    FakeOllama,
    LiveServer,
    body_of,
    raw_http,
    status_of,
)
from tests.gateway.test_policy import (
    BRACE_STRINGS,
    MANAGEMENT,
    PATH_TRICKS,
    WORST_UNDER_THE_CAPS,
    js_history,
    many_members,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SECRET = secrets.token_urlsafe(32)
KEY = secrets.token_urlsafe(32)
MODEL = "qwen3:14b"
CHAT = json.dumps({"model": MODEL, "messages": [{"role": "user", "content": "hi"}]}).encode()


@dataclass
class Running:
    proxy: str
    admin: str
    keys: RunKeys


def _config(upstream: str, **overrides: Any) -> GatewayConfig:
    values: dict[str, Any] = {
        "upstream": upstream,
        "listen": Listener("172.31.232.10", 4000),
        "admin_listen": Listener("172.31.231.20", 4001),
        "admin_secret": SECRET,
        **overrides,
    }
    return GatewayConfig(**values)


@pytest.fixture
def gateway_for(fake: FakeOllama) -> Iterator[Callable[..., Running]]:
    with contextlib.ExitStack() as stack:

        def make(upstream: str | None = None, **overrides: Any) -> Running:
            config = _config(upstream or fake.url, **overrides)
            keys = RunKeys()
            keys.register("run_a", key_sha256(KEY), [MODEL], datetime.now(UTC) + timedelta(hours=1))
            proxy = stack.enter_context(LiveServer(ModelProxy(config, keys)))
            admin = stack.enter_context(LiveServer(AdminApi(config, keys)))
            return Running(proxy.url, admin.url, keys)

        yield make


@pytest.fixture
def gw(gateway_for: Callable[..., Running]) -> Running:
    return gateway_for()


def _auth(key: str = KEY) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


def _refusal(response: httpx.Response) -> str:
    doc = response.json()
    assert set(doc) == {"error"}
    assert doc["error"]["type"] in ("gateway_refused", "gateway_upstream_error")
    reason = doc["error"]["reason"]
    assert isinstance(reason, str) and reason
    return reason


def _raw(method: str, target: str, *headers: str, body: bytes = b"") -> bytes:
    lines = [f"{method} {target} HTTP/1.1", "host: gateway", *headers, "connection: close"]
    if body and not any(
        h.lower().startswith(("content-length", "transfer-encoding")) for h in headers
    ):
        lines.append(f"content-length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body


# --------------------------------------------------------------------------- endpoints


@pytest.mark.parametrize("path", [p for p in MANAGEMENT if p.startswith("/")])
@pytest.mark.parametrize("method", ["GET", "POST", "DELETE", "PUT", "HEAD"])
def test_denies_management_endpoints(gw: Running, fake: FakeOllama, method: str, path: str) -> None:
    response = httpx.request(method, gw.proxy + path, headers=_auth(), content=CHAT)
    assert response.status_code == 404
    if method != "HEAD":
        assert "not allowed" in _refusal(response)
    assert fake.seen == []


@pytest.mark.parametrize("target", [p for p in PATH_TRICKS if p and " " not in p])
def test_path_tricks_never_reach_ollama(gw: Running, fake: FakeOllama, target: str) -> None:
    raw = _raw("POST", target.replace("\x00", "%00"), f"authorization: Bearer {KEY}", body=CHAT)
    response = raw_http(gw.proxy, raw)
    assert status_of(response) in (400, 404), response[:200]
    assert fake.seen == []


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/api/chat", CHAT),
        ("/api/generate", json.dumps({"model": MODEL, "prompt": "hi"}).encode()),
        ("/v1/chat/completions", CHAT),
        ("/v1/messages?beta=true", CHAT),
    ],
)
def test_inference_reaches_ollama_at_the_same_path(
    gw: Running, fake: FakeOllama, path: str, body: bytes
) -> None:
    response = httpx.post(gw.proxy + path, headers=_auth(), content=body)
    assert response.status_code == 200
    assert response.content == b"".join(NDJSON_CHUNKS)
    (seen,) = fake.seen
    assert (seen.method, seen.path) == ("POST", path.partition("?")[0])
    assert seen.query == path.partition("?")[2]
    assert seen.body == body


# --------------------------------------------------------------------------- keys


@pytest.mark.parametrize(
    "headers",
    [
        {"authorization": f"Bearer {KEY}"},
        {"authorization": f"bearer {KEY}"},
        {"x-api-key": KEY},
        {"api-key": KEY},
        {"authorization": f"Bearer {KEY}", "x-api-key": KEY},
        {"x-api-key": KEY, "api-key": ""},
    ],
)
def test_every_client_key_header_is_accepted(
    gw: Running, fake: FakeOllama, headers: dict[str, str]
) -> None:
    response = httpx.post(gw.proxy + "/api/chat", headers=headers, content=CHAT)
    assert response.status_code == 200, response.text
    # the run key never travels on to Ollama
    assert not fake.seen[0].header_names() & {"authorization", "x-api-key", "api-key"}


def test_unknown_or_revoked_key_is_401(gw: Running, fake: FakeOllama) -> None:
    other = secrets.token_urlsafe(32)
    refused: list[dict[str, str]] = [
        {},
        {"authorization": f"Bearer {other}"},
        {"authorization": f"Basic {KEY}"},
        {"authorization": KEY},
        {"authorization": "Bearer"},
        {"authorization": f"Bearer {key_sha256(KEY)}"},  # the hash is not the key
        {"x-goog-api-key": KEY},
        {"cookie": f"key={KEY}"},
        {"authorization": f"Bearer {KEY}", "x-api-key": other},  # two different keys
        {"x-api-key": KEY, "api-key": other},
    ]
    for headers in refused:
        response = httpx.post(gw.proxy + "/api/chat", headers=headers, content=CHAT)
        assert response.status_code == 401, headers
        assert response.json()["error"]["type"] == "gateway_refused"
    # a key in the query string is not a key
    response = httpx.post(gw.proxy + f"/v1/messages?key={KEY}", content=CHAT)
    assert response.status_code == 401
    # two Authorization headers
    raw = _raw(
        "POST",
        "/api/chat",
        f"authorization: Bearer {KEY}",
        f"authorization: Bearer {other}",
        body=CHAT,
    )
    assert status_of(raw_http(gw.proxy, raw)) == 401
    assert fake.seen == []
    # revoked, then the same key again
    assert httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT).status_code == 200
    gw.keys.revoke("run_a")
    assert httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT).status_code == 401
    assert len(fake.seen) == 1


def test_an_unauthenticated_client_learns_nothing_about_endpoints(gw: Running) -> None:
    for path in ("/api/pull", "/api/chat", "/nope"):
        assert httpx.post(gw.proxy + path, content=CHAT).status_code == 401


# --------------------------------------------------------------------------- models


def test_only_the_exact_granted_model_passes(gw: Running, fake: FakeOllama) -> None:
    body = json.dumps({"model": MODEL, "messages": []}).encode()
    assert httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body).status_code == 200
    assert fake.seen[0].body == body
    for model in ("ollama/" + MODEL, "ollama_chat/" + MODEL):
        body = json.dumps({"model": model, "messages": []}).encode()
        response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body)
        assert response.status_code == 403, model
    assert len(fake.seen) == 1


@pytest.mark.parametrize(
    "body",
    [
        json.dumps({"model": "qwen3:32b", "messages": []}).encode(),
        json.dumps({"model": "llama3:8b", "messages": []}).encode(),
        json.dumps({"messages": []}).encode(),
        b"not json",
        b"",
        b'{"model": "qwen3:14b", "MODEL": "llama3:8b"}',
        b'{"model": "qwen3:14b", "model": "llama3:8b"}',
    ],
)
def test_model_must_match_grant(gw: Running, fake: FakeOllama, body: bytes) -> None:
    response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body)
    assert response.status_code == 403
    _refusal(response)
    assert fake.seen == []


def test_a_compressed_request_body_is_refused(gw: Running, fake: FakeOllama) -> None:
    headers = {**_auth(), "content-encoding": "gzip"}
    response = httpx.post(gw.proxy + "/api/chat", headers=headers, content=CHAT)
    assert response.status_code == 415
    assert fake.seen == []


# --------------------------------------------------------------------------- filtered


def test_tags_and_show_filtered_to_grant(gw: Running, fake: FakeOllama) -> None:
    tags = httpx.get(gw.proxy + "/api/tags", headers=_auth())
    assert tags.status_code == 200
    assert [m["name"] for m in tags.json()["models"]] == [MODEL]
    models = httpx.get(gw.proxy + "/v1/models", headers=_auth())
    assert models.status_code == 200
    assert models.json()["object"] == "list"
    assert [m["id"] for m in models.json()["data"]] == [MODEL]

    show = httpx.post(gw.proxy + "/api/show", headers=_auth(), json={"model": MODEL})
    assert show.status_code == 200
    assert show.content == SHOW  # the granted model's own answer, unchanged
    for body in ({"model": "qwen3:32b"}, {"name": "llama3:8b"}, {"model": MODEL, "name": "x"}):
        response = httpx.post(gw.proxy + "/api/show", headers=_auth(), json=body)
        assert response.status_code == 403, body
    assert fake.paths() == ["/api/tags", "/v1/models", "/api/show"]


def test_listing_requests_carry_no_client_body(gw: Running, fake: FakeOllama) -> None:
    raw = _raw("GET", "/api/tags", f"authorization: Bearer {KEY}", body=b'{"x": 1}')
    assert status_of(raw_http(gw.proxy, raw)) == 200
    assert fake.seen[0].body == b""


# --------------------------------------------------------------------------- streaming


@pytest.mark.parametrize(
    ("path", "chunks", "media_type"),
    [
        ("/api/chat", NDJSON_CHUNKS, "application/x-ndjson"),
        ("/api/generate", NDJSON_CHUNKS, "application/x-ndjson"),
        ("/v1/chat/completions", SSE_CHUNKS, "text/event-stream"),
        ("/v1/messages", SSE_CHUNKS, "text/event-stream"),
    ],
)
def test_streams_ndjson_and_sse_unbuffered(
    gw: Running, fake: FakeOllama, path: str, chunks: tuple[bytes, ...], media_type: str
) -> None:
    fake.mode, fake.chunks, fake.media_type = "gate", chunks, media_type
    with (
        httpx.Client(timeout=5) as client,
        client.stream("POST", gw.proxy + path, headers=_auth(), content=CHAT) as response,
    ):
        assert response.status_code == 200
        assert response.headers["content-type"].startswith(media_type)
        stream = response.iter_raw()
        first = next(stream)
        # the first chunk arrived while Ollama still holds the rest
        assert not fake.release.is_set()
        assert first == chunks[0]
        fake.release.set()
        rest = b"".join(stream)
    assert first + rest == b"".join(chunks)


def test_bytes_pass_through_unchanged(gw: Running, fake: FakeOllama) -> None:
    fake.chunks = (
        b"\xff\xfe not utf-8 \x00\r\n",
        "split multibyte: \u00e9".encode()[:-1],
        "split multibyte: \u00e9".encode()[-1:] + b"\n",
        b"",
        b"\n\n\r\r",
        bytes(range(256)) * 4096,  # one 1 MiB chunk
        b'data: {"x": "\\u0000"}\n\n',
    )
    fake.media_type = "application/octet-stream"
    upstream = hashlib.sha256(b"".join(fake.chunks)).hexdigest()
    # raw UTF-8, an escaped surrogate pair, odd spacing and a number Python reads as inf
    sent = (
        b'{ "model" : "qwen3:14b",\t"prompt": "\xc3\xa9 \\ud83d\\ude00", "x": [1.0, 1e400, -0.0] }'
    )
    with httpx.Client(timeout=10) as client:
        response = client.post(gw.proxy + "/api/generate", headers=_auth(), content=sent)
    assert response.status_code == 200
    assert hashlib.sha256(response.content).hexdigest() == upstream
    # and the request reached Ollama byte for byte
    assert hashlib.sha256(fake.seen[0].body).hexdigest() == hashlib.sha256(sent).hexdigest()


def test_an_upstream_error_passes_through_unchanged(gw: Running, fake: FakeOllama) -> None:
    fake.mode = "error"
    response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT)
    assert response.status_code == 404
    assert response.json() == {"error": "model 'qwen3:14b' not found"}


def test_a_client_disconnecting_mid_stream_closes_the_upstream(
    gw: Running, fake: FakeOllama
) -> None:
    fake.mode = "gate"
    with (
        httpx.Client(timeout=5) as client,
        client.stream("POST", gw.proxy + "/api/chat", headers=_auth(), content=CHAT) as response,
    ):
        assert next(response.iter_raw()) == NDJSON_CHUNKS[0]
    # the client is gone: Ollama must stop generating, not run to the end
    assert fake.closed.wait(5)
    assert not fake.release.is_set()


# --------------------------------------------------------------------------- hostile input


def test_header_smuggling_never_reaches_ollama(gw: Running, fake: FakeOllama) -> None:
    smuggled = b"GET /api/pull HTTP/1.1\r\nhost: ollama\r\n\r\n"
    cases = [
        # Content-Length and Transfer-Encoding together
        _raw(
            "POST",
            "/api/chat",
            f"authorization: Bearer {KEY}",
            f"content-length: {len(CHAT)}",
            "transfer-encoding: chunked",
            body=b"0\r\n\r\n" + smuggled,
        ),
        # two different Content-Lengths
        _raw(
            "POST",
            "/api/chat",
            f"authorization: Bearer {KEY}",
            f"content-length: {len(CHAT)}",
            "content-length: 5",
            body=CHAT + smuggled,
        ),
        # an obs-folded header line
        _raw("POST", "/api/chat", f"authorization: Bearer {KEY}", " x: y", body=CHAT),
    ]
    for raw in cases:
        status = status_of(raw_http(gw.proxy, raw))
        assert status in (0, 400, 401, 403), raw[:120]
    assert "/api/pull" not in fake.paths()
    # a bare LF splits a header in two: harmless, as the extra header stays behind
    raw = _raw("POST", "/api/chat", f"authorization: Bearer {KEY}\nx-evil: 1", body=CHAT)
    assert status_of(raw_http(gw.proxy, raw)) in (200, 400)
    assert all("x-evil" not in s.header_names() for s in fake.seen)
    assert "/api/pull" not in fake.paths()


def test_a_request_smuggled_in_the_body_stays_in_the_body(gw: Running, fake: FakeOllama) -> None:
    body = CHAT + b"\r\n\r\nGET /api/pull HTTP/1.1\r\nhost: ollama\r\n\r\n"
    response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body)
    assert response.status_code == 403  # not one JSON object
    chunked = _raw(
        "POST",
        "/api/chat",
        f"authorization: Bearer {KEY}",
        "transfer-encoding: chunked",
        body=f"{len(CHAT):x}\r\n".encode() + CHAT + b"\r\n0\r\n\r\n",
    )
    assert status_of(raw_http(gw.proxy, chunked)) == 200
    assert fake.paths() == ["/api/chat"]
    assert fake.seen[0].body == CHAT
    # Ollama gets a fixed length, never the client's chunked framing
    names = fake.seen[0].header_names()
    assert "transfer-encoding" not in names and "content-length" in names


def test_only_allow_listed_headers_reach_ollama(gw: Running, fake: FakeOllama) -> None:
    headers = {
        **_auth(),
        "x-api-key": KEY,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-forwarded-for": "10.0.0.1",
        "x-forwarded-host": "ollama",
        "forwarded": "for=1.2.3.4",
        "x-real-ip": "1.2.3.4",
        "connection": "keep-alive, x-secret",
        "x-secret": "1",
        "proxy-authorization": "Basic Zm9vOmJhcg==",
        "cookie": "a=b",
        "te": "trailers",
        "upgrade": "h2c",
        "expect": "100-continue",
        "x-http-method-override": "DELETE",
    }
    response = httpx.post(gw.proxy + "/v1/messages", headers=headers, content=CHAT)
    assert response.status_code == 200
    seen = fake.seen[0]
    assert seen.method == "POST" and seen.path == "/v1/messages"
    names = seen.header_names()
    assert {"content-type", "anthropic-version"} <= names
    assert names <= {
        "host",
        "connection",
        "content-type",
        "content-length",
        "accept",
        "accept-encoding",
        "user-agent",
        "anthropic-version",
        "anthropic-beta",
        "openai-beta",
    }
    assert dict(seen.headers)["host"] == fake.url.removeprefix("http://")
    # the gateway's own keep-alive, never the client's connection header
    assert dict(seen.headers).get("connection", "keep-alive") == "keep-alive"


def test_oversized_bodies_are_refused_before_ollama(
    gateway_for: Callable[..., Running], fake: FakeOllama
) -> None:
    gw = gateway_for(max_body_bytes=1024)
    big = json.dumps({"model": MODEL, "prompt": "x" * 2048}).encode()
    response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=big)
    assert response.status_code == 413
    assert response.json()["error"]["reason"].startswith("body_too_large")
    # a lying or absurd Content-Length
    for length in ("99999999999999999999", "-1", "1e3", "0x10", "1024 1024"):
        raw = _raw("POST", "/api/chat", f"authorization: Bearer {KEY}", f"content-length: {length}")
        assert status_of(raw_http(gw.proxy, raw)) in (400, 413), length
    # chunked, with no length up front: cut off once it passes the limit
    chunks = b"".join(b"100\r\n" + b"x" * 256 + b"\r\n" for _ in range(8)) + b"0\r\n\r\n"
    raw = _raw(
        "POST",
        "/api/chat",
        f"authorization: Bearer {KEY}",
        "transfer-encoding: chunked",
        body=chunks,
    )
    refused = raw_http(gw.proxy, raw)
    assert status_of(refused) == 413
    assert body_of(refused)["error"]["reason"].startswith("body_too_large")
    assert fake.seen == []
    # a body exactly at the limit is fine
    exact = json.dumps({"model": MODEL, "p": ""}).encode()
    exact = exact[:-2] + b"x" * (1024 - len(exact)) + exact[-2:]
    assert len(exact) == 1024
    assert httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=exact).status_code == 200


def test_brace_dense_bodies_pass_and_too_complex_ones_are_413(
    gw: Running, fake: FakeOllama
) -> None:
    # an agent's history of fetched minified JavaScript, strings full of braces, and
    # the costliest body under both caps: they pass, forwarded unchanged
    for body in (js_history(15 << 20), BRACE_STRINGS, WORST_UNDER_THE_CAPS):
        assert len(body) <= 16 << 20
        response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body, timeout=30)
        assert response.status_code == 200
        assert fake.seen[-1].body == body
    forwarded = len(fake.seen)
    # really over a cap: 413 with its own reason, never a 403 that reads like a model
    # swap, and never forwarded. The object of 1.15M members has two brackets.
    too_complex = [
        b'{"model": "qwen3:14b", "x": [' + fill * 2_000_000 + b"[]]}"
        for fill in (b"[],", b"{},", b"[[]],")
    ]
    too_complex.append(
        b'{"model": "qwen3:14b", "o": {'
        + b",".join(b'"k%d":""' % i for i in range(1_150_000))
        + b"}}"
    )
    for body in too_complex:
        response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body, timeout=30)
        assert response.status_code == 413
        assert _refusal(response).startswith("body_too_complex")
    assert len(fake.seen) == forwarded


def test_a_refused_body_is_freed_at_once(gw: Running) -> None:
    # A refusal raised in a parse thread used to sit in a reference cycle with the
    # thread runner's frame, which holds the body: refused bodies piled up until the
    # garbage collector ran (hundreds of MiB). With the collector off, nothing of the
    # three bodies below may stay behind.
    bodies = (
        many_members((MAX_JSON_SEPARATORS - 2) // 2, model="llama3:8b"),  # 403
        b'{"model": "qwen3:14b", "x": [' + b"[]," * 2_000_000 + b"[]]}",  # 413
        b'{"model": "llama3:8b", "e": "\xf0\x9f\x98\x80", "s": "' + b"y" * (12 << 20) + b'"}',
    )
    gc.collect()
    gc.disable()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        for body in bodies:
            response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=body, timeout=30)
            assert response.status_code in (403, 413)
        time.sleep(0.3)
        held = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
        gc.enable()
    assert held < 4 << 20, held >> 20


def test_a_client_that_sends_its_body_too_slowly_is_cut_off(
    gateway_for: Callable[..., Running], fake: FakeOllama
) -> None:
    gw = gateway_for(body_timeout_s=0.5)
    raw = (
        _raw("POST", "/api/chat", f"authorization: Bearer {KEY}", "content-length: 100")
        + b'{"model":'
    )
    started = time.monotonic()
    response = raw_http(gw.proxy, raw, timeout_s=10)
    assert status_of(response) == 408
    assert time.monotonic() - started < 5
    assert fake.seen == []


# --------------------------------------------------------------------------- upstream trouble


def test_upstream_down_is_502_not_hang(gateway_for: Callable[..., Running]) -> None:
    with LiveServer(FakeOllama().app) as gone:
        url = gone.url
    gw = gateway_for(upstream=url)
    started = time.monotonic()
    response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=30)
    assert response.status_code == 502
    assert response.json()["error"]["type"] == "gateway_upstream_error"
    assert time.monotonic() - started < 10
    assert httpx.get(gw.proxy + "/api/tags", headers=_auth(), timeout=30).status_code == 502


def test_an_upstream_that_never_answers_is_504(
    gateway_for: Callable[..., Running], fake: FakeOllama
) -> None:
    fake.mode = "hang"
    gw = gateway_for(read_timeout_s=0.5)
    started = time.monotonic()
    response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=30)
    assert response.status_code == 504
    assert time.monotonic() - started < 5


def test_a_slowloris_upstream_is_cut_off_at_the_request_deadline(
    gateway_for: Callable[..., Running],
) -> None:
    with DripServer(interval_s=0.05) as drip:
        # each byte arrives well inside the read timeout, so only the deadline helps
        gw = gateway_for(upstream=drip.url, read_timeout_s=5, max_request_s=1)
        started = time.monotonic()
        response = httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=30)
        assert response.status_code == 504
        assert time.monotonic() - started < 5


def test_a_dripping_stream_is_aborted_at_the_request_deadline(
    gateway_for: Callable[..., Running], fake: FakeOllama
) -> None:
    fake.mode = "drip"
    gw = gateway_for(read_timeout_s=5, max_request_s=1)
    started = time.monotonic()
    with pytest.raises(httpx.RemoteProtocolError):  # cut off, never a clean end
        httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=30)
    assert time.monotonic() - started < 5
    assert fake.closed.wait(5)


# --------------------------------------------------------------------------- admin


def _grant(digest: str, run_id: str = "run_b", **extra: Any) -> dict[str, Any]:
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    return {
        "run_id": run_id,
        "key_sha256": digest,
        "models": [MODEL],
        "expires_at": expires,
        **extra,
    }


def _admin(secret: str = SECRET) -> dict[str, str]:
    return {"authorization": f"Bearer {secret}"}


def test_admin_api_rejects_without_secret(gw: Running) -> None:
    key = secrets.token_urlsafe(32)
    body = _grant(key_sha256(key))
    for headers in (
        {},
        _admin("wrong"),
        _admin(SECRET[:-1]),
        _admin(SECRET + "x"),
        {"authorization": f"Basic {SECRET}"},
        {"authorization": SECRET},
        {"x-api-key": SECRET},
        _admin(KEY),  # a run key is not the admin secret
    ):
        assert httpx.post(gw.admin + "/admin/grants", headers=headers, json=body).status_code == 401
        assert httpx.delete(gw.admin + "/admin/grants/run_a", headers=headers).status_code == 401
    assert gw.keys.lookup(key) is None
    assert gw.keys.lookup(KEY) is not None  # run_a still granted


def test_admin_grant_and_revoke(gw: Running, fake: FakeOllama) -> None:
    key = secrets.token_urlsafe(32)
    grant = _grant(key_sha256(key))
    response = httpx.post(gw.admin + "/admin/grants", headers=_admin(), json=grant)
    assert response.status_code == 201
    assert key not in response.text and key_sha256(key) not in response.text
    assert httpx.post(gw.proxy + "/api/chat", headers=_auth(key), content=CHAT).status_code == 200
    # the same grant again is fine, another key for the same run is not
    again = httpx.post(gw.admin + "/admin/grants", headers=_admin(), json=grant)
    assert again.status_code == 201
    other = _grant(key_sha256(secrets.token_urlsafe(32)))
    assert httpx.post(gw.admin + "/admin/grants", headers=_admin(), json=other).status_code == 409
    assert httpx.delete(gw.admin + "/admin/grants/run_b", headers=_admin()).status_code == 204
    assert httpx.delete(gw.admin + "/admin/grants/run_b", headers=_admin()).status_code == 204
    assert httpx.post(gw.proxy + "/api/chat", headers=_auth(key), content=CHAT).status_code == 401


@pytest.mark.parametrize(
    "body",
    [
        {"run_id": "run_b"},
        _grant("a" * 64, embeddings="yes"),
        _grant("a" * 64, role="admin"),
        _grant("A" * 64),
        _grant("a" * 64, models=[]),
        _grant("a" * 64, models=["two words"]),
        _grant("a" * 64, run_id="../etc"),
        _grant("a" * 64, expires_at="2020-01-01T00:00:00+00:00"),
        _grant("a" * 64, expires_at="2099-01-01T00:00:00"),
        [],
        "x",
    ],
)
def test_admin_refuses_malformed_grants(gw: Running, body: Any) -> None:
    response = httpx.post(gw.admin + "/admin/grants", headers=_admin(), json=body)
    assert response.status_code in (400, 422)
    assert gw.keys.lookup("a" * 64) is None


def test_admin_refuses_a_non_json_or_huge_body(gw: Running) -> None:
    for content in (b"not json", b"{" * 100_000, b"x" * (1 << 20)):
        response = httpx.post(gw.admin + "/admin/grants", headers=_admin(), content=content)
        assert response.status_code in (400, 413)


def test_the_listeners_do_not_serve_each_other(gw: Running, fake: FakeOllama) -> None:
    body = _grant(key_sha256(secrets.token_urlsafe(32)))
    # the admin API is not on the cell-facing listener, even with the admin secret
    assert httpx.post(gw.proxy + "/admin/grants", headers=_admin(), json=body).status_code == 401
    response = httpx.post(gw.proxy + "/admin/grants", headers=_auth(), json=body)
    assert response.status_code == 404
    # and the proxy is not on the admin listener
    response = httpx.post(gw.admin + "/api/chat", headers={**_admin(), **_auth()}, content=CHAT)
    assert response.status_code == 404
    assert fake.seen == []
    assert httpx.get(gw.admin + "/healthz").status_code == 200


# --------------------------------------------------------------------------- configuration


def test_refuses_to_start_when_both_listeners_share_address_and_port() -> None:
    with pytest.raises(GatewayConfigError, match="admin"):
        _config("http://ollama:11434", admin_listen=Listener("172.31.232.10", 4000))


@pytest.mark.parametrize(
    "overrides",
    [
        {"admin_listen": Listener("0.0.0.0", 4001)},  # noqa: S104 - the case under test
        {"admin_listen": Listener("::", 4001)},
        {"admin_listen": Listener("172.31.232.10", 4001)},  # the cell-facing address
        {"listen": Listener("0.0.0.0", 4000)},  # noqa: S104 - would cover the admin's
        {"admin_secret": "short"},
        {"admin_secret": ""},
        {"upstream": "ftp://ollama:11434"},
        {"upstream": "http://user:pw@ollama:11434"},
        {"upstream": "http://ollama:11434/api"},
        {"upstream": "http://ollama:11434?x=1"},
        {"upstream": "ollama:11434"},
        {"max_body_bytes": 0},
        {"max_request_s": 0},
        {"read_timeout_s": -1},
        {"read_timeout_s": float("nan")},
        {"max_request_s": float("inf")},
        {"header_timeout_s": float("nan")},
        {"body_timeout_s": float("-inf")},
        {"max_inflight_per_run": 0},
        {"max_inflight_per_run": 65, "max_upstream_connections": 64},
        {"max_large_bodies_per_run": 0},
        {"max_connections": 0},
        {"max_connections_per_peer": 0},
        {"max_connections": 64, "max_connections_per_peer": 64},
    ],
)
def test_unsafe_configurations_are_refused(overrides: dict[str, Any]) -> None:
    values = {"upstream": "http://ollama:11434", **overrides}
    with pytest.raises(GatewayConfigError):
        _config(**values)


def test_config_from_env() -> None:
    env = {
        "LAB_OLLAMA_URL": "http://ollama:11434",
        "LAB_GATEWAY_LISTEN": "172.31.232.10:4000",
        "LAB_GATEWAY_ADMIN_LISTEN": "172.31.231.20:4001",
        "LAB_GATEWAY_ADMIN_SECRET": SECRET,
        "LAB_GATEWAY_MAX_BODY_BYTES": "2048",
    }
    config = GatewayConfig.from_env(env)
    assert config.listen == Listener("172.31.232.10", 4000)
    assert config.admin_listen == Listener("172.31.231.20", 4001)
    assert config.max_body_bytes == 2048
    assert SECRET not in repr(config)
    for key in ("LAB_OLLAMA_URL", "LAB_GATEWAY_LISTEN", "LAB_GATEWAY_ADMIN_SECRET"):
        with pytest.raises(GatewayConfigError, match=key):
            GatewayConfig.from_env({k: v for k, v in env.items() if k != key})
    for bad in ("4000", "host:port", "172.31.232.10:0", "172.31.232.10:70000", "[::1]"):
        with pytest.raises(GatewayConfigError):
            GatewayConfig.from_env({**env, "LAB_GATEWAY_LISTEN": bad})
    with pytest.raises(GatewayConfigError):
        GatewayConfig.from_env({**env, "LAB_GATEWAY_MAX_BODY_BYTES": "lots"})
    for name in ("LAB_GATEWAY_READ_TIMEOUT_S", "LAB_GATEWAY_HEADER_TIMEOUT_S"):
        for bad in ("nan", "inf", "-inf"):
            with pytest.raises(GatewayConfigError):
                GatewayConfig.from_env({**env, name: bad})
    tuned = GatewayConfig.from_env({**env, "LAB_GATEWAY_MAX_INFLIGHT_PER_RUN": "4"})
    assert tuned.max_inflight_per_run == 4
    assert GatewayConfig.from_env(env).max_body_bytes == 2048
    assert (
        GatewayConfig.from_env({k: v for k, v in env.items() if "BODY" not in k}).max_body_bytes
        == 16 << 20
    )


def test_the_run_key_never_reaches_the_logs(
    gw: Running, fake: FakeOllama, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT)
    httpx.post(gw.proxy + "/api/chat", headers=_auth(), json={"model": "llama3:8b"})
    httpx.post(gw.proxy + "/api/pull", headers=_auth(), content=CHAT)
    httpx.post(gw.proxy + "/api/chat", headers=_auth(KEY + "x"), content=CHAT)
    text = caplog.text
    assert "llama3:8b" in text  # the refusal is logged ...
    assert KEY not in text and SECRET not in text  # ... without any secret


@contextlib.contextmanager
def full_gateway(upstream: str, keys: RunKeys, **overrides: Any) -> Iterator[GatewayConfig]:
    """The whole gateway process (both listeners) on 127.0.0.1 and 127.0.0.2."""
    proxy_sock = socket.create_server(("127.0.0.1", 0))
    admin_sock = socket.create_server(("127.0.0.2", 0))
    config = _config(
        upstream,
        listen=Listener("127.0.0.1", proxy_sock.getsockname()[1]),
        admin_listen=Listener("127.0.0.2", admin_sock.getsockname()[1]),
        **overrides,
    )
    gateway = Gateway(config, keys)
    thread = threading.Thread(
        target=gateway.run, kwargs={"sockets": [proxy_sock, admin_sock]}, daemon=True
    )
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not gateway.started:
            assert time.monotonic() < deadline and thread.is_alive()
            time.sleep(0.01)
        yield config
    finally:
        gateway.stop()
        thread.join(15)
        proxy_sock.close()
        admin_sock.close()


def _keys(*runs: tuple[str, str, str]) -> RunKeys:
    keys = RunKeys()
    for run_id, key, model in runs:
        keys.register(run_id, key_sha256(key), [model], datetime.now(UTC) + timedelta(hours=1))
    return keys


def test_each_listener_serves_only_its_own_app(fake: FakeOllama) -> None:
    with full_gateway(fake.url, RunKeys()) as config:
        proxy, admin = f"http://{config.listen}", f"http://{config.admin_listen}"
        key = secrets.token_urlsafe(32)
        grant = _grant(key_sha256(key), run_id="run_c")
        assert httpx.post(proxy + "/admin/grants", headers=_admin(), json=grant).status_code == 401
        assert httpx.post(admin + "/admin/grants", headers=_admin(), json=grant).status_code == 201
        assert httpx.post(admin + "/api/chat", headers=_auth(key), content=CHAT).status_code == 404
        response = httpx.post(proxy + "/api/chat", headers=_auth(key), content=CHAT)
        assert response.status_code == 200
        assert response.content == b"".join(NDJSON_CHUNKS)
        assert fake.paths() == ["/api/chat"]


# --------------------------------------------------------------------------- availability


def test_idle_sockets_on_the_proxy_never_reach_the_admin_api(fake: FakeOllama) -> None:
    with full_gateway(
        fake.url,
        _keys(("run_a", KEY, MODEL)),
        max_connections=20,
        max_connections_per_peer=10,
        header_timeout_s=1,
    ) as config:
        proxy, admin = f"http://{config.listen}", f"http://{config.admin_listen}"
        # two peers at their caps fill the whole proxy
        address = (config.listen.host, config.listen.port)
        idle = [
            socket.create_connection(address, source_address=(peer, 0))
            for _ in range(30)
            for peer in ("127.0.0.1", "127.0.0.4")
        ]
        try:
            time.sleep(0.3)
            # the proxy is saturated, the admin API is not
            assert httpx.get(admin + "/healthz", timeout=3).status_code == 200
            grant = _grant(key_sha256(secrets.token_urlsafe(32)), run_id="run_d")
            response = httpx.post(admin + "/admin/grants", headers=_admin(), json=grant, timeout=3)
            assert response.status_code == 201
            assert (
                httpx.delete(admin + "/admin/grants/run_d", headers=_admin(), timeout=3).status_code
                == 204
            )
            # a connection that sends no request head is closed at the head deadline
            for sock in idle[:5]:
                sock.settimeout(5)
                assert sock.recv(1024) == b""
            # half a request head, dripped, is no better
            slow = socket.create_connection((config.listen.host, config.listen.port))
            slow.settimeout(5)
            slow.sendall(b"POST /api/chat HTTP/1.1\r\nhost: x\r\n")
            started = time.monotonic()
            with contextlib.suppress(OSError):
                for _ in range(20):
                    time.sleep(0.2)
                    slow.sendall(b"x-drip: 1\r\n")
            with contextlib.suppress(OSError):
                data = slow.recv(1024)
                assert data == b"" or data.startswith(b"HTTP/1.1 4")
            assert time.monotonic() - started < 4
            slow.close()
        finally:
            for sock in idle:
                sock.close()
        time.sleep(0.2)
        response = httpx.post(proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=5)
        assert response.status_code == 200


def test_one_run_at_its_cap_does_not_affect_another_run(fake: FakeOllama) -> None:
    other = secrets.token_urlsafe(32)
    fake.mode = "gate"
    keys = _keys(("run_a", KEY, MODEL), ("run_b", other, MODEL))
    with (
        full_gateway(fake.url, keys, max_inflight_per_run=2) as config,
        contextlib.ExitStack() as held,
    ):
        proxy = f"http://{config.listen}"
        client = held.enter_context(httpx.Client(timeout=5))
        for _ in range(2):
            stream = held.enter_context(
                client.stream("POST", proxy + "/api/chat", headers=_auth(), content=CHAT)
            )
            assert stream.status_code == 200
        refused = httpx.post(proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=5)
        assert refused.status_code == 429
        assert refused.json() == {
            "error": {"type": "gateway_refused", "reason": refused.json()["error"]["reason"]}
        }
        assert "in flight" in refused.json()["error"]["reason"]
        # run_b is not held back by run_a's full quota
        with client.stream("POST", proxy + "/api/chat", headers=_auth(other), content=CHAT) as b:
            assert b.status_code == 200
            assert next(b.iter_raw()) == NDJSON_CHUNKS[0]
        fake.release.set()
    assert len(fake.seen) == 3  # the refused call never reached Ollama


def test_the_gateway_wide_cap_is_a_503(fake: FakeOllama) -> None:
    fake.mode = "gate"
    runs = [(f"run_{i}", secrets.token_urlsafe(32), MODEL) for i in range(3)]
    with (
        full_gateway(
            fake.url, _keys(*runs), max_inflight_per_run=2, max_upstream_connections=2
        ) as config,
        contextlib.ExitStack() as held,
    ):
        proxy = f"http://{config.listen}"
        client = held.enter_context(httpx.Client(timeout=5))
        for _, key, _ in runs[:2]:
            held.enter_context(
                client.stream("POST", proxy + "/api/chat", headers=_auth(key), content=CHAT)
            )
        busy = httpx.post(proxy + "/api/chat", headers=_auth(runs[2][1]), content=CHAT, timeout=5)
        assert busy.status_code == 503
        assert busy.json()["error"]["type"] == "gateway_refused"
        fake.release.set()


def test_too_many_large_bodies_from_one_run_are_refused(fake: FakeOllama) -> None:
    fake.mode = "gate"
    large = json.dumps({"model": MODEL, "prompt": "x" * (2 << 20)}).encode()
    with (
        full_gateway(fake.url, _keys(("run_a", KEY, MODEL)), max_large_bodies_per_run=1) as config,
        contextlib.ExitStack() as held,
    ):
        proxy = f"http://{config.listen}"
        client = held.enter_context(httpx.Client(timeout=10))
        held.enter_context(
            client.stream("POST", proxy + "/api/generate", headers=_auth(), content=large)
        )
        response = httpx.post(proxy + "/api/generate", headers=_auth(), content=large, timeout=10)
        assert response.status_code == 429
        assert "large" in response.json()["error"]["reason"]
        # small calls of the same run still pass
        with client.stream("POST", proxy + "/api/chat", headers=_auth(), content=CHAT) as small:
            assert small.status_code == 200
        fake.release.set()


@contextlib.contextmanager
def gateway_process(upstream: str, *runs: tuple[str, str]) -> Iterator[dict[str, str]]:
    """The gateway in its own process (and GIL), in front of ``upstream``; its URLs.

    The child is killed if it does not report its URLs within 30 s or does not exit
    within 30 s of its stdin closing, so it can never hang the suite.
    """
    args = [f"{run_id}={key}" for run_id, key in runs]
    with subprocess.Popen(  # noqa: S603 - this interpreter and a test module, no input
        [sys.executable, "-m", "tests.gateway.serve_gateway", upstream, *args],
        cwd=REPO_ROOT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ) as process:
        assert process.stdin is not None and process.stdout is not None
        try:
            ready, _, _ = select.select([process.stdout], [], [], 30)
            assert ready, "the gateway process did not start within 30 s"
            yield json.loads(process.stdout.readline())
        finally:
            process.stdin.close()
            try:
                process.wait(30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


#: How often the fake Ollama's ``drip`` mode sends a byte.
DRIP_S = 0.05


def test_a_large_body_blocks_neither_other_streams_nor_the_admin_api(fake: FakeOllama) -> None:
    fake.mode = "drip"
    other = secrets.token_urlsafe(32)
    # the costliest body the gateway still parses (both caps nearly reached, long
    # keys); the reviewer's 15 MiB of small objects, which took 9 s to parse on the
    # event loop; a [] flood; one object of 1.15M members, which held the GIL for
    # 425 ms; all refused before parsing. And a history of minified JavaScript and a
    # flood of strings full of braces, which must pass.
    objects = b'{"model": "qwen3:14b", "x": [' + b",".join([b'{"a":1}'] * 1_900_000) + b"]}"
    assert len(objects) > 14 << 20
    arrays = b'{"model": "qwen3:14b", "x": [' + b"[]," * 5_000_000 + b"[]]}"
    members = (
        b'{"model": "qwen3:14b", "o": {'
        + b",".join(b'"k%d":""' % i for i in range(1_150_000))
        + b"}}"
    )
    cases = (
        (many_members((MAX_JSON_SEPARATORS - 2) // 2, model="llama3:8b"), 403, "not granted"),
        (objects, 413, "body_too_complex"),
        (arrays, 413, "body_too_complex"),
        (members, 413, "body_too_complex"),
        (js_history(15 << 20), 200, ""),
        (BRACE_STRINGS, 200, ""),
    )
    assert all(len(body) <= 16 << 20 for body, _, _ in cases)
    with gateway_process(fake.url, ("run_a", KEY), ("run_b", other)) as urls:
        proxy, admin = urls["proxy"], urls["admin"]
        gaps: list[float] = []
        health: list[float] = []
        done = threading.Event()

        def watch() -> None:
            with (
                httpx.Client(timeout=10) as client,
                client.stream(
                    "POST", proxy + "/api/chat", headers=_auth(other), content=CHAT
                ) as stream,
            ):
                last = time.monotonic()
                for _ in stream.iter_raw():
                    now = time.monotonic()
                    gaps.append(now - last)
                    last = now
                    if done.is_set():
                        return

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        time.sleep(0.5)
        for heavy, status, reason in cases * 2:
            # /api/show: checked like a chat call, but the fake answers it at once
            response = httpx.post(proxy + "/api/show", headers=_auth(), content=heavy, timeout=30)
            assert response.status_code == status
            if reason:
                assert reason in response.json()["error"]["reason"]
            started = time.monotonic()
            assert httpx.get(admin + "/healthz", timeout=5).status_code == 200
            health.append(time.monotonic() - started)
        done.set()
        watcher.join(15)
    assert len(gaps) > 20
    # Chunks come every 50 ms. The parse on the event loop delayed them by 9 s on every
    # such body (each is sent twice). Now the loop waits at most for one short regex
    # call or for a parse's last stretch in C (about 50 ms under the caps). A busy
    # host stretches a few of those, so the third-largest delay must stay under 0.3 s
    # and none may reach 2 s; the policy tests carry the precise bounds.
    delays = sorted(gap - DRIP_S for gap in gaps[1:])
    assert delays[-3] < 0.3, delays[-5:]
    assert delays[-1] < 2.0, delays[-5:]
    assert sorted(health)[-2] < 0.3, health


def test_a_client_leaving_during_prefill_cancels_the_upstream_call(
    gw: Running, fake: FakeOllama
) -> None:
    fake.mode = "prefill"
    with pytest.raises(httpx.ReadTimeout):
        httpx.post(gw.proxy + "/api/chat", headers=_auth(), content=CHAT, timeout=0.5)
    # Ollama's response headers never came; the gateway still hung up on it
    assert fake.closed.wait(5)


def test_every_content_encoding_value_is_checked(gw: Running, fake: FakeOllama) -> None:
    for headers in (
        ["content-encoding: identity, gzip"],
        ["content-encoding: identity", "content-encoding: gzip"],
        ["content-encoding: gzip, identity"],
    ):
        raw = _raw("POST", "/api/chat", f"authorization: Bearer {KEY}", *headers, body=CHAT)
        assert status_of(raw_http(gw.proxy, raw)) == 415, headers
    raw = _raw(
        "POST", "/api/chat", f"authorization: Bearer {KEY}", "content-encoding: identity", body=CHAT
    )
    assert status_of(raw_http(gw.proxy, raw)) == 200
    assert len(fake.seen) == 1


def test_a_grant_without_a_tag_lists_the_latest_tag(gw: Running, fake: FakeOllama) -> None:
    key = secrets.token_urlsafe(32)
    gw.keys.register("run_b", key_sha256(key), ["qwen3"], datetime.now(UTC) + timedelta(hours=1))
    tags = httpx.get(gw.proxy + "/api/tags", headers=_auth(key))
    assert [m["name"] for m in tags.json()["models"]] == ["qwen3:latest"]
    models = httpx.get(gw.proxy + "/v1/models", headers=_auth(key))
    assert [m["id"] for m in models.json()["data"]] == ["qwen3:latest"]
    # and a tagged grant does not pick up :latest
    tags = httpx.get(gw.proxy + "/api/tags", headers=_auth())
    assert [m["name"] for m in tags.json()["models"]] == [MODEL]


# --------------------------------------------------------------------------- peers


def _from(address: str) -> httpx.Client:
    """A client whose connections leave from ``address`` (another peer)."""
    return httpx.Client(transport=httpx.HTTPTransport(local_address=address), timeout=5)


def test_a_peer_at_its_connection_cap_does_not_stop_another_peer(fake: FakeOllama) -> None:
    fake.mode = "gate"
    other = secrets.token_urlsafe(32)
    keys = _keys(("run_a", KEY, MODEL), ("run_b", other, MODEL))
    with full_gateway(fake.url, keys, max_connections_per_peer=5) as config:
        address = (config.listen.host, config.listen.port)
        held = [socket.create_connection(address) for _ in range(5)]
        try:
            time.sleep(0.2)
            # the sixth connection of the same peer: the gateway's JSON 503, then closed
            # (read before sending anything: data left unread would make the close a reset)
            response = b""
            with socket.create_connection(address, timeout=5) as extra:
                while chunk := extra.recv(4096):
                    response += chunk
            assert status_of(response) == 503
            assert body_of(response) == {
                "error": {
                    "type": "gateway_refused",
                    "reason": "too many connections from this peer",
                }
            }
            # another peer's run streams as usual
            with (
                _from("127.0.0.3") as client,
                client.stream(
                    "POST", f"http://{config.listen}/api/chat", headers=_auth(other), content=CHAT
                ) as stream,
            ):
                assert stream.status_code == 200
                assert next(stream.iter_raw()) == NDJSON_CHUNKS[0]
        finally:
            for sock in held:
                sock.close()
            fake.release.set()
        time.sleep(0.2)
        # the peer's own slots come back once its sockets close
        assert (
            httpx.post(
                f"http://{config.listen}/api/chat", headers=_auth(), content=CHAT, timeout=5
            ).status_code
            == 200
        )


def test_a_peer_that_keeps_refilling_idle_sockets_does_not_stop_another(fake: FakeOllama) -> None:
    other = secrets.token_urlsafe(32)
    keys = _keys(("run_b", other, MODEL))
    with full_gateway(
        fake.url, keys, max_connections=40, max_connections_per_peer=10, header_timeout_s=1
    ) as config:
        address = (config.listen.host, config.listen.port)
        stop = threading.Event()

        def refill() -> None:
            # one keyless peer: reopen every socket the gateway closes, as fast as it can
            socks: list[socket.socket] = []
            while not stop.is_set():
                alive = []
                for sock in socks:
                    sock.setblocking(False)
                    try:
                        if sock.recv(4096) == b"":
                            sock.close()
                            continue
                    except BlockingIOError:
                        pass
                    except OSError:
                        sock.close()
                        continue
                    alive.append(sock)
                socks = alive
                while len(socks) < 100:
                    try:
                        socks.append(socket.create_connection(address, timeout=1))
                    except OSError:
                        break
                time.sleep(0.05)
            for sock in socks:
                sock.close()

        attacker = threading.Thread(target=refill, daemon=True)
        attacker.start()
        time.sleep(0.5)
        statuses = []
        try:
            with _from("127.0.0.3") as client:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    response = client.post(
                        f"http://{config.listen}/api/chat", headers=_auth(other), content=CHAT
                    )
                    statuses.append(response.status_code)
                    time.sleep(0.1)
        finally:
            stop.set()
            attacker.join(5)
        assert len(statuses) > 10
        assert set(statuses) == {200}, statuses


@pytest.mark.parametrize(
    ("stopped", "status"),
    [("by the caller", 0), ("proxy server", 1), ("admin server", 1)],
)
def test_run_reports_a_server_that_stopped_by_itself(
    fake: FakeOllama, stopped: str, status: int
) -> None:
    proxy_sock = socket.create_server(("127.0.0.1", 0))
    admin_sock = socket.create_server(("127.0.0.2", 0))
    config = _config(
        fake.url,
        listen=Listener("127.0.0.1", proxy_sock.getsockname()[1]),
        admin_listen=Listener("127.0.0.2", admin_sock.getsockname()[1]),
    )
    gateway = Gateway(config, RunKeys())
    results: list[int] = []
    thread = threading.Thread(
        target=lambda: results.append(gateway.run([proxy_sock, admin_sock])), daemon=True
    )
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not gateway.started:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        if stopped == "by the caller":
            gateway.stop()  # what SIGTERM does
        else:  # one server ends on its own; the other is stopped with it
            gateway._servers[0 if stopped == "proxy server" else 1].should_exit = True
        thread.join(15)
        assert results == [status]
    finally:
        gateway.stop()
        thread.join(15)
        proxy_sock.close()
        admin_sock.close()


def test_peers_at_their_caps_get_the_gateways_503_never_uvicorns(fake: FakeOllama) -> None:
    # Two peers at their full share reach max_connections. A third peer gets the
    # gateway's JSON 503 at once, and the requests on the held connections are still
    # served: uvicorn's own limit (a plain-text 503) is never reached.
    with full_gateway(
        fake.url, _keys(("run_a", KEY, MODEL)), max_connections=6, max_connections_per_peer=3
    ) as config:
        address = (config.listen.host, config.listen.port)
        held = [
            socket.create_connection(address, source_address=(peer, 0))
            for peer in ("127.0.0.3", "127.0.0.4")
            for _ in range(3)
        ]
        try:
            time.sleep(0.2)
            with socket.create_connection(address, source_address=("127.0.0.5", 0)) as extra:
                extra.settimeout(5)
                refused = b""
                while chunk := extra.recv(4096):
                    refused += chunk
            assert status_of(refused) == 503
            assert body_of(refused) == {
                "error": {
                    "type": "gateway_refused",
                    "reason": "too many connections to the gateway",
                }
            }
            for sock in held:
                sock.settimeout(5)
                sock.sendall(_raw("POST", "/api/chat", f"authorization: Bearer {KEY}", body=CHAT))
                answer = b""
                while chunk := sock.recv(65536):
                    answer += chunk
                assert status_of(answer) == 200, answer[:200]
        finally:
            for sock in held:
                sock.close()


#: A WebSocket handshake; its key is RFC 6455's sample nonce, encoded here so that no
#: secret scanner mistakes it for a credential.
_UPGRADE = (
    b"GET /api/chat HTTP/1.1\r\nhost: x\r\nupgrade: websocket\r\nconnection: upgrade\r\n"
    b"sec-websocket-key: "
    + base64.b64encode(b"the sample nonce")
    + b"\r\nsec-websocket-version: 13\r\n\r\n"
)


@pytest.mark.parametrize("ws", ["as configured", "wsproto"])
def test_websocket_upgrades_never_leak_a_peers_slot(fake: FakeOllama, ws: str) -> None:
    # uvicorn swaps the protocol on an upgrade, and the slot is freed only by the
    # protocol that took it. The gateway runs with ws="none"; "wsproto" checks the
    # protocol's own refusal, in case a WebSocket library is ever switched on.
    pytest.importorskip("wsproto")
    proxy_sock = socket.create_server(("127.0.0.1", 0))
    admin_sock = socket.create_server(("127.0.0.2", 0))
    config = _config(
        fake.url,
        listen=Listener("127.0.0.1", proxy_sock.getsockname()[1]),
        admin_listen=Listener("127.0.0.2", admin_sock.getsockname()[1]),
        max_connections=16,
        max_connections_per_peer=3,
    )
    gateway = Gateway(config, _keys(("run_a", KEY, MODEL)))
    proxy = gateway._servers[0].config
    if ws == "wsproto":
        proxy.ws = "wsproto"
    thread = threading.Thread(target=gateway.run, args=([proxy_sock, admin_sock],), daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        while not gateway.started:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert (proxy.ws_protocol_class is None) == (ws == "as configured")
        address = (config.listen.host, config.listen.port)
        for _ in range(10):  # well past the peer's cap of 3
            with socket.create_connection(address) as sock:
                sock.settimeout(5)
                sock.sendall(_UPGRADE)
                answer = sock.recv(4096)
                assert answer.startswith((b"HTTP/1.1 4", b"HTTP/1.1 400")), answer[:80]
                assert not answer.startswith(b"HTTP/1.1 101")
        time.sleep(0.3)
        assert dict(proxy.http.peers) == {}  # type: ignore[union-attr]
        response = httpx.post(
            f"http://{config.listen}/api/chat", headers=_auth(), content=CHAT, timeout=5
        )
        assert response.status_code == 200
    finally:
        gateway.stop()
        thread.join(15)
        proxy_sock.close()
        admin_sock.close()
