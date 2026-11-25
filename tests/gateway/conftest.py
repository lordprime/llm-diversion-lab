"""Live HTTP servers for the gateway tests: a fake Ollama, the gateway, a slowloris.

The gateway is tested over real sockets, never through an in-process transport: an
in-process transport buffers whole responses (so streaming could not be checked) and
normalises paths and headers before the gateway would see them.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

LOCALHOST = "127.0.0.1"

NDJSON_CHUNKS = (
    b'{"model":"qwen3:14b","message":{"role":"assistant","content":"Hel"},"done":false}\n',
    b'{"model":"qwen3:14b","message":{"role":"assistant","content":"lo"},"done":false}\n',
    b'{"model":"qwen3:14b","message":{"role":"assistant","content":""},"done":true}\n',
)
SSE_CHUNKS = (
    b'data: {"id":"c1","choices":[{"delta":{"content":"Hel"}}]}\n\n',
    b'data: {"id":"c1","choices":[{"delta":{"content":"lo"}}]}\n\n',
    b"data: [DONE]\n\n",
)
TAGS = {
    "models": [
        {"name": "qwen3:14b", "model": "qwen3:14b", "digest": "a" * 64, "size": 1},
        {"name": "qwen3:32b", "model": "qwen3:32b", "digest": "b" * 64, "size": 2},
        {"name": "llama3:8b", "model": "llama3:8b", "digest": "c" * 64, "size": 3},
    ]
}
OPENAI_MODELS = {
    "object": "list",
    "data": [
        {"id": "qwen3:14b", "object": "model", "owned_by": "library"},
        {"id": "qwen3:32b", "object": "model", "owned_by": "library"},
        {"id": "llama3:8b", "object": "model", "owned_by": "library"},
    ],
}
SHOW = b'{"modelfile":"FROM qwen3:14b","details":{"family":"qwen3"},"model_info":{}}'


@dataclass
class Seen:
    """One request as the fake Ollama received it."""

    method: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: bytes

    def header_names(self) -> set[str]:
        return {name for name, _ in self.headers}


@dataclass
class FakeOllama:
    """An Ollama stand-in whose streaming behaviour a test sets before it calls.

    ``mode``: ``normal`` streams ``chunks``; ``gate`` sends the first chunk and holds
    the rest until ``release`` is set; ``drip`` sends one byte every 50 ms forever;
    ``hang`` never answers; ``error`` answers 404 like Ollama for an unknown model.
    ``closed`` is set when a stream ended before it sent everything.
    """

    mode: str = "normal"
    chunks: tuple[bytes, ...] = NDJSON_CHUNKS
    media_type: str = "application/x-ndjson"
    seen: list[Seen] = field(default_factory=list)
    release: threading.Event = field(default_factory=threading.Event)
    closed: threading.Event = field(default_factory=threading.Event)
    stop: threading.Event = field(default_factory=threading.Event)
    url: str = ""

    def paths(self) -> list[str]:
        return [s.path for s in self.seen]

    async def _wait(self, event: threading.Event) -> None:
        while not event.is_set() and not self.stop.is_set():
            await asyncio.sleep(0.01)

    async def _stream(self) -> AsyncIterator[bytes]:
        finished = False
        try:
            if self.mode == "drip":
                while not self.stop.is_set():
                    yield b"x"
                    await asyncio.sleep(0.05)
            else:
                yield self.chunks[0]
                if self.mode == "gate":
                    await self._wait(self.release)
                for chunk in self.chunks[1:]:
                    yield chunk
                finished = True
        finally:
            if not finished:
                self.closed.set()

    async def endpoint(self, request: Request) -> Response:
        body = await request.body()
        self.seen.append(
            Seen(
                request.method,
                request.url.path,
                request.url.query,
                [(k.decode("latin-1"), v.decode("latin-1")) for k, v in request.headers.raw],
                body,
            )
        )
        path = request.url.path
        if path == "/api/tags":
            return JSONResponse(TAGS)
        if path == "/v1/models":
            return JSONResponse(OPENAI_MODELS)
        if path == "/api/show":
            return Response(SHOW, media_type="application/json")
        if self.mode == "hang":
            await self._wait(threading.Event())
            return Response(b"too late")
        if self.mode == "error":
            return JSONResponse({"error": "model 'qwen3:14b' not found"}, status_code=404)
        return StreamingResponse(self._stream(), media_type=self.media_type)

    @property
    def app(self) -> Starlette:
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        return Starlette(routes=[Route("/{path:path}", self.endpoint, methods=methods)])


class LiveServer:
    """An ASGI app served by uvicorn on 127.0.0.1 in a background thread."""

    def __init__(self, app: Any, host: str = LOCALHOST) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, 0))
        self.host, self.port = self._sock.getsockname()
        config = uvicorn.Config(
            app, log_level="warning", lifespan="on", timeout_graceful_shutdown=1
        )
        self._server = uvicorn.Server(config)
        self._thread = threading.Thread(
            target=self._server.run, kwargs={"sockets": [self._sock]}, daemon=True
        )

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def __enter__(self) -> LiveServer:
        self._thread.start()
        deadline = time.monotonic() + 10
        while not self._server.started:
            if time.monotonic() > deadline or not self._thread.is_alive():
                raise RuntimeError("test server did not start")
            time.sleep(0.01)
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.should_exit = True
        self._thread.join(10)
        self._sock.close()


class DripServer:
    """A slowloris upstream: it answers every connection with one header byte at a time."""

    def __init__(self, interval_s: float = 0.1) -> None:
        self._interval_s = interval_s
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind((LOCALHOST, 0))
        self._sock.listen(8)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self.url = f"http://{LOCALHOST}:{self.port}"
        self._stop = threading.Event()
        self.connections = 0
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _drip(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(1)
            try:
                conn.recv(65536)
                for byte in b"HTTP/1.1 200 OK\r\nX-Slow: " + b"a" * 10_000:
                    if self._stop.is_set():
                        return
                    conn.sendall(bytes([byte]))
                    time.sleep(self._interval_s)
            except OSError:
                return

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            self.connections += 1
            threading.Thread(target=self._drip, args=(conn,), daemon=True).start()

    def __enter__(self) -> DripServer:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(5)
        self._sock.close()


def raw_http(url: str, data: bytes, *, timeout_s: float = 10.0) -> bytes:
    """Send ``data`` as-is on a fresh connection; return everything read until close."""
    host, _, port = url.removeprefix("http://").partition(":")
    out = b""
    with socket.create_connection((host, int(port)), timeout=timeout_s) as sock:
        sock.sendall(data)
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                chunk = sock.recv(65536)
            except TimeoutError:
                break
            if not chunk:
                break
            out += chunk
    return out


def status_of(response: bytes) -> int:
    line = response.split(b"\r\n", 1)[0]
    parts = line.split(b" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0


def body_of(response: bytes) -> dict[str, Any]:
    head, _, body = response.partition(b"\r\n\r\n")
    if b"transfer-encoding: chunked" in head.lower():
        size, _, rest = body.partition(b"\r\n")
        body = rest[: int(size, 16)]
    doc = json.loads(body)
    assert isinstance(doc, dict)
    return doc


@pytest.fixture
def fake() -> Iterator[FakeOllama]:
    ollama = FakeOllama()
    with LiveServer(ollama.app) as server:
        ollama.url = server.url
        yield ollama
        ollama.stop.set()
