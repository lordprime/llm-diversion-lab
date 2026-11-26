"""The recording stub model server that agent images are smoke-tested against.

It speaks the three model APIs the lab's agents use (see
:mod:`agents.ci.stub_model.replies`), answers chat requests from a scripted-turns file
(:mod:`agents.ci.stub_model.script`) and records every request, whatever its path, as
one JSON line:

``seq``, ``ts``, ``method``, ``path`` (credential-looking query values masked),
``api`` (``ollama``/``openai``/``anthropic``, or ``null`` for an unknown path),
``headers`` (auth values masked), ``body_format`` (``json``/``text``/``empty``),
``body``, ``stream``, ``turn`` (the script turn used, ``"final"`` for the final reply,
``null`` for non-chat calls), ``status``, ``response_content_type`` and ``response``
(the exact reply text, so a check can read it back with the telemetry parsers).

Headers are masked with the lab's own rules (:func:`control.core.logging.is_sensitive_key`
for the header name, :func:`control.core.logging.redact_text` for anything secret-looking
in other values) and paths with the tap's (:func:`cell.tap.recorder.redact_path`).
Bodies are kept as sent: they are the evidence that a model call happened.

Run::

    python -m agents.ci.stub_model.server --script script.yaml --record requests.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from collections.abc import Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any, Final

from fastapi import FastAPI, Request
from fastapi.responses import Response, StreamingResponse

from agents.ci.stub_model.replies import API_SHAPES, ApiShape, ChatRequest, StubReply
from agents.ci.stub_model.script import ScriptError, StubScript, TurnPlayer
from cell.tap.recorder import redact_path
from control.core.logging import REDACTED, is_sensitive_key, redact_text

__all__ = ["MAX_REQUEST_BYTES", "RequestRecorder", "StubModel", "create_app", "main"]

#: Largest request body the stub reads; a larger one is answered with 413.
MAX_REQUEST_BYTES: Final = 32 * 1024 * 1024
_METHODS: Final = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


class RequestRecorder:
    """Appends one JSON line per request to a text stream, one writer at a time."""

    def __init__(self, stream: IO[str]) -> None:
        self._stream = stream
        self._lock = threading.Lock()
        self._seq = 0

    def next_seq(self) -> int:
        with self._lock:
            seq = self._seq
            self._seq += 1
            return seq

    def write(self, record: Mapping[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n"
        with self._lock:
            self._stream.write(line)
            self._stream.flush()

    @staticmethod
    def headers(headers: Mapping[str, str]) -> dict[str, str]:
        """Headers with every auth value masked; names lowercased."""
        return {
            name.lower(): REDACTED if is_sensitive_key(name) else redact_text(value)
            for name, value in headers.items()
        }

    @staticmethod
    def body(raw: bytes) -> tuple[str, Any]:
        """``(body_format, body)``: parsed JSON when it is JSON, else the text."""
        if not raw:
            return "empty", None
        text = raw.decode("utf-8", errors="replace")
        try:
            return "json", json.loads(text)
        except ValueError:
            return "text", text


class StubModel:
    """Routes one request to its API, picks the scripted turn, and records the exchange."""

    def __init__(self, script: StubScript, recorder: RequestRecorder) -> None:
        self.script = script
        self.player = TurnPlayer(script)
        self.recorder = recorder

    def handle(self, method: str, path: str, headers: Mapping[str, str], body: bytes) -> StubReply:
        seq = self.recorder.next_seq()
        bare = path.split("?", 1)[0]
        body_format, doc = self.recorder.body(body)
        shape, reply, turn = self._reply(seq, method, bare, body, doc)
        self.recorder.write(
            {
                "seq": seq,
                "ts": datetime.now(UTC).isoformat(),
                "method": method,
                "path": redact_path(path),
                "api": shape.name if shape else None,
                "headers": self.recorder.headers(headers),
                "body_format": body_format,
                "body": doc,
                "stream": reply.streamed,
                "turn": turn,
                "status": reply.status,
                "response_content_type": reply.media_type,
                "response": reply.body.decode("utf-8", errors="replace"),
            }
        )
        return reply

    def _reply(
        self, seq: int, method: str, path: str, body: bytes, doc: Any
    ) -> tuple[ApiShape | None, StubReply, int | str | None]:
        if method == "GET" and path in ("/", "/healthz"):
            return None, StubReply(200, "text/plain", (b"Ollama is running",)), None
        for shape in API_SHAPES:
            is_chat = method == "POST" and path == shape.chat_path
            if not is_chat and (method, path) not in shape.endpoints:
                continue
            if len(body) > MAX_REQUEST_BYTES:
                return shape, shape.error(413, "request body too large"), None
            if method == "POST" and not isinstance(doc, dict):
                return shape, shape.error(400, "the request body must be a JSON object"), None
            request = ChatRequest(seq, doc if isinstance(doc, dict) else {}, len(body))
            if not is_chat:
                reply = shape.answer(method, path, self.script, request)
                return shape, reply or shape.error(404, f"no such endpoint: {path}"), None
            index, turn = self.player.next_turn(path, body.decode("utf-8", errors="replace"))
            return (
                shape,
                shape.chat(self.script, turn, request),
                "final" if index is None else index,
            )
        return None, StubReply.json({"error": f"no such endpoint: {method} {path}"}, 404), None


def create_app(model: StubModel) -> FastAPI:
    """The HTTP front of a :class:`StubModel`: every path goes to :meth:`StubModel.handle`."""
    app = FastAPI(title="Recording stub model", docs_url=None, redoc_url=None, openapi_url=None)

    @app.api_route("/{path:path}", methods=_METHODS)
    async def any_path(request: Request) -> Response:
        body = await request.body()
        target = request.url.path + (f"?{request.url.query}" if request.url.query else "")
        reply = model.handle(request.method, target, dict(request.headers), body)
        if not reply.streamed:
            return Response(reply.body, status_code=reply.status, media_type=reply.media_type)

        def pieces() -> Iterator[bytes]:
            yield from reply.chunks

        return StreamingResponse(pieces(), status_code=reply.status, media_type=reply.media_type)

    return app


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--script", type=Path, required=True, help="scripted-turns YAML file")
    parser.add_argument("--record", type=Path, required=True, help="requests.jsonl to append to")
    parser.add_argument("--host", default="0.0.0.0")  # noqa: S104 -- inside its own container
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--check", action="store_true", help="check the script and exit")
    args = parser.parse_args(argv)
    try:
        script = StubScript.load(args.script)
    except ScriptError as exc:
        print(f"stub model: {exc}", file=sys.stderr)
        return 2
    if args.check:
        print(f"stub model: {args.script} is valid ({len(script.turns)} turns)")
        return 0
    import uvicorn

    with args.record.open("a", encoding="utf-8") as stream:
        model = StubModel(script, RequestRecorder(stream))
        uvicorn.run(
            create_app(model), host=args.host, port=args.port, access_log=False, log_level="warning"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
