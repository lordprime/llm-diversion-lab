"""Stub LLM gateway: a deterministic, offline stand-in for the model gateway.

Used by the M0 self-test so no real model is ever called. Run with
``uvicorn cell.stub_llm.app:app``.

* ``POST /v1/messages``: an Anthropic-Messages-shaped, non-streaming response chosen
  by the request header ``x-lab-script`` (default ``ok``). The response echoes the
  requested ``model``; the same request bytes and script always give byte-identical
  response bytes. Auth headers are ignored and no key is ever needed.
* ``GET /healthz``: liveness.

The stub records nothing itself; the tap in front of it is the evidence record.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

from fastapi import FastAPI, Request
from fastapi.responses import Response

__all__ = ["DEFAULT_SCRIPT", "OK_TEXT", "SCRIPTS", "SCRIPT_HEADER", "app", "create_app"]

SCRIPT_HEADER: Final = "x-lab-script"
OK_TEXT: Final = "OK. This is the lab stub LLM; no model was called."
#: Script name -> the assistant text it answers with.
SCRIPTS: Final[Mapping[str, str]] = MappingProxyType({"ok": OK_TEXT})
DEFAULT_SCRIPT: Final = "ok"


def _json(status: int, doc: object) -> Response:
    body = json.dumps(doc, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return Response(content=body, status_code=status, media_type="application/json")


def _error(status: int, message: str) -> Response:
    return _json(
        status,
        {"type": "error", "error": {"type": "invalid_request_error", "message": message}},
    )


def render_message(model: str, script: str, text: str, request_body: bytes) -> dict[str, object]:
    """The canned Anthropic Messages response; a pure function of its inputs."""
    digest = hashlib.sha256(script.encode("utf-8") + b"\0" + request_body).hexdigest()
    return {
        "id": f"msg_stub_{digest[:24]}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {
            "input_tokens": max(1, len(request_body) // 4),
            "output_tokens": max(1, len(text.encode("utf-8")) // 4),
        },
    }


def create_app() -> FastAPI:
    app = FastAPI(
        title="LLM Diversion Lab stub LLM",
        version="1",
        summary="Deterministic offline stand-in for the model gateway.",
    )

    @app.get("/healthz", tags=["health"])
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/v1/messages")
    async def messages(request: Request) -> Response:
        script = request.headers.get(SCRIPT_HEADER, DEFAULT_SCRIPT)
        text = SCRIPTS.get(script)
        if text is None:
            return _error(400, f"unknown {SCRIPT_HEADER} {script[:64]!r}")
        body = await request.body()
        try:
            doc = json.loads(body)
        except ValueError:
            return _error(400, "request body is not JSON")
        model = doc.get("model") if isinstance(doc, dict) else None
        if not isinstance(model, str) or not model:
            return _error(400, "model is required")
        if isinstance(doc, dict) and doc.get("stream") is True:
            return _error(400, "the stub LLM does not stream")
        return _json(200, render_message(model, script, text, body))

    return app


app = create_app()
