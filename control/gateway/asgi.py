"""Small ASGI pieces both listeners share: refusals, bounded body reads, lifespan."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from typing import Final

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import Receive, Send

__all__ = ["REFUSED", "UPSTREAM_ERROR", "BodyReader", "Refused", "serve_lifespan"]

#: ``error.type`` of a request the gateway refused by policy (401, 403, 404, 408, 413...).
REFUSED: Final = "gateway_refused"
#: ``error.type`` when Ollama could not be reached or did not answer (502, 504).
UPSTREAM_ERROR: Final = "gateway_upstream_error"
_CONTENT_LENGTH: Final = re.compile(r"[0-9]{1,20}")


class Refused(Exception):
    """A request the gateway answers itself, with a status and a reason."""

    def __init__(self, status: int, reason: str, kind: str = REFUSED) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.kind = kind

    def response(self) -> JSONResponse:
        return JSONResponse(
            {"error": {"type": self.kind, "reason": self.reason}}, status_code=self.status
        )


class BodyReader:
    """Reads a request body within a size cap and a deadline, or refuses it."""

    def __init__(self, limit: int, timeout_s: float) -> None:
        self._limit = limit
        self._timeout_s = timeout_s

    async def read(self, request: Request) -> bytes:
        declared = request.headers.get("content-length")
        if declared is not None:
            if not _CONTENT_LENGTH.fullmatch(declared):
                raise Refused(400, "malformed content-length")
            if int(declared) > self._limit:
                raise Refused(413, f"request body over {self._limit} bytes")
        chunks: list[bytes] = []
        size = 0
        try:
            async with asyncio.timeout(self._timeout_s):
                async for chunk in request.stream():
                    size += len(chunk)
                    if size > self._limit:
                        raise Refused(413, f"request body over {self._limit} bytes")
                    chunks.append(chunk)
        except TimeoutError:
            raise Refused(408, "request body not received in time") from None
        return b"".join(chunks)


async def serve_lifespan(
    receive: Receive,
    send: Send,
    startup: Callable[[], Awaitable[None]],
    shutdown: Callable[[], Awaitable[None]],
) -> None:
    while True:
        message = await receive()
        if message["type"] == "lifespan.startup":
            await startup()
            await send({"type": "lifespan.startup.complete"})
        elif message["type"] == "lifespan.shutdown":
            await shutdown()
            await send({"type": "lifespan.shutdown.complete"})
            return
