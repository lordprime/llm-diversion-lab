"""mitmproxy addon: the in-cell LLM tap (a thin I/O shell around :mod:`cell.tap.recorder`).

Run in reverse mode in front of the model gateway, with the repo root importable::

    PYTHONPATH=/lab LAB_RUN_ID=run_... LAB_TAGS=<tag> LAB_EVIDENCE_DIR=/evidence \\
        mitmdump --mode reverse:http://gateway:4000 --listen-port 8080 \\
        -s /lab/cell/tap/addon.py

Hooks:

* ``request``: records the request body (Content-Encoding removed; raw wire bytes if
  it cannot be decoded) before the flow is forwarded. If it cannot be recorded, the
  flow is answered with a ``502`` here and never reaches the gateway.
* ``response``: records the response body verbatim, the call's ``NNNN.meta.json``
  (method, path, status, content-type/-encoding, decoded flags; never credential
  headers) and the ``LlmCall`` line. If a file cannot be written the event is still
  emitted, and the agent gets a ``502`` instead of an unrecorded answer.
* ``error``: a call that ended without a response is still emitted (no response file).

The tap never modifies traffic it has recorded. Configuration is read from the
environment once, at script load; a bad configuration is logged as an error, which
makes ``mitmdump`` exit at startup.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from mitmproxy import http

from cell.tap.recorder import PendingCall, Recorder, RequestMeta, ResponseMeta, TapConfig

__all__ = ["LlmTap"]

log = logging.getLogger(__name__)

_METADATA_KEY: Final = "lab_tap_pending"
_REFUSAL: Final = json.dumps(
    {
        "type": "error",
        "error": {
            "type": "api_error",
            "message": "lab tap could not record this call as evidence; not forwarded",
        },
    }
).encode()


def _body(message: http.Message) -> tuple[bytes, bool]:
    """The body with any Content-Encoding removed, and whether that decoding worked.

    If decoding fails, the raw wire bytes are returned with ``False``.
    """
    try:
        return message.get_content(strict=True) or b"", True
    except ValueError:
        return message.raw_content or b"", False


def _header(message: http.Message, name: str) -> str | None:
    return message.headers.get(name)


def _refuse(flow: http.HTTPFlow) -> None:
    flow.response = http.Response.make(502, _REFUSAL, {"content-type": "application/json"})


class LlmTap:
    """Records every flow through the proxy as one ``LlmCall`` of the ``tap`` stream."""

    def __init__(self, recorder: Recorder) -> None:
        self._recorder = recorder

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> LlmTap:
        return cls(Recorder(TapConfig.from_env(env)))

    def _pop(self, flow: http.HTTPFlow) -> PendingCall | None:
        pending = flow.metadata.pop(_METADATA_KEY, None)
        return pending if isinstance(pending, PendingCall) else None

    def request(self, flow: http.HTTPFlow) -> None:
        ts = datetime.fromtimestamp(flow.request.timestamp_start, tz=UTC)
        body, decoded = _body(flow.request)
        meta = RequestMeta(
            method=flow.request.method,
            path=flow.request.path,
            content_type=_header(flow.request, "content-type"),
            content_encoding=_header(flow.request, "content-encoding"),
            decoded=decoded,
        )
        try:
            pending = self._recorder.begin(body, ts, meta)
        except Exception:
            log.exception("tap: cannot record request %s; refusing it", flow.id)
            _refuse(flow)
            return
        flow.metadata[_METADATA_KEY] = pending

    def response(self, flow: http.HTTPFlow) -> None:
        pending = self._pop(flow)
        if pending is None or flow.response is None:
            return
        body, decoded = _body(flow.response)
        meta = ResponseMeta(
            status=flow.response.status_code,
            content_type=_header(flow.response, "content-type"),
            content_encoding=_header(flow.response, "content-encoding"),
            decoded=decoded,
        )
        try:
            self._recorder.finish(pending, body, meta)
        except Exception:
            log.exception("tap: cannot record response of call %d; withholding it", pending.seq)
            _refuse(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        pending = self._pop(flow)
        if pending is None:
            return
        try:
            self._recorder.finish(pending, None)
        except Exception:
            log.exception("tap: cannot record failed call %d", pending.seq)


if __name__.startswith("__mitmproxy_script__."):
    # Loaded by ``mitmdump -s``: configure from the environment, failing at startup.
    addons = [LlmTap.from_env(os.environ)]
