"""mitmproxy addon: the in-cell LLM tap (a thin I/O shell around :mod:`cell.tap.recorder`).

Run in reverse mode in front of the model gateway, with the repo root importable::

    PYTHONPATH=/lab LAB_RUN_ID=run_... LAB_TAGS=<tag> LAB_EVIDENCE_DIR=/evidence \\
        mitmdump --mode reverse:http://gateway:4000 --listen-port 8080 \\
        -s /lab/cell/tap/addon.py

Hooks:

* ``request``: records the request body (Content-Encoding removed) before the flow is
  forwarded. If it cannot be recorded, the flow is answered with a ``502`` here and
  never reaches the gateway.
* ``response``: records the response body verbatim and emits the ``LlmCall`` line. If
  that fails, the agent gets a ``502`` instead of an unrecorded answer.
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

from cell.tap.recorder import PendingCall, Recorder, TapConfig

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


def _body(message: http.Message) -> bytes:
    """The message body with any Content-Encoding removed (raw bytes if undecodable)."""
    return message.get_content(strict=False) or b""


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
        try:
            pending = self._recorder.begin(_body(flow.request), ts)
        except Exception:
            log.exception("tap: cannot record request %s; refusing it", flow.id)
            _refuse(flow)
            return
        flow.metadata[_METADATA_KEY] = pending

    def response(self, flow: http.HTTPFlow) -> None:
        pending = self._pop(flow)
        if pending is None or flow.response is None:
            return
        try:
            self._recorder.finish(pending, _body(flow.response))
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
