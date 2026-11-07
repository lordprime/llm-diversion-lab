"""mitmproxy addon: the surface injector (an I/O shell around :mod:`cell.injector.placement`).

Run in reverse mode in front of the target app, with the repo root importable::

    PYTHONPATH=/lab LAB_MANIFEST=/run/manifest.json LAB_PAYLOADS=/run/payloads.json \\
        LAB_PROBE_SECRET=<per-run secret> LAB_EVIDENCE_DIR=/evidence \\
        mitmdump --mode reverse:http://target:5013 --listen-port 8080 \\
        -s /lab/cell/injector/addon.py

Configuration is read from the environment once, at script load
(:meth:`~cell.injector.serve_log.InjectorConfig.from_env`: ``LAB_MANIFEST``,
``LAB_PAYLOADS``, ``LAB_PROBE_SECRET``, ``LAB_EVIDENCE_DIR``, ``LAB_RUN_ID``); a bad
configuration is logged as an error, which makes ``mitmdump`` exit at startup.

Hooks:

* ``request``: decides probe or not, removes every ``x-lab-probe`` header (so it never
  reaches the app), and answers the planted surfaces itself (robots.txt, P7 paths and
  the decoy path in an injected run). Any other request is forwarded untouched.
* ``response``: appends to ``<evidence>/injector/events.jsonl`` one
  :class:`TargetAccessEvent` for the request and, if the response carried planted
  bytes, one :class:`PlacementServe` per placement in it; the served wire bytes go to
  the write-once ``<evidence>/injector/NNNN.body`` (``NNNN`` = the access event's
  ``seq``). Responses are never modified, except that a request whose evidence cannot
  be written is answered with ``502`` instead (fail closed, like the tap).
* ``error``: a request that ended without a response is still logged (``status`` null).

Evidence formats are described in :mod:`cell.injector.serve_log`.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Final

from mitmproxy import http

from cell.injector.placement import (
    PROBE_HEADER,
    InjectionPlan,
    SyntheticResponse,
    build_plan,
    is_probe,
    plant_into_body,
)
from cell.injector.serve_log import AccessRecord, InjectorConfig, ServedBody, ServeLog

__all__ = ["SurfaceInjector", "plant_into_response"]

log = logging.getLogger(__name__)

_METADATA_KEY: Final = "lab_injector"
_WITHHELD: Final = b"Bad Gateway\n"


# --------------------------------------------------------------------------- headers


def plant_into_response(
    response: http.Response, payload: bytes, *, before: bytes | None = None
) -> tuple[int, bool]:
    """Plant ``payload`` into an app response in its own Content-Encoding.

    On success the wire body is replaced, Content-Length is set to the new length
    (unless the response uses Transfer-Encoding) and the now stale ETag and
    Content-MD5 are removed; returns ``(offset in the decoded body, True)``. On failure
    the response is left exactly as it was and ``(-1, False)`` is returned.
    """
    raw = response.raw_content
    if raw is None:
        return -1, False
    wire, offset, ok = plant_into_body(
        raw, response.headers.get("content-encoding"), payload, before=before
    )
    if not ok:
        return -1, False
    response.raw_content = wire
    if "transfer-encoding" not in response.headers:
        response.headers["content-length"] = str(len(wire))
    for stale in ("etag", "content-md5"):
        if stale in response.headers:
            del response.headers[stale]
    return offset, True


# --------------------------------------------------------------------------- addon


class _FlowState:
    """Per-flow decision, kept in ``flow.metadata`` (a plain class: see serve_log)."""

    __slots__ = ("logged", "probe", "synthetic")

    def __init__(self, probe: bool, synthetic: SyntheticResponse | None) -> None:
        self.probe = probe
        self.synthetic = synthetic
        self.logged = False


def _ts(timestamp: float | None) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=UTC) if timestamp else datetime.now(UTC)


def _make_response(synthetic: SyntheticResponse, *, head: bool) -> http.Response:
    resp = http.Response.make(
        synthetic.status, b"" if head else synthetic.body, {"content-type": synthetic.content_type}
    )
    if head:
        resp.headers["content-length"] = str(len(synthetic.body))
    return resp


def _refuse(flow: http.HTTPFlow) -> None:
    flow.response = http.Response.make(502, _WITHHELD, {"content-type": "text/plain"})


class SurfaceInjector:
    """Plants a run's surfaces and logs every request to the target."""

    def __init__(self, plan: InjectionPlan, serve_log: ServeLog, probe_secret: str) -> None:
        self._plan = plan
        self._log = serve_log
        self._probe_secret = probe_secret

    @property
    def plan(self) -> InjectionPlan:
        return self._plan

    @classmethod
    def from_config(cls, config: InjectorConfig) -> SurfaceInjector:
        plan = build_plan(config.manifest, config.contents)
        return cls(plan, ServeLog(config.manifest.run_id, config.evidence_dir), config.probe_secret)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> SurfaceInjector:
        return cls.from_config(InjectorConfig.from_env(env))

    def _classify(self, flow: http.HTTPFlow) -> _FlowState:
        headers = flow.request.headers
        probe = is_probe(headers.get_all(PROBE_HEADER), self._probe_secret)
        if PROBE_HEADER in headers:
            del headers[PROBE_HEADER]
        return _FlowState(probe, self._plan.match(flow.request.method, flow.request.path))

    def _state(self, flow: http.HTTPFlow) -> _FlowState:
        state = flow.metadata.get(_METADATA_KEY)
        if not isinstance(state, _FlowState):  # a flow the request hook did not see
            state = self._classify(flow)
            flow.metadata[_METADATA_KEY] = state
        return state

    def _access(self, flow: http.HTTPFlow, state: _FlowState, status: int | None) -> AccessRecord:
        peer = flow.client_conn.peername
        return AccessRecord(
            flow_id=flow.id,
            method=flow.request.method,
            url=flow.request.url,
            ts=_ts(flow.request.timestamp_start),
            probe=state.probe,
            status=status,
            source_ip=str(peer[0]) if peer else None,
        )

    def request(self, flow: http.HTTPFlow) -> None:
        state = self._classify(flow)
        flow.metadata[_METADATA_KEY] = state
        if state.synthetic is not None:
            head = flow.request.method.upper() == "HEAD"
            flow.response = _make_response(state.synthetic, head=head)

    def _served(self, flow: http.HTTPFlow, state: _FlowState) -> ServedBody | None:
        synthetic, resp = state.synthetic, flow.response
        if synthetic is None or not synthetic.plants or resp is None:
            return None
        if flow.request.method.upper() == "HEAD":
            return None  # headers only: no planted bytes reached the client
        wire = resp.raw_content or b""
        try:
            decoded, decodable = resp.get_content(strict=True) or b"", True
        except ValueError:
            decoded, decodable = wire, False
        plants = tuple(
            (
                plant,
                decodable
                and resp.status_code == synthetic.status
                and decoded[plant.offset : plant.offset + len(plant.content)] == plant.content,
            )
            for plant in synthetic.plants
        )
        return ServedBody(wire, decoded, resp.status_code, _ts(resp.timestamp_start), plants)

    def response(self, flow: http.HTTPFlow) -> None:
        state = self._state(flow)
        if state.logged:
            return
        state.logged = True
        status = flow.response.status_code if flow.response is not None else None
        try:
            self._log.record(self._access(flow, state, status), self._served(flow, state))
        except Exception:
            log.exception("injector: cannot record flow %s; withholding the response", flow.id)
            _refuse(flow)

    def error(self, flow: http.HTTPFlow) -> None:
        state = self._state(flow)
        if state.logged:
            return
        state.logged = True
        try:
            self._log.record(self._access(flow, state, None))
        except Exception:
            log.exception("injector: cannot record failed flow %s", flow.id)


if __name__.startswith("__mitmproxy_script__."):
    # Loaded by ``mitmdump -s``: configure from the environment, failing at startup.
    addons = [SurfaceInjector.from_env(os.environ)]
