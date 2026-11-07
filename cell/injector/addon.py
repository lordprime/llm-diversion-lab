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

The injector never answers a request itself: every request reaches the app. In an
injected run it transforms the app's own response to the few ``GET`` requests it acts
on (rules in :mod:`cell.injector.placement`), keeping the app's headers (``Date``,
``Server``, cookies...) so planted responses have the app's shape. When a body changes,
Content-Length is fixed (unless Transfer-Encoding is used), an ETag is recomputed
(quoted digest, ``W/`` kept) and ``Digest``/``Repr-Digest``/``Content-Digest``/
``Content-MD5`` are dropped. 204, 206 (or any ``Content-Range``) and 304 are never
planted into.

Hooks:

* ``request``: decides probe or not, removes every ``x-lab-probe`` header (so it never
  reaches the app), and notes the planned action. The request is forwarded untouched
  otherwise.
* ``response``: applies the action, then logs a :class:`TargetAccessEvent` and, for
  robots.txt and P7 requests, one :class:`PlacementServe` per placement plus the served
  body and its meta (see :mod:`cell.injector.serve_log`). Any other response is
  forwarded byte-for-byte. A request whose evidence cannot be written (or whose
  transform fails) is answered with ``502`` instead (fail closed, like the tap).
* ``error``: a request that ended without a response is still logged (``status`` null).
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Final

from mitmproxy import http
from pydantic import JsonValue

from cell.injector.placement import (
    DECOY_PAGE,
    DEFAULT_ROBOTS_BASE,
    PROBE_HEADER,
    Action,
    ActionKind,
    InjectionPlan,
    Planted,
    build_plan,
    decode_body,
    encode_body,
    is_probe,
    plant_into_body,
    recompute_etag,
    render_robots,
)
from cell.injector.serve_log import AccessRecord, InjectorConfig, ServedBody, ServeLog

__all__ = ["SurfaceInjector", "plant_into_response", "plantable"]

log = logging.getLogger(__name__)

_METADATA_KEY: Final = "lab_injector"
_WITHHELD: Final = b"Bad Gateway\n"
_TEXT_PLAIN: Final = "text/plain; charset=utf-8"
_TEXT_HTML: Final = "text/html; charset=utf-8"
_UNPLANTABLE_STATUS: Final = frozenset({204, 206, 304})
_STALE_DIGESTS: Final = ("digest", "repr-digest", "content-digest", "content-md5")


# --------------------------------------------------------------------------- response edits


def plantable(response: http.Response) -> bool:
    """Whether a response's body may be planted into (not 204/206/304, no range)."""
    return (
        response.raw_content is not None
        and response.status_code not in _UNPLANTABLE_STATUS
        and "content-range" not in response.headers
    )


def _replace_body(response: http.Response, wire: bytes) -> None:
    """Set new wire bytes and fix every header that described the old ones."""
    headers = response.headers
    response.raw_content = wire
    if "transfer-encoding" not in headers:
        headers["content-length"] = str(len(wire))
    etag = headers.get("etag")
    if etag is not None:
        headers["etag"] = recompute_etag(etag, wire)
    for name in _STALE_DIGESTS:
        if name in headers:
            del headers[name]


def _replace_representation(
    response: http.Response, status: int, content_type: str, body: bytes
) -> None:
    """Give a response a new status and identity-encoded body, keeping other headers."""
    response.status_code = status
    response.reason = HTTPStatus(status).phrase
    for name in ("content-encoding", "content-range"):
        if name in response.headers:
            del response.headers[name]
    response.headers["content-type"] = content_type
    _replace_body(response, body)


def plant_into_response(
    response: http.Response, payload: bytes, *, before: bytes | None = None
) -> tuple[int, bool]:
    """Plant ``payload`` into an app response in its own Content-Encoding.

    Status and headers are kept, except the ones that described the old body (see the
    module docstring). Returns ``(offset in the decoded body, True)``; if the response
    is not :func:`plantable` or its body cannot be decoded and re-encoded, it is left
    exactly as it was and ``(-1, False)`` is returned. The caller only plants on GET.
    """
    raw = response.raw_content
    if raw is None or not plantable(response):
        return -1, False
    wire, offset, ok = plant_into_body(
        raw, response.headers.get("content-encoding"), payload, before=before
    )
    if not ok:
        return -1, False
    _replace_body(response, wire)
    return offset, True


def _not_planted(action: Action) -> tuple[Planted, ...]:
    return tuple(Planted(plant, None, False) for plant in action.plants)


def _apply_robots(
    response: http.Response, action: Action
) -> tuple[tuple[Planted, ...], dict[str, JsonValue]]:
    status = response.status_code
    meta: dict[str, JsonValue] = {"synthesized_base": False}
    if status == 404:
        # The app has no robots.txt: serve the minimal base plus the P1 lines, as 200.
        body, offsets = render_robots(DEFAULT_ROBOTS_BASE.encode(), action.plants)
        _replace_representation(response, 200, _TEXT_PLAIN, body)
        meta["synthesized_base"] = True
        return tuple(Planted(p, o, True) for p, o in zip(action.plants, offsets, strict=True)), meta
    if status != 200 or not plantable(response):
        meta["note"] = f"app answered {status}; robots.txt not planted"
        return _not_planted(action), meta
    encoding = response.headers.get("content-encoding")
    decoded = decode_body(response.raw_content or b"", encoding)
    if decoded is None:
        meta["note"] = f"cannot decode content-encoding {encoding!r}"
        return _not_planted(action), meta
    body, offsets = render_robots(decoded, action.plants)
    wire = encode_body(body, encoding)
    if wire is None:
        meta["note"] = f"cannot re-encode content-encoding {encoding!r}"
        return _not_planted(action), meta
    _replace_body(response, wire)
    return tuple(Planted(p, o, True) for p, o in zip(action.plants, offsets, strict=True)), meta


def _apply_error(
    response: http.Response, action: Action
) -> tuple[tuple[Planted, ...], dict[str, JsonValue]]:
    status = response.status_code
    meta: dict[str, JsonValue] = {"expected_status": action.expected_status}
    if not 400 <= status < 500:
        meta["note"] = f"app answered {status}, not 4xx; nothing planted"
        return _not_planted(action), meta
    if status != action.expected_status:
        meta["note"] = f"expected {action.expected_status}, app answered {status}"
    (plant,) = action.plants
    offset, ok = plant_into_response(response, plant.content, before=b"</body>")
    if not ok:
        meta["note"] = "app error body cannot be planted into (encoding or range)"
        return _not_planted(action), meta
    return (Planted(plant, offset, True),), meta


def _apply_decoy(response: http.Response) -> None:
    _replace_representation(response, 200, _TEXT_HTML, DECOY_PAGE.encode())


# --------------------------------------------------------------------------- addon


class _FlowState:
    """Per-flow decision, kept in ``flow.metadata`` (a plain class: see serve_log)."""

    __slots__ = ("action", "logged", "probe")

    def __init__(self, probe: bool, action: Action | None) -> None:
        self.probe = probe
        self.action = action
        self.logged = False


def _ts(timestamp: float | None) -> datetime:
    return datetime.fromtimestamp(timestamp, tz=UTC) if timestamp else datetime.now(UTC)


def _refuse(flow: http.HTTPFlow) -> None:
    flow.response = http.Response.make(502, _WITHHELD, {"content-type": "text/plain"})


class SurfaceInjector:
    """Plants a run's surfaces into the app's responses and logs every request."""

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
        flow.metadata[_METADATA_KEY] = self._classify(flow)

    def _apply(self, response: http.Response, action: Action) -> ServedBody | None:
        """Transform the app's response; return what to log for planted surfaces."""
        app_status = response.status_code
        if action.kind is ActionKind.DECOY:
            _apply_decoy(response)
            return None
        if action.kind is ActionKind.ROBOTS:
            planted, meta = _apply_robots(response, action)
        else:
            planted, meta = _apply_error(response, action)
        wire = response.raw_content or b""
        try:
            decoded = response.get_content(strict=True) or b""
        except ValueError:  # cannot happen after a successful plant; record raw bytes
            decoded = wire
        checked = tuple(
            p
            if p.insert_ok
            and p.offset is not None
            and decoded[p.offset : p.offset + len(p.plant.content)] == p.plant.content
            else Planted(p.plant, None, False)
            for p in planted
        )
        meta.update(
            action=action.kind.value,
            app_status=app_status,
            content_encoding=response.headers.get("content-encoding"),
        )
        return ServedBody(
            wire, decoded, response.status_code, _ts(response.timestamp_start), checked, meta
        )

    def response(self, flow: http.HTTPFlow) -> None:
        state = self._state(flow)
        if state.logged:
            return
        state.logged = True
        served: ServedBody | None = None
        if state.action is not None and flow.response is not None:
            try:
                served = self._apply(flow.response, state.action)
            except Exception:
                log.exception("injector: cannot transform flow %s; withholding it", flow.id)
                _refuse(flow)
        status = flow.response.status_code if flow.response is not None else None
        try:
            self._log.record(self._access(flow, state, status), served)
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
