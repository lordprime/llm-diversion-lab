"""Pre-flight probe of a run cell's target, run *inside* the injector container.

The runner never opens a connection into a cell; it runs this with ``docker exec`` in
the injector, which requests each path from its own listener (``127.0.0.1``) with the
``x-lab-probe`` header set to the run's probe secret (``LAB_PROBE_SECRET``, from the
injector's own environment). The injector marks those requests as probes, so they are
logged (``probe: true``) but never count as the agent's Access::

    python -m cell.injector.preflight --port 80 /robots.txt /.env

It prints one JSON object, ``{"results": [{"path", "status", "content_type",
"bytes"}...]}``, and exits ``0`` if every path got an HTTP response (any status) and
every placement check passed, ``1`` otherwise (the failure is in the result's ``error``
or its ``checks``). The runner compares the statuses with the placement map (e.g. the P7
path must answer 404) and fails the probe on any failed check.

When the injector's own run files are in the environment (``LAB_MANIFEST`` and
``LAB_PAYLOADS``), a probe of a page path (P2-P6, P8) also checks what was planted, and
the result gets ``checks``: ``[{"placement_id", "surface", "ok", "detail"}...]``:

* P2: the planted markup is in the decoded body, and the page's path is disallowed for
  ``User-agent: *`` by the robots.txt the injector serves (read with
  :mod:`urllib.robotparser`; the P1 lines a treated run adds are comments or
  non-standard lines, which the parser ignores);
* P3: the planted markup is in the decoded body;
* P4: the off-screen style is there and the element has no ``aria-hidden``;
* P5: the element has ``aria-hidden="true"``;
* P6: a JSON-LD block parses as JSON, has an ``@type`` and carries the text;
* P8: the ``X-Security-Notice`` header matches exactly, and the decoded body hashes to
  the digest the injector reports (on probe responses only, in
  :data:`~cell.injector.placement.BODY_DIGEST_HEADER`) for the body after every P2-P6
  text and before P8: P8 itself never changes the body.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from typing import Final
from urllib.robotparser import RobotFileParser

from pydantic import JsonValue

from cell.injector.placement import (
    BODY_DIGEST_HEADER,
    NOTICE_HEADER,
    PROBE_HEADER,
    ROBOTS_PATH,
    Action,
    ActionKind,
    InjectionPlan,
    Plant,
    build_plan,
    decode_body,
)
from cell.injector.serve_log import InjectorConfig
from control.core.models import Surface
from control.core.tags import request_path

__all__ = ["PlacementProbe", "main", "probe"]

_TIMEOUT_S: Final = 20.0
_OFFSCREEN_STYLE: Final = (
    b"position:absolute;left:-10000px;top:auto;width:1px;height:1px;overflow:hidden"
)
_JSONLD_BLOCK: Final = re.compile(
    rb'<script type="application/ld\+json">(.*?)</script>', re.DOTALL | re.IGNORECASE
)


class PlacementProbe:
    """Checks one probed page against the plan's plants for its path (see the module doc)."""

    def __init__(self, plan: InjectionPlan | None) -> None:
        self._plan = plan

    def action(self, path: str) -> Action | None:
        """The page action for ``path``, if the plan plants anything on it."""
        action = self._plan.match("GET", path) if self._plan is not None else None
        return action if action is not None and action.kind is ActionKind.PAGE else None

    def check(
        self,
        action: Action,
        headers: Mapping[str, list[str]],
        wire: bytes,
        robots: bytes | None = None,
    ) -> list[JsonValue]:
        """One check result per plant of ``action``, from the probe response.

        ``robots`` is the decoded robots.txt the injector serves (``None``: not fetched);
        only P2 needs it.
        """
        encodings = headers.get("content-encoding")
        encoding = encodings[0] if encodings else None
        decoded = decode_body(wire, encoding)
        checks: list[JsonValue] = []
        for plant in action.plants:
            problem = self._problem(plant, headers, decoded, robots)
            checks.append(
                {
                    "placement_id": plant.placement.placement_id,
                    "surface": plant.placement.surface.value,
                    "ok": problem is None,
                    "detail": problem or "ok",
                }
            )
        return checks

    def _problem(
        self,
        plant: Plant,
        headers: Mapping[str, list[str]],
        decoded: bytes | None,
        robots: bytes | None,
    ) -> str | None:
        """Why the plant is not served as planned, or ``None`` if it is."""
        surface = plant.placement.surface
        if decoded is None:
            return "the probe response body cannot be decoded"
        if surface is Surface.P8:
            if headers.get(NOTICE_HEADER) != [plant.content.decode("ascii")]:
                return f"{NOTICE_HEADER} does not match the planted text"
            if headers.get(BODY_DIGEST_HEADER) != [hashlib.sha256(decoded).hexdigest()]:
                return "the body is not the app's own body"
            return None
        payload = plant.payload
        if payload not in decoded:
            return "the planted markup is missing from the body"
        if surface is Surface.P2:
            return self._disallowed(request_path(plant.placement.url), robots)
        if surface is Surface.P4 and (_OFFSCREEN_STYLE not in payload or b"aria-hidden" in payload):
            return "the off-screen element lacks its style or carries aria-hidden"
        if surface is Surface.P5 and b'aria-hidden="true"' not in payload:
            return 'the element lacks aria-hidden="true"'
        if surface is Surface.P6 and not self._jsonld_ok(decoded, plant.content.decode("utf-8")):
            return "no JSON-LD block parses with an @type and the planted description"
        return None

    @staticmethod
    def _disallowed(path: str, robots: bytes | None) -> str | None:
        """Why ``path`` is not disallowed for every crawler by ``robots``, or ``None``."""
        if robots is None:
            return f"robots.txt could not be read, so {path} is not known to be disallowed"
        parser = RobotFileParser()
        parser.parse(robots.decode("utf-8", "replace").splitlines())
        if parser.can_fetch("*", path):
            return f"robots.txt does not disallow {path} for User-agent: *"
        return None

    @staticmethod
    def _jsonld_ok(decoded: bytes, text: str) -> bool:
        for block in _JSONLD_BLOCK.findall(decoded):
            try:
                doc = json.loads(block)
            except ValueError:
                continue
            if isinstance(doc, dict) and "@type" in doc and doc.get("description") == text:
                return True
        return False


def _get(
    path: str, *, port: int, secret: str, host: str
) -> tuple[int, dict[str, list[str]], bytes]:
    """One probe GET through the injector: status, lower-cased headers, wire body."""
    conn = http.client.HTTPConnection(host, port, timeout=_TIMEOUT_S)
    try:
        conn.request("GET", path, headers={PROBE_HEADER: secret})
        resp = conn.getresponse()
        body = resp.read()
        headers: dict[str, list[str]] = {}
        for name, value in resp.getheaders():
            headers.setdefault(name.lower(), []).append(value)
        return resp.status, headers, body
    finally:
        conn.close()


def _robots(*, port: int, secret: str, host: str) -> bytes | None:
    """The decoded robots.txt the injector serves, or ``None`` if there is none."""
    try:
        status, headers, wire = _get(ROBOTS_PATH, port=port, secret=secret, host=host)
    except (OSError, http.client.HTTPException):
        return None
    encodings = headers.get("content-encoding")
    return decode_body(wire, encodings[0] if encodings else None) if status == 200 else None


def probe(
    path: str,
    *,
    port: int,
    secret: str,
    host: str = "127.0.0.1",
    plan: InjectionPlan | None = None,
) -> dict[str, JsonValue]:
    """GET ``path`` from the injector as a probe; never raises.

    With a ``plan`` the result also lists the placement ``checks`` of a page path.
    """
    result: dict[str, JsonValue] = {"path": path}
    try:
        status, headers, body = _get(path, port=port, secret=secret, host=host)
        types = headers.get("content-type")
        result.update(status=status, content_type=types[0] if types else None, bytes=len(body))
        checker = PlacementProbe(plan)
        action = checker.action(path)
        if action is not None:
            wants_robots = any(p.placement.surface is Surface.P2 for p in action.plants)
            robots = _robots(port=port, secret=secret, host=host) if wants_robots else None
            result["checks"] = checker.check(action, headers, body, robots)
    except (OSError, http.client.HTTPException) as exc:
        result.update(status=None, error=f"{type(exc).__name__}: {exc}")
    return result


def _load_plan(env: Mapping[str, str]) -> InjectionPlan | None:
    """The injector's own plan, if its run files are in the environment."""
    if not env.get("LAB_MANIFEST"):
        return None
    config = InjectorConfig.from_env(env)
    return build_plan(config.manifest, config.contents, synthesize_robots=config.synthesize_robots)


def _passed(result: Mapping[str, JsonValue]) -> bool:
    """Whether a path got a response and every placement check on it passed."""
    checks = result.get("checks", [])
    if not isinstance(checks, list):
        return False
    return result.get("status") is not None and all(
        isinstance(c, dict) and c.get("ok") is True for c in checks
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe the target through the injector")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    secret = os.environ.get("LAB_PROBE_SECRET", "")
    if not secret:
        print(json.dumps({"error": "LAB_PROBE_SECRET is not set"}))
        return 1
    try:
        plan = _load_plan(os.environ)
    except ValueError as exc:
        print(json.dumps({"error": f"cannot build the injector plan: {exc}"}))
        return 1
    results = [probe(p, port=args.port, secret=secret, plan=plan) for p in args.paths]
    print(json.dumps({"results": results}, sort_keys=True))
    return 0 if all(_passed(r) for r in results) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
