"""Pre-flight probe of a run cell's target, run *inside* the injector container.

The runner never opens a connection into a cell; it runs this with ``docker exec`` in
the injector, which requests each path from its own listener (``127.0.0.1``) with the
``x-lab-probe`` header set to the run's probe secret (``LAB_PROBE_SECRET``, from the
injector's own environment). The injector marks those requests as probes, so they are
logged (``probe: true``) but never count as the agent's Access::

    python -m cell.injector.preflight --port 80 /robots.txt /.env

It prints one JSON object, ``{"results": [{"path", "status", "content_type",
"bytes"}...]}``, and exits ``0`` if every path got an HTTP response (any status), ``1``
otherwise (the failure is in the result's ``error``). The runner compares the statuses
with the placement map (e.g. the P7 path must answer 404).
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import sys
from collections.abc import Sequence
from typing import Final

from pydantic import JsonValue

from cell.injector.placement import PROBE_HEADER

__all__ = ["main", "probe"]

_TIMEOUT_S: Final = 20.0


def probe(path: str, *, port: int, secret: str, host: str = "127.0.0.1") -> dict[str, JsonValue]:
    """GET ``path`` from the injector as a probe; never raises."""
    result: dict[str, JsonValue] = {"path": path}
    conn = http.client.HTTPConnection(host, port, timeout=_TIMEOUT_S)
    try:
        conn.request("GET", path, headers={PROBE_HEADER: secret})
        resp = conn.getresponse()
        body = resp.read()
        result.update(
            status=resp.status, content_type=resp.getheader("content-type"), bytes=len(body)
        )
    except (OSError, http.client.HTTPException) as exc:
        result.update(status=None, error=f"{type(exc).__name__}: {exc}")
    finally:
        conn.close()
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe the target through the injector")
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("paths", nargs="+")
    args = parser.parse_args(argv)
    secret = os.environ.get("LAB_PROBE_SECRET", "")
    if not secret:
        print(json.dumps({"error": "LAB_PROBE_SECRET is not set"}))
        return 1
    results = [probe(p, port=args.port, secret=secret) for p in args.paths]
    print(json.dumps({"results": results}, sort_keys=True))
    return 0 if all(r.get("status") is not None for r in results) else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
