"""The cell's mitmproxy services, as rendered for a run: bounded request and response bodies.

Without ``body_size_limit`` mitmproxy buffers a body of any size, so one large upload
(or LLM request) would OOM-kill the injector or the tap (``mem_limit`` 512m). With it,
an oversized flow ends in mitmproxy's ``error`` hook: it is never forwarded, the
injector logs it with status ``null`` and the tap records nothing for it (the end-to-end
tests below run the real ``mitmdump`` with the cell's addons and a tiny limit).
"""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import http.server
import ipaddress
import itertools
import json
import os
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

from cell.injector.serve_log import EVENTS_FILE as INJECTOR_EVENTS
from cell.tap.recorder import EVENTS_FILE as TAP_EVENTS
from control.core.ids import new_id
from control.core.models import Arm, RunManifest
from control.runner.cell_spec import CellSettings, allocate_subnets, render_cell
from control.runner.experiment import load_experiment
from control.runner.render import render_manifest
from control.runner.schedule import build_schedule

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE = REPO_ROOT / "deploy" / "compose" / "cell.dvga.yml"
SELFTEST = REPO_ROOT / "experiments" / "selftest.yaml"
KEY = hashlib.sha256(b"cell-compose-test-key").digest()
WHEN = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
POOL = ipaddress.IPv4Network("10.232.0.0/16")
IMAGES = {
    "lab-cell": "ghcr.io/lordprime/lab-cell@sha256:" + "a" * 64,
    "goat-dvga": "ghcr.io/lordprime/goat-dvga@sha256:" + "b" * 64,
}
#: The limits: the injector carries target traffic (uploads), the tap LLM requests.
LIMITS = {"injector": "64m", "tap": "32m"}
MEM_LIMIT = 512 * 1024 * 1024
RUN_ID = new_id("run")


def _set_options(command: list[str]) -> dict[str, str]:
    """The ``--set name=value`` options of a mitmdump command line."""
    options: dict[str, str] = {}
    for flag, value in itertools.pairwise(command):
        if flag == "--set":
            name, _, setting = value.partition("=")
            assert name not in options, f"--set {name} given twice"
            options[name] = setting
    return options


def _size(text: str) -> int:
    units = {"k": 1024, "m": 1024**2, "g": 1024**3}
    return int(text[:-1]) * units[text[-1]] if text[-1] in units else int(text)


@pytest.fixture(scope="module", params=[Arm.CONTROL, Arm.INJECTED])
def rendered(request: pytest.FixtureRequest) -> dict[str, Any]:
    experiment = load_experiment(SELFTEST)
    run = next(r for r in build_schedule(experiment) if r.arm is request.param)
    manifest = render_manifest(run, experiment, KEY, created_at=WHEN)
    project = render_cell(
        run,
        manifest,
        experiment=experiment,
        settings=CellSettings(images=IMAGES, cell_networks=(POOL,)),
        subnets=allocate_subnets((POOL,), []),
    )
    services: dict[str, Any] = project.document["services"]
    return services


@pytest.mark.parametrize("service", sorted(LIMITS))
def test_template_bounds_mitmproxy_bodies(service: str) -> None:
    services = yaml.safe_load(TEMPLATE.read_text())["services"]
    assert _set_options(services[service]["command"])["body_size_limit"] == LIMITS[service]


@pytest.mark.parametrize("service", sorted(LIMITS))
def test_rendered_cell_bounds_mitmproxy_bodies(rendered: dict[str, Any], service: str) -> None:
    options = _set_options(rendered[service]["command"])
    assert options["body_size_limit"] == LIMITS[service]
    # mitmproxy holds a request and its response at once: both fit under the limit
    assert 2 * _size(LIMITS[service]) < MEM_LIMIT
    assert rendered[service]["mem_limit"] == "512m"
    # streaming would forward an oversized body unrecorded instead of failing the flow
    assert "stream_large_bodies" not in options


# --------------------------------------------------------------------------- end to end

_SMALL_LIMIT = "2k"


class _Upstream(http.server.ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _UpstreamHandler)
        self.seen: list[tuple[str, str, int]] = []


class _UpstreamHandler(http.server.BaseHTTPRequestHandler):
    server: _Upstream

    def _answer(self) -> None:
        length = int(self.headers.get("content-length") or 0)
        self.rfile.read(length)
        self.server.seen.append((self.command, self.path, length))
        body = b"x" * 8192 if self.path == "/big" else b"ok"
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._answer()

    def do_POST(self) -> None:
        self._answer()

    def log_message(self, format: str, *args: Any) -> None:
        return


@contextlib.contextmanager
def _upstream() -> Iterator[_Upstream]:
    server = _Upstream()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
        return port


@contextlib.contextmanager
def _mitmdump(tmp_path: Path, upstream: int, addon: str, env: dict[str, str]) -> Iterator[int]:
    mitmdump = Path(sys.executable).with_name("mitmdump")
    if not mitmdump.exists():
        pytest.skip("mitmdump is not installed (the cell extra)")
    port = _free_port()
    argv = [
        str(mitmdump),
        "--mode", f"reverse:http://127.0.0.1:{upstream}",
        "--listen-host", "127.0.0.1",
        "--listen-port", str(port),
        "--set", f"confdir={tmp_path / 'mitmproxy'}",
        "--set", "flow_detail=0",
        "--set", f"body_size_limit={_SMALL_LIMIT}",
        "-s", str(REPO_ROOT / "cell" / addon / "addon.py"),
    ]  # fmt: skip
    log_path = tmp_path / f"{addon}.log"
    with log_path.open("wb") as log:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv
            argv, env={**os.environ, **env}, stdout=log, stderr=subprocess.STDOUT
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                if proc.poll() is not None:
                    log.flush()
                    pytest.fail(f"mitmdump exited: {log_path.read_text()}")
                with contextlib.suppress(OSError):
                    socket.create_connection(("127.0.0.1", port), 1).close()
                    break
                if time.monotonic() > deadline:
                    pytest.fail("mitmdump did not start listening")
                time.sleep(0.2)
            yield port
        finally:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def _send(port: int, method: str, path: str, body: bytes = b"") -> int | None:
    """The status the client got, or ``None`` if the proxy dropped the connection."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request(method, path, body=body or None)
        resp = conn.getresponse()
        resp.read()
        return resp.status
    except (ConnectionError, http.client.HTTPException):
        return None
    finally:
        conn.close()


def _lines(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_bytes().splitlines() if line.strip()]


def _control_manifest() -> RunManifest:
    return RunManifest(
        run_id=RUN_ID,
        experiment_id=new_id("exp"),
        pair_id=new_id("pair"),
        arm=Arm.CONTROL,
        target="dvga",
        agent="scripted",
        model="stub",
        schedule_index=0,
        tag=None,
        placements=[],
        created_at=WHEN,
    )


def test_injector_oversized_flows_are_not_forwarded_and_logged_without_status(
    tmp_path: Path,
) -> None:
    manifest = tmp_path / "manifest.json"
    manifest.write_text(_control_manifest().model_dump_json())
    evidence = tmp_path / "evidence"
    env = {"LAB_MANIFEST": str(manifest), "LAB_EVIDENCE_DIR": str(evidence)}
    with _upstream() as up, _mitmdump(tmp_path, up.server_port, "injector", env) as port:
        assert _send(port, "POST", "/graphql", b"y" * 4096) != 200  # request too large
        assert _send(port, "GET", "/big") != 200  # response too large
        assert _send(port, "POST", "/graphql", b"small") == 200
        seen = list(up.seen)
    # the oversized request never reached the app; the oversized response never left
    assert ("POST", "/graphql", 4096) not in seen
    assert ("POST", "/graphql", 5) in seen
    records = _lines(evidence / INJECTOR_EVENTS)
    by_path = [(r["method"], r["url"].rsplit("/", 1)[1], r["status"]) for r in records]
    assert by_path == [("POST", "graphql", None), ("GET", "big", None), ("POST", "graphql", 200)]


def test_tap_oversized_requests_are_never_forwarded_or_recorded(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence"
    env = {"LAB_RUN_ID": RUN_ID, "LAB_EVIDENCE_DIR": str(evidence)}
    with _upstream() as up, _mitmdump(tmp_path, up.server_port, "tap", env) as port:
        assert _send(port, "POST", "/v1/messages", b"y" * 4096) != 200
        assert _send(port, "POST", "/v1/messages", b'{"model":"m"}') == 200
        seen = list(up.seen)
    assert seen == [("POST", "/v1/messages", 13)]
    calls = _lines(evidence / TAP_EVENTS)
    assert [(c["seq"], c["response_artifact"] is not None) for c in calls] == [(0, True)]
