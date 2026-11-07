"""``labctl doctor``: one check per prerequisite, exit 0 only when none failed.

Every check is exercised on its own with fakes (a Docker API on a Unix socket, a fake
``lab-cell-egress``, the Collector app through a TestClient); the database check runs
against a real migrated Postgres (the ``engine`` fixture).
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from ipaddress import IPv4Network
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from control.api.app import create_app
from control.cli import doctor
from control.cli.doctor import (
    CHECK_NAMES,
    DEFAULT_CELL_RANGE,
    CheckResult,
    DoctorConfig,
    Status,
    exit_code,
    parse_cell_networks,
    render_text,
    run_doctor,
)
from control.cli.settings import LabSettings
from tests.conftest import alembic_config

VALID_HOST_ENV = """\
# managed
LAB_HOST=lab1
LAB_ISOLATION=lxc
LAB_CELL_NETWORKS=10.231.0.0/16
LAB_CONTAINERD_PINNED=false
"""


# --------------------------------------------------------------------- fakes


class _DockerHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        if self.path.endswith("/_ping"):
            body, ctype = b"OK", "text/plain"
        elif self.path.endswith("/version"):
            body, ctype = json.dumps({"Version": "29.1.3"}).encode(), "application/json"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def address_string(self) -> str:  # a Unix socket has no peer address
        return "unix"

    def log_message(self, *args: Any) -> None:
        pass


class _UnixHTTPServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture
def docker_socket(tmp_path: Path) -> Iterator[Path]:
    # AF_UNIX paths are limited to ~108 bytes; pytest's tmp_path can be longer.
    import tempfile

    with tempfile.TemporaryDirectory(prefix="lab-docker-") as d:
        path = Path(d) / "docker.sock"
        server = _UnixHTTPServer(str(path), _DockerHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield path
        finally:
            server.shutdown()
            server.server_close()


def _egress(tmp_path: Path, rc: int, out: str = "") -> Path:
    script = tmp_path / "lab-cell-egress"
    script.write_text(f"#!/bin/sh\n[ \"$1\" = check ] || exit 9\necho '{out}'\nexit {rc}\n")
    script.chmod(0o755)
    return script


def _config(tmp_path: Path, **kw: Any) -> DoctorConfig:
    settings = LabSettings.from_environ({"LAB_ROOT": str(tmp_path / "lab")})
    defaults: dict[str, Any] = {
        "settings": settings,
        "egress_command": tmp_path / "absent-lab-cell-egress",
        "docker_host": f"unix://{tmp_path}/absent.sock",
        "http_client": httpx.Client(timeout=2),
        "database_url": None,
    }
    defaults.update(kw)
    return DoctorConfig(**defaults)


def _write_host_env(tmp_path: Path, text: str = VALID_HOST_ENV) -> None:
    (tmp_path / "lab").mkdir(exist_ok=True)
    (tmp_path / "lab" / "host.env").write_text(text, encoding="utf-8")


def _by_name(results: list[CheckResult]) -> dict[str, CheckResult]:
    return {r.name: r for r in results}


# --------------------------------------------------------------------- cell networks


@pytest.mark.parametrize(
    "value",
    ["10.231.0.0/16", "10.231.0.0/24,10.231.1.0/24", "10.231.128.0/17"],
)
def test_cell_networks_accepted(value: str) -> None:
    nets = parse_cell_networks(value, DEFAULT_CELL_RANGE)
    assert all(isinstance(n, IPv4Network) for n in nets)


@pytest.mark.parametrize(
    ("value", "why"),
    [
        ("", "empty"),
        ("10.231.0.1/16", "host bits"),
        ("10.230.0.0/16", "outside"),
        ("10.0.0.0/8", "outside"),
        ("192.168.1.0/24", "outside"),
        ("fd00::/64", "IPv4"),
        ("10.231.0.0/24,10.231.0.0/25", "overlap"),
        ("10.231.0.0/24,", "empty"),
        (" 10.231.0.0/24", "whitespace"),
        ("10.231.0.0", "prefix"),
        ("garbage", "not a network"),
    ],
)
def test_cell_networks_rejected(value: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        parse_cell_networks(value, DEFAULT_CELL_RANGE)


def test_default_cell_range() -> None:
    assert IPv4Network("10.231.0.0/16") == DEFAULT_CELL_RANGE


# --------------------------------------------------------------------- host.env


def test_host_env_ok(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    result = doctor.check_host_env(_config(tmp_path))
    assert result.status is Status.OK, result.detail
    assert "10.231.0.0/16" in result.detail


def test_host_env_missing(tmp_path: Path) -> None:
    result = doctor.check_host_env(_config(tmp_path))
    assert result.status is Status.FAIL
    assert "host.env" in result.detail


@pytest.mark.parametrize(
    "text",
    [
        "LAB_HOST=lab1\n",  # no LAB_CELL_NETWORKS
        "LAB_CELL_NETWORKS=\n",
        "LAB_CELL_NETWORKS=172.20.0.0/16\n",
        "LAB_CELL_NETWORKS=10.231.0.5/16\n",
    ],
)
def test_host_env_bad_cell_networks(tmp_path: Path, text: str) -> None:
    _write_host_env(tmp_path, text)
    result = doctor.check_host_env(_config(tmp_path))
    assert result.status is Status.FAIL
    assert "LAB_CELL_NETWORKS" in result.detail


def test_host_env_custom_cell_range(tmp_path: Path) -> None:
    _write_host_env(tmp_path, "LAB_CELL_NETWORKS=10.99.0.0/24\n")
    cfg = _config(tmp_path, cell_range=IPv4Network("10.99.0.0/16"))
    assert doctor.check_host_env(cfg).status is Status.OK


# --------------------------------------------------------------------- firewall


def test_firewall_skipped_off_host(tmp_path: Path) -> None:
    result = doctor.check_firewall(_config(tmp_path))
    assert result.status is Status.SKIP
    assert "not on the lab host" in result.detail


def test_firewall_check_passes(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    cfg = _config(tmp_path, egress_command=_egress(tmp_path, 0, "DOCKER-USER matches"))
    result = doctor.check_firewall(cfg)
    assert result.status is Status.OK, result.detail


def test_firewall_check_fails(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    cfg = _config(tmp_path, egress_command=_egress(tmp_path, 1, "table inet lab_host missing"))
    result = doctor.check_firewall(cfg)
    assert result.status is Status.FAIL
    assert "lab_host" in result.detail


def test_firewall_tool_missing_on_the_host_fails(tmp_path: Path) -> None:
    _write_host_env(tmp_path)  # host.env present: this is the lab host
    result = doctor.check_firewall(_config(tmp_path))
    assert result.status is Status.FAIL
    assert "lab-cell-egress" in result.detail


# --------------------------------------------------------------------- docker


def test_docker_reachable(tmp_path: Path, docker_socket: Path) -> None:
    result = doctor.check_docker(_config(tmp_path, docker_host=f"unix://{docker_socket}"))
    assert result.status is Status.OK, result.detail
    assert "29.1.3" in result.detail


def test_docker_unreachable(tmp_path: Path) -> None:
    result = doctor.check_docker(_config(tmp_path))
    assert result.status is Status.FAIL


def test_docker_non_unix_host_is_refused(tmp_path: Path) -> None:
    result = doctor.check_docker(_config(tmp_path, docker_host="tcp://10.0.0.1:2375"))
    assert result.status is Status.FAIL
    assert "unix" in result.detail


# --------------------------------------------------------------------- collector + metrics


@pytest.fixture
def collector_client(engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(engine)) as c:
        yield c


def test_collector_and_metrics_up(tmp_path: Path, collector_client: TestClient) -> None:
    cfg = _config(
        tmp_path,
        settings=LabSettings.from_environ(
            {"LAB_ROOT": str(tmp_path), "LAB_COLLECTOR_URL": "http://testserver"}
        ),
        http_client=collector_client,
    )
    assert doctor.check_collector(cfg).status is Status.OK
    assert doctor.check_metrics(cfg).status is Status.OK


def test_collector_down(tmp_path: Path) -> None:
    cfg = _config(
        tmp_path,
        settings=LabSettings.from_environ(
            {"LAB_ROOT": str(tmp_path), "LAB_COLLECTOR_URL": "http://127.0.0.1:9"}
        ),
    )
    assert doctor.check_collector(cfg).status is Status.FAIL
    assert doctor.check_metrics(cfg).status is Status.FAIL


def test_metrics_fail_when_the_collector_cannot_read_the_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with TestClient(create_app()) as client:
        cfg = _config(
            tmp_path,
            settings=LabSettings.from_environ(
                {"LAB_ROOT": str(tmp_path), "LAB_COLLECTOR_URL": "http://testserver"}
            ),
            http_client=client,
        )
        assert doctor.check_collector(cfg).status is Status.OK
        result = doctor.check_metrics(cfg)
    assert result.status is Status.FAIL
    assert "lab_metrics_database_up 0" in result.detail


def test_metrics_without_lab_metrics_fails(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="# nothing here\n")

    cfg = _config(
        tmp_path,
        settings=LabSettings.from_environ(
            {"LAB_ROOT": str(tmp_path), "LAB_COLLECTOR_URL": "http://collector"}
        ),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = doctor.check_metrics(cfg)
    assert result.status is Status.FAIL
    assert "lab_runs_total" in result.detail


# --------------------------------------------------------------------- database


def test_database_at_head(tmp_path: Path, db_url: str, engine: Engine) -> None:
    result = doctor.check_database(_config(tmp_path, database_url=db_url))
    assert result.status is Status.OK, result.detail
    assert "head" in result.detail


def test_database_behind_head(tmp_path: Path, db_url: str, engine: Engine) -> None:
    command.downgrade(alembic_config(db_url), "-1")
    result = doctor.check_database(_config(tmp_path, database_url=db_url))
    assert result.status is Status.FAIL
    assert "not at head" in result.detail


def test_database_never_migrated(tmp_path: Path, db_url: str) -> None:
    result = doctor.check_database(_config(tmp_path, database_url=db_url))
    assert result.status is Status.FAIL
    assert "not at head" in result.detail


def test_database_unreachable_does_not_leak_the_password(tmp_path: Path) -> None:
    url = "postgresql://lab:hunter2-secret@127.0.0.1:9/lab"
    result = doctor.check_database(_config(tmp_path, database_url=url))
    assert result.status is Status.FAIL
    assert "hunter2" not in result.detail


def test_database_not_configured(tmp_path: Path) -> None:
    result = doctor.check_database(_config(tmp_path))
    assert result.status is Status.FAIL
    assert "DATABASE_URL" in result.detail


# --------------------------------------------------------------------- whole run


def test_run_doctor_runs_every_check_and_never_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(cfg: DoctorConfig) -> CheckResult:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(doctor, "check_docker", boom)
    results = run_doctor(_config(tmp_path))
    assert [r.name for r in results] == list(CHECK_NAMES)
    assert _by_name(results)["docker"].status is Status.FAIL
    assert "RuntimeError" in _by_name(results)["docker"].detail


def test_exit_code() -> None:
    ok = CheckResult("a", Status.OK, "")
    skip = CheckResult("b", Status.SKIP, "")
    fail = CheckResult("c", Status.FAIL, "")
    assert exit_code([ok, skip]) == 0
    assert exit_code([ok, fail, skip]) == 1


def test_render_text_marks_each_status() -> None:
    text = render_text(
        [
            CheckResult("database", Status.OK, "at head"),
            CheckResult("firewall", Status.SKIP, "not on the lab host"),
            CheckResult("docker", Status.FAIL, "unreachable"),
        ]
    )
    lines = text.splitlines()
    assert lines[0].startswith("[ OK ] database")
    assert lines[1].startswith("[SKIP] firewall")
    assert lines[2].startswith("[FAIL] docker")
    assert "1 failed" in lines[-1]


def test_all_checks_pass_end_to_end(
    tmp_path: Path, db_url: str, engine: Engine, docker_socket: Path, collector_client: TestClient
) -> None:
    _write_host_env(tmp_path)
    cfg = _config(
        tmp_path,
        settings=LabSettings.from_environ(
            {"LAB_ROOT": str(tmp_path / "lab"), "LAB_COLLECTOR_URL": "http://testserver"}
        ),
        database_url=db_url,
        docker_host=f"unix://{docker_socket}",
        egress_command=_egress(tmp_path, 0),
        http_client=collector_client,
    )
    results = run_doctor(cfg)
    assert {r.name: r.status for r in results} == dict.fromkeys(CHECK_NAMES, Status.OK)
    assert exit_code(results) == 0
    assert os.environ.get("LAB_ROOT") is None  # nothing leaked into the process env
