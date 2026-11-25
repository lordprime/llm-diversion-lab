"""``labctl doctor``: one check per prerequisite, exit 0 only when none failed.

Every check is exercised on its own with fakes (a Docker API on a Unix socket, a fake
``lab-cell-egress``, the Collector app through a TestClient); the database check runs
against a real migrated Postgres (the ``engine`` fixture).
"""

from __future__ import annotations

import json
import os
import pwd
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
    GPU_CHECKS,
    CheckResult,
    DoctorConfig,
    Status,
    exit_code,
    parse_cell_networks,
    render_text,
    run_doctor,
)
from control.cli.settings import LabSettings
from control.runner.compose_backend import CommandResult
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


ME = pwd.getpwuid(os.getuid()).pw_name


def _write_lab_env(tmp_path: Path, mode: int = 0o600) -> Path:
    secrets = tmp_path / "lab" / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    path = secrets / "lab.env"
    path.write_text("LAB_DB_PASSWORD=" + "a" * 64 + "\n", encoding="utf-8")
    path.chmod(mode)
    return path


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
    _write_lab_env(tmp_path)
    cfg = _config(
        tmp_path,
        settings=LabSettings.from_environ(
            {"LAB_ROOT": str(tmp_path / "lab"), "LAB_COLLECTOR_URL": "http://testserver"}
        ),
        secrets_owners=frozenset({ME}),
        database_url=db_url,
        docker_host=f"unix://{docker_socket}",
        egress_command=_egress(tmp_path, 0),
        http_client=collector_client,
    )
    results = run_doctor(cfg)
    # a host without a GPU has no Ollama: those three checks are skipped, not failed
    expected = dict.fromkeys(CHECK_NAMES, Status.OK) | dict.fromkeys(GPU_CHECKS, Status.SKIP)
    assert {r.name: r.status for r in results} == expected
    assert exit_code(results) == 0
    assert os.environ.get("LAB_ROOT") is None  # nothing leaked into the process env


# --------------------------------------------------------------------- lab.env


def test_secrets_skipped_off_host(tmp_path: Path) -> None:
    result = doctor.check_secrets(_config(tmp_path))
    assert result.status is Status.SKIP


def test_secrets_ok_when_0600_and_owned_by_an_allowed_user(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    _write_lab_env(tmp_path)
    result = doctor.check_secrets(_config(tmp_path, secrets_owners=frozenset({ME})))
    assert result.status is Status.OK, result.detail
    assert "0600" in result.detail


@pytest.mark.parametrize("mode", [0o640, 0o644, 0o604, 0o700])
def test_secrets_fail_on_a_loose_mode(tmp_path: Path, mode: int) -> None:
    _write_host_env(tmp_path)
    _write_lab_env(tmp_path, mode)
    result = doctor.check_secrets(_config(tmp_path, secrets_owners=frozenset({ME})))
    assert result.status is Status.FAIL
    assert oct(mode)[2:] in result.detail


def test_secrets_fail_on_a_foreign_owner(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    _write_lab_env(tmp_path)
    result = doctor.check_secrets(_config(tmp_path))  # default owners: root, lab
    if ME in {"root", "lab"}:
        pytest.skip("the test user is an allowed owner")
    assert result.status is Status.FAIL
    assert ME in result.detail


def test_secrets_fail_when_missing_on_the_host(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    result = doctor.check_secrets(_config(tmp_path))
    assert result.status is Status.FAIL
    assert "lab.env" in result.detail


def test_default_secret_owners() -> None:
    assert frozenset({"root", "lab"}) == doctor.DEFAULT_SECRETS_OWNERS


def test_metrics_need_a_positive_database_up(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="# TYPE lab_runs_total counter\n")

    cfg = _config(
        tmp_path,
        settings=LabSettings.from_environ(
            {"LAB_ROOT": str(tmp_path), "LAB_COLLECTOR_URL": "http://collector"}
        ),
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    result = doctor.check_metrics(cfg)
    assert result.status is Status.FAIL
    assert "lab_metrics_database_up" in result.detail


def test_unparsable_database_url_is_a_clean_failure(tmp_path: Path) -> None:
    result = doctor.check_database(_config(tmp_path, database_url="not a url"))
    assert result.status is Status.FAIL
    assert "not a valid" in result.detail


# --------------------------------------------------------------------- GPU host: Ollama

GPU_HOST_ENV = VALID_HOST_ENV + "LAB_GPU=true\n"
OLLAMA_ID = "0llama0123456789"
DIGEST = "d" * 64


class FakeEngine:
    """The docker CLI as the GPU checks use it: one Ollama container on `lab_models`."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.running = [OLLAMA_ID]
        self.smi = "GPU 0: NVIDIA H200 (UUID: GPU-1234)\n"
        self.smi_rc = 0
        self.tags = (
            b'HTTP/1.0 200 OK\r\n\r\n{"models": [{"name": "qwen3:32b", "digest": "'
            + DIGEST.encode()
            + b'", "size": 5}]}'
        )
        self.ports: dict[str, Any] = {}
        self.networks = {"lab_models": {"IPAddress": "172.31.232.2"}}
        self.internal = True
        self.subnet = "172.31.232.0/24"
        self.services_on_net = ["ollama", "gateway"]

    def __call__(self, argv: Any, *, stdin: bytes | None = None, timeout: float | None = None):  # type: ignore[no-untyped-def]
        a = list(argv)
        self.calls.append(a)
        if a[1] == "ps" and any(x.startswith("network=") for x in a):
            return CommandResult(
                tuple(a), 0, "".join(f"{s}\n" for s in self.services_on_net).encode()
            )
        if a[1] == "ps":
            return CommandResult(tuple(a), 0, "".join(f"{i}\n" for i in self.running).encode())
        if a[1] == "exec" and "nvidia-smi" in a:
            return CommandResult(
                tuple(a),
                self.smi_rc,
                self.smi.encode(),
                b"" if not self.smi_rc else b"nvidia-smi failed",
            )
        if a[1] == "exec":
            return CommandResult(tuple(a), 0, self.tags)
        if a[1] == "inspect":
            doc = [{"NetworkSettings": {"Ports": self.ports, "Networks": self.networks}}]
            return CommandResult(tuple(a), 0, json.dumps(doc).encode())
        if a[1:3] == ["network", "inspect"]:
            doc = [{"Internal": self.internal, "IPAM": {"Config": [{"Subnet": self.subnet}]}}]
            return CommandResult(tuple(a), 0, json.dumps(doc).encode())
        return CommandResult(tuple(a), 1, b"", b"unexpected")


def _gpu_config(
    tmp_path: Path, engine: FakeEngine, *, host_env: str = GPU_HOST_ENV
) -> DoctorConfig:
    _write_host_env(tmp_path, host_env)
    return _config(tmp_path, runner=engine)


def test_gpu_checks_are_skipped_on_a_host_without_a_gpu(tmp_path: Path) -> None:
    _write_host_env(tmp_path)
    engine = FakeEngine()
    cfg = _config(tmp_path, runner=engine)
    for check in (doctor.check_gpu, doctor.check_models, doctor.check_ollama_isolation):
        assert check(cfg).status is Status.SKIP
    assert engine.calls == []


def test_a_gpu_host_whose_host_env_is_missing_skips_rather_than_guessing(tmp_path: Path) -> None:
    engine = FakeEngine()
    assert doctor.check_gpu(_config(tmp_path, runner=engine)).status is Status.SKIP


def test_gpu_visible_in_the_ollama_container(tmp_path: Path) -> None:
    result = doctor.check_gpu(_gpu_config(tmp_path, FakeEngine()))
    assert result.status is Status.OK, result.detail
    assert "H200" in result.detail


def test_doctor_fails_without_a_gpu(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.smi, engine.smi_rc = "", 127  # no driver in the container
    result = doctor.check_gpu(_gpu_config(tmp_path, engine))
    assert result.status is Status.FAIL
    assert "no GPU" in result.detail


@pytest.mark.parametrize("output", ["", "No devices were found\n", "garbage"])
def test_nvidia_smi_that_lists_no_gpu_fails(tmp_path: Path, output: str) -> None:
    engine = FakeEngine()
    engine.smi = output
    assert doctor.check_gpu(_gpu_config(tmp_path, engine)).status is Status.FAIL


def test_gpu_check_fails_when_ollama_is_not_running(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.running = []
    result = doctor.check_gpu(_gpu_config(tmp_path, engine))
    assert result.status is Status.FAIL
    assert "not running" in result.detail


def test_models_lists_each_pulled_model_with_its_full_digest(tmp_path: Path) -> None:
    result = doctor.check_models(_gpu_config(tmp_path, FakeEngine()))
    assert result.status is Status.OK
    assert f"qwen3:32b sha256:{DIGEST}" in result.detail


def test_models_with_nothing_pulled_is_ok_but_says_so(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.tags = b'HTTP/1.0 200 OK\r\n\r\n{"models": []}'
    result = doctor.check_models(_gpu_config(tmp_path, engine))
    assert result.status is Status.OK and "no models pulled" in result.detail


def test_models_fails_on_an_unreadable_answer(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.tags = b"nonsense"
    assert doctor.check_models(_gpu_config(tmp_path, engine)).status is Status.FAIL


def test_ollama_isolation_ok_when_only_the_gateway_shares_the_internal_network(
    tmp_path: Path,
) -> None:
    result = doctor.check_ollama_isolation(_gpu_config(tmp_path, FakeEngine()))
    assert result.status is Status.OK, result.detail


@pytest.mark.parametrize(
    ("change", "expect"),
    [
        (
            lambda e: setattr(
                e, "ports", {"11434/tcp": [{"HostIp": "127.0.0.1", "HostPort": "11434"}]}
            ),
            "published",
        ),
        (lambda e: setattr(e, "internal", False), "not internal"),
        (lambda e: setattr(e, "subnet", "10.231.4.0/27"), "cell network"),
        (lambda e: setattr(e, "services_on_net", ["ollama", "gateway", "collector"]), "collector"),
        (
            lambda e: setattr(e, "networks", {"lab_models": {}, "bridge": {}}),
            "more than the models network",
        ),
    ],
)
def test_ollama_isolation_fails_on_any_way_in(tmp_path: Path, change: Any, expect: str) -> None:
    engine = FakeEngine()
    change(engine)
    result = doctor.check_ollama_isolation(_gpu_config(tmp_path, engine))
    assert result.status is Status.FAIL
    assert expect in result.detail


def test_an_unpublished_port_entry_is_not_a_published_port(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.ports = {"11434/tcp": None}  # exposed by the image, bound to nothing
    assert doctor.check_ollama_isolation(_gpu_config(tmp_path, engine)).status is Status.OK


def test_all_gpu_checks_pass_end_to_end(
    tmp_path: Path, db_url: str, engine: Engine, docker_socket: Path, collector_client: TestClient
) -> None:
    _write_lab_env(tmp_path)
    fake = FakeEngine()
    cfg = _gpu_config(tmp_path, fake)
    cfg.settings = LabSettings.from_environ(
        {"LAB_ROOT": str(tmp_path / "lab"), "LAB_COLLECTOR_URL": "http://testserver"}
    )
    cfg.secrets_owners = frozenset({ME})
    cfg.database_url = db_url
    cfg.docker_host = f"unix://{docker_socket}"
    cfg.egress_command = _egress(tmp_path, 0)
    cfg.http_client = collector_client
    results = run_doctor(cfg)
    assert {r.name: r.status for r in results} == dict.fromkeys(CHECK_NAMES, Status.OK)


def test_the_one_network_must_be_the_projects_models_network(tmp_path: Path) -> None:
    engine = FakeEngine()
    engine.networks = {"lab_lab-ollama-uplink": {}}  # one network, but the wrong one
    result = doctor.check_ollama_isolation(_gpu_config(tmp_path, engine))
    assert result.status is Status.FAIL
    assert "lab_models" in result.detail
