"""The lane's self-check client (agents/_selfcheck/selfcheck.py), run here against a real
stub model server on a local port and a fake cell-guard on a Unix socket. In CI the same
client runs inside its image under smoke.sh."""

from __future__ import annotations

import importlib.util
import io
import json
import socket
import socketserver
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar

import pytest
import uvicorn

from agents.ci.stub_model.script import StubScript
from agents.ci.stub_model.server import RequestRecorder, StubModel, create_app
from agents.ci.stub_model.verify import RequestLog

ROOT = Path(__file__).resolve().parents[3]
SELFCHECK = ROOT / "agents" / "_selfcheck"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("selfcheck", SELFCHECK / "selfcheck.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def selfcheck() -> ModuleType:
    return _load()


@pytest.fixture
def tap(selfcheck: ModuleType, tmp_path: Path) -> Iterator[Path]:
    """A stub model server on a free local port, with the self-check's own script."""
    record = tmp_path / "requests.jsonl"
    stream = record.open("a", encoding="utf-8")
    model = StubModel(StubScript.load(SELFCHECK / "script.yaml"), RequestRecorder(stream))
    server = uvicorn.Server(uvicorn.Config(create_app(model), port=0, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        threading.Event().wait(0.02)
    port = server.servers[0].sockets[0].getsockname()[1]
    selfcheck.TAP = f"http://127.0.0.1:{port}"
    yield record
    server.should_exit = True
    thread.join(5)
    stream.close()


def test_apis_mode_calls_every_shape_and_reads_back_cleanly(
    selfcheck: ModuleType, tap: Path
) -> None:
    assert selfcheck.main(["apis"]) == 0
    log = RequestLog.load(tap)
    assert len(log.records) == 11
    assert (
        log.check(
            [
                "/api/chat",
                "/api/embed",
                "/api/embeddings",
                "/api/tags",
                "/v1/chat/completions",
                "/v1/models",
                "/v1/embeddings",
                "/v1/messages",
            ],
            ["run_command", "read_file"],
        )
        == []
    )
    assert "selfcheck-not-a-key" not in tap.read_text()


def test_the_default_mode_is_apis(selfcheck: ModuleType, tap: Path) -> None:
    assert selfcheck.main([]) == 0


def test_a_broken_tap_fails_the_check(selfcheck: ModuleType) -> None:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    selfcheck.TAP = f"http://127.0.0.1:{port}"  # nothing listens there
    assert selfcheck.main(["apis"]) == 1


@pytest.mark.parametrize(
    "argv", [["nope"], ["egress-name"], ["egress-ip", "a", "b"], ["docker"], ["docker-egress"]]
)
def test_unknown_or_incomplete_modes(selfcheck: ModuleType, argv: list[str]) -> None:
    assert selfcheck.main(argv) == 2


def test_fail_mode_exits_7(selfcheck: ModuleType) -> None:
    assert selfcheck.main(["fail"]) == 7


def test_egress_modes_try_and_still_exit_0(selfcheck: ModuleType, capsys: Any) -> None:
    assert selfcheck.main(["egress-ip", "127.0.0.1"]) == 0  # nothing on 443 locally
    assert "failed as expected" in capsys.readouterr().out


# --------------------------------------------------------------------------- --docker


class FakeGuard(BaseHTTPRequestHandler):
    """Just enough of cell-guard: version, create (403 for a socket mount), start, wait, logs."""

    calls: ClassVar[list[tuple[str, str, Any]]] = []
    worker_output: ClassVar[bytes] = b'{"models": []}'
    worker_status: ClassVar[int] = 0

    def _reply(self, status: int, body: object = None) -> None:
        data = (
            b""
            if body is None
            else (body if isinstance(body, bytes) else json.dumps(body).encode())
        )
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else None
        self.calls.append((self.command, self.path, body))
        path = self.path.split("/", 2)[-1] if self.path.startswith("/v") else self.path
        if self.path == "/version":
            self._reply(200, {"ApiVersion": "1.47"})
        elif path == "containers/create":
            binds = (body or {}).get("HostConfig", {}).get("Binds")
            self._reply(403, {"message": "bind mounts denied"}) if binds else self._reply(
                201, {"Id": "w1"}
            )
        elif path.endswith("/start"):
            self._reply(204)
        elif path.endswith("/wait"):
            self._reply(200, {"StatusCode": self.worker_status})
        elif "/logs" in path:
            self._reply(200, b"\x01\x00\x00\x00\x00\x00\x00\x0e" + self.worker_output)
        else:
            self._reply(204)

    do_GET = do_POST = do_DELETE = _handle

    def log_message(self, *args: Any) -> None:
        return


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def get_request(self) -> tuple[Any, Any]:
        request, _ = super().get_request()
        return request, ("guard", 0)


@pytest.fixture
def guard(tmp_path: Path, selfcheck: ModuleType, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "docker.sock"
    FakeGuard.calls = []
    FakeGuard.worker_output = b'{"models": []}'
    FakeGuard.worker_status = 0
    server = _UnixServer(str(path), FakeGuard)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("DOCKER_HOST", f"unix://{path}")
    selfcheck.REAL_SOCKETS = (str(tmp_path / "real.sock"), str(tmp_path / "also-real.sock"))
    yield path
    server.shutdown()
    server.server_close()


def test_docker_mode_proves_the_guard(selfcheck: ModuleType, guard: Path) -> None:
    assert (
        selfcheck.main(["docker", "busybox@sha256:" + "a" * 64, "agent-selfcheck-worker:ci"]) == 0
    )
    creates = [c for c in FakeGuard.calls if c[1].endswith("/containers/create")]
    assert creates[0][2]["HostConfig"]["Binds"] == ["/var/run/docker.sock:/var/run/docker.sock"]
    assert [c[2]["Image"] for c in creates[1:]] == [
        "busybox@sha256:" + "a" * 64,
        "agent-selfcheck-worker:ci",
    ]
    assert all(c[1].startswith("/v1.47/") for c in FakeGuard.calls if c[1] != "/version")
    # each worker is removed again
    assert sum(1 for c in FakeGuard.calls if c[0] == "DELETE") == 2


def test_docker_mode_fails_if_the_real_socket_is_there(
    selfcheck: ModuleType, guard: Path, tmp_path: Path
) -> None:
    real = tmp_path / "real.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(real))
    listener.listen()
    try:
        assert selfcheck.main(["docker", "busybox"]) == 1
    finally:
        listener.close()


def test_docker_mode_fails_if_the_guard_allows_a_socket_mount(
    selfcheck: ModuleType, guard: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = FakeGuard._handle

    def allow_everything(self: FakeGuard) -> None:
        if self.path.endswith("/containers/create"):
            length = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(length)
            self._reply(201, {"Id": "w1"})
            return
        original(self)

    monkeypatch.setattr(FakeGuard, "do_POST", allow_everything)
    assert selfcheck.main(["docker", "busybox"]) == 1


def test_docker_mode_fails_if_a_worker_cannot_reach_the_tap(
    selfcheck: ModuleType, guard: Path
) -> None:
    FakeGuard.worker_status = 1
    FakeGuard.worker_output = b"wget: bad address"
    assert selfcheck.main(["docker", "busybox"]) == 1


def test_docker_mode_needs_a_unix_docker_host(
    selfcheck: ModuleType, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    selfcheck.REAL_SOCKETS = (str(tmp_path / "none"),)
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    assert selfcheck.main(["docker", "busybox"]) == 1
    monkeypatch.delenv("DOCKER_HOST")
    assert selfcheck.main(["docker-egress", "busybox"]) == 1


def test_docker_egress_mode_runs_one_worker(selfcheck: ModuleType, guard: Path) -> None:
    FakeGuard.worker_status = 1
    assert selfcheck.main(["docker-egress", "busybox"]) == 0
    (create,) = [c for c in FakeGuard.calls if c[1].endswith("/containers/create")]
    assert "http://example.com/" in create[2]["Cmd"]


def test_the_selfcheck_script_is_valid_and_uses_every_turn_kind() -> None:
    script = StubScript.load(SELFCHECK / "script.yaml")
    assert any(t.calls_tools for t in script.turns)
    assert any(t.text and not t.calls_tools for t in script.turns)
    assert any(t.when is not None for t in script.turns)


def test_the_selfcheck_is_never_pushed_and_says_so() -> None:
    for name in ("Dockerfile", "selfcheck.py", "source.yaml"):
        assert (
            "never pushed" in (SELFCHECK / name).read_text(encoding="utf-8").lower()
            or name == "selfcheck.py"
        )
    assert "not a tool under test" in (SELFCHECK / "selfcheck.py").read_text(encoding="utf-8")
    assert not (SELFCHECK / "ci" / "push_extra").exists()


def _unused(_: io.StringIO) -> None:
    return
