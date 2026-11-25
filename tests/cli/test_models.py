"""``labctl models pull|list|rm``: admin-only, and only through the control plane.

Docker is faked: a scripted :class:`~control.runner.compose_backend.CommandRunner`
answers each ``docker`` call, so the tests check which commands run, in which order,
and that nothing runs at all when the caller is refused.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from control.cli import main as labctl
from control.cli import models as models_module
from control.cli.models import ModelsError, OllamaAdmin, OllamaService
from control.runner.compose_backend import CommandResult

CID = "c0ffee0123456789"
DIGEST = "a" * 64
TAGS_BODY = {
    "models": [
        {"name": "qwen3:32b", "digest": DIGEST, "size": 20_000_000_000},
        {"name": "llama3.1:8b", "digest": "sha256:" + "b" * 64, "size": 4_900_000_000},
    ]
}


@pytest.fixture(autouse=True)
def _lock_in_tmp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(models_module, "DEFAULT_LOCK_PATH", tmp_path / "run" / "models.lock")


def _http(body: str, status: str = "200 OK") -> bytes:
    return f"HTTP/1.0 {status}\r\nContent-Type: application/json\r\n\r\n{body}".encode()


class FakeDocker:
    """Answers docker calls from a script; every argv is kept in :attr:`calls`."""

    def __init__(
        self,
        *,
        ollama: Sequence[str] = (CID,),
        cells: Sequence[str] = (),
        stopped_cells: Sequence[str] = (),
        cell_networks: Sequence[str] = (),
    ) -> None:
        self.calls: list[list[str]] = []
        self.ollama = list(ollama)
        self.cells = list(cells)  # running cell containers
        self.stopped_cells = list(stopped_cells)  # created or exited ones: only `ps -a`
        self.cell_networks = list(cell_networks)
        self.uplink: dict[str, Any] = {"Labels": {"lab.role": "ollama-uplink"}, "Containers": {}}
        self.tags: bytes = _http(json.dumps(TAGS_BODY))
        self.fail: dict[str, CommandResult] = {}

    def stream(self, argv: Sequence[str]) -> int:
        """The terminal-streaming runner (a pull): only its exit status comes back."""
        self.calls.append(list(argv))
        for key, result in self.fail.items():
            if key in " ".join(argv):
                return result.returncode
        return 0

    def __call__(
        self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        self.calls.append(list(argv))
        a = list(argv)
        for key, result in self.fail.items():
            if key in " ".join(a):
                return result
        out = b""
        if a[1:2] == ["ps"]:
            joined = " ".join(a)
            if "label=lab.run_id" in joined:
                ids = self.cells + (self.stopped_cells if "-a" in a else [])
            else:
                ids = self.ollama
            out = "".join(f"{i}\n" for i in ids).encode()
        elif a[1:3] == ["network", "ls"]:
            out = "".join(f"{n}\n" for n in self.cell_networks).encode()
        elif a[1:3] == ["network", "inspect"]:
            out = json.dumps([self.uplink]).encode()
        elif a[1:2] == ["exec"] and "bash" in a:
            out = self.tags
        elif a[1:2] == ["exec"]:
            out = b"done\n"
        return CommandResult(tuple(a), 0, out)

    def verbs(self) -> list[str]:
        """``exec ollama pull`` -> ``exec:pull`` and so on, one entry per docker call."""
        verbs = []
        for a in self.calls:
            if a[1] == "exec":
                verbs.append("exec:" + (a[3] if a[3] != "bash" else "tags"))
            elif a[1] == "network":
                verbs.append("network:" + a[2])
            else:
                verbs.append(a[1])
        return verbs


def _admin(
    docker: FakeDocker,
    *,
    euid: int = 0,
    markers: Sequence[Path] = (),
    environ: dict[str, str] | None = None,
) -> OllamaAdmin:
    return OllamaAdmin(
        docker,
        geteuid=lambda: euid,
        container_markers=tuple(markers),
        environ=environ or {},
        stream=docker.stream,
    )


# --------------------------------------------------------------------- list


def test_list_reads_the_models_and_their_full_digests() -> None:
    docker = FakeDocker()
    models = _admin(docker).models()
    assert [(m.name, m.digest) for m in models] == [
        ("llama3.1:8b", "sha256:" + "b" * 64),
        ("qwen3:32b", "sha256:" + DIGEST),
    ]
    assert models[1].size_bytes == 20_000_000_000
    # one exec into the running container, never a network call from the host
    assert docker.verbs() == ["ps", "exec:tags"]


def test_list_with_no_models_is_an_empty_list() -> None:
    docker = FakeDocker()
    docker.tags = _http('{"models": []}')
    assert _admin(docker).models() == []


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not http at all",
        _http("not json"),
        _http("[]"),
        _http('{"models": "x"}'),
        _http('{"models": [{"name": "x"}]}'),
        _http('{"models": [{"name": "x", "digest": "zzz", "size": 1}]}'),
        _http('{"models": [1]}'),
        _http("{}", status="500 Internal Server Error"),
    ],
)
def test_list_refuses_an_unreadable_answer_without_a_traceback(body: bytes) -> None:
    docker = FakeDocker()
    docker.tags = body
    with pytest.raises(ModelsError, match="Ollama"):
        _admin(docker).models()


def test_list_when_ollama_is_not_running() -> None:
    with pytest.raises(ModelsError, match="not running"):
        _admin(FakeDocker(ollama=())).models()


def test_list_when_two_containers_claim_to_be_ollama() -> None:
    with pytest.raises(ModelsError, match="more than one"):
        _admin(FakeDocker(ollama=("a1", "b2"))).models()


def test_list_when_the_exec_fails_reports_the_error() -> None:
    docker = FakeDocker()
    docker.fail["bash"] = CommandResult(("docker",), 1, b"", b"connection refused")
    with pytest.raises(ModelsError, match="connection refused"):
        _admin(docker).models()


# --------------------------------------------------------------------- the admin gate


def test_a_container_is_refused_before_anything_runs(tmp_path: Path) -> None:
    marker = tmp_path / ".dockerenv"
    marker.write_text("")
    for action in (
        lambda a: a.models(),
        lambda a: a.pull("qwen3:32b"),
        lambda a: a.remove("qwen3:32b"),
    ):
        docker = FakeDocker()
        with pytest.raises(ModelsError, match="inside a container"):
            action(_admin(docker, markers=[marker]))
        assert docker.calls == []


def test_a_run_id_in_the_environment_means_a_cell() -> None:
    docker = FakeDocker()
    admin = _admin(docker, environ={"LAB_RUN_ID": "run_01HX"})
    with pytest.raises(ModelsError, match="inside a cell"):
        admin.pull("qwen3:32b")
    assert docker.calls == []


def test_without_root_it_is_refused() -> None:
    docker = FakeDocker()
    for action in (
        lambda a: a.models(),
        lambda a: a.pull("qwen3:32b"),
        lambda a: a.remove("qwen3:32b"),
    ):
        with pytest.raises(ModelsError, match="root"):
            action(_admin(docker, euid=1000))
    assert docker.calls == []


def test_the_read_only_service_has_no_admin_gate() -> None:
    # doctor reads through OllamaService; it needs neither root nor a clean container
    service = OllamaService(FakeDocker())
    assert len(service.models()) == 2
    assert not hasattr(service, "pull")


# --------------------------------------------------------------------- pull


@pytest.mark.parametrize(
    "model",
    [
        "",
        " ",
        "-rf",
        "--help",
        "qwen3 32b",
        "qwen3:32b;id",
        "$(id)",
        "`id`",
        "a|b",
        "x\ny",
        "../etc/passwd",
        "a//b",
        "qwen3:",
        ":32b",
        "a:b:c",
        "/abs",
        "q" * 300,
        "qwen3\x00",
        "ünï",
    ],
)
def test_bad_model_ids_are_refused_before_docker_runs(model: str) -> None:
    docker = FakeDocker()
    admin = _admin(docker)
    with pytest.raises(ModelsError, match="model id"):
        admin.pull(model)
    with pytest.raises(ModelsError, match="model id"):
        admin.remove(model)
    assert docker.calls == []


@pytest.mark.parametrize(
    "model", ["qwen3:32b", "llama3.1:8b", "library/gemma3:27b", "hf.co/u/m:Q4_K_M"]
)
def test_good_model_ids_are_accepted(model: str) -> None:
    docker = FakeDocker()
    _admin(docker).pull(model)
    pull = next(c for c in docker.calls if c[1] == "exec")
    assert pull[-3:] == ["ollama", "pull", model]


def test_pull_opens_the_uplink_only_around_the_pull() -> None:
    docker = FakeDocker()
    _admin(docker).pull("qwen3:32b")
    assert docker.verbs() == [
        "ps",  # any run cell container, running or not?
        "network:ls",  # any cell network?
        "ps",  # the ollama container
        "network:create",
        "network:connect",
        "exec:ollama",
        "network:disconnect",
        "network:rm",
    ]
    create = next(c for c in docker.calls if c[1:3] == ["network", "create"])
    assert "--internal" not in create
    connect = next(c for c in docker.calls if c[1:3] == ["network", "connect"])
    assert connect[-1] == CID


@pytest.mark.parametrize(
    "kwargs",
    [
        {"cells": ("deadbeef",)},
        {"stopped_cells": ("created01",)},  # created or exited: only `ps -a` sees it
        {"cell_networks": ("labcell-x_agent",)},  # a cell network left behind
    ],
)
def test_pull_and_rm_never_run_while_any_cell_exists(kwargs: dict[str, Any]) -> None:
    for action in (lambda a: a.pull("qwen3:32b"), lambda a: a.remove("qwen3:32b")):
        docker = FakeDocker(**kwargs)
        with pytest.raises(ModelsError, match="run cell"):
            action(_admin(docker))
        assert not any(c[1] == "network" and c[2] != "ls" for c in docker.calls)
        assert not any(c[1] == "exec" for c in docker.calls)
    assert any(c[1:3] == ["ps", "-a"] for c in docker.calls)


def test_the_uplink_is_created_without_container_to_container_traffic() -> None:
    docker = FakeDocker()
    _admin(docker).pull("qwen3:32b")
    create = next(c for c in docker.calls if c[1:3] == ["network", "create"])
    assert "com.docker.network.bridge.enable_icc=false" in create
    assert "lab.role=ollama-uplink" in create


@pytest.mark.parametrize(
    ("uplink", "message"),
    [
        ({"Labels": {}, "Containers": {}}, "not the Ollama uplink"),
        ({"Labels": {"lab.role": "ollama-uplink"}, "Containers": {"f" * 64: {}}}, "already has"),
        ({"Labels": {"lab.role": "ollama-uplink"}, "Containers": {CID: {}}}, "already has"),
    ],
)
def test_an_uplink_that_is_not_ours_to_touch_is_refused_and_left_alone(
    uplink: dict[str, Any], message: str
) -> None:
    docker = FakeDocker()
    docker.fail["network create"] = CommandResult(("d",), 1, b"", b"already exists")
    docker.uplink = uplink
    with pytest.raises(ModelsError, match=message) as info:
        _admin(docker).pull("qwen3:32b")
    assert "docker network rm" in str(info.value)  # the exact commands to clear it
    assert not any(
        c[1:3] in (["network", "connect"], ["network", "disconnect"]) for c in docker.calls
    )
    assert not any(c[1:3] == ["network", "rm"] for c in docker.calls)


def test_two_operations_cannot_overlap() -> None:
    docker = FakeDocker()
    inner: list[str] = []

    def stream(argv: Sequence[str]) -> int:
        # while A downloads, B (a pull or a removal) must be refused outright
        for action in (lambda a: a.pull("other:1b"), lambda a: a.remove("qwen3:32b")):
            with pytest.raises(ModelsError, match="another model operation is running"):
                action(_admin(docker))
        inner.append("refused")
        return 0

    OllamaAdmin(docker, geteuid=lambda: 0, container_markers=(), environ={}, stream=stream).pull(
        "qwen3:32b"
    )
    assert inner == ["refused"]
    # B never touched the network or the container: one create, one connect, one disconnect
    assert [c[2] for c in docker.calls if c[1] == "network" and c[2] != "ls"] == [
        "create",
        "connect",
        "disconnect",
        "rm",
    ]
    _admin(docker).remove("qwen3:32b")  # the lock is free again


def test_the_lock_is_free_after_a_failed_pull() -> None:
    docker = FakeDocker()
    docker.fail["ollama pull"] = CommandResult(("d",), 1)
    with pytest.raises(ModelsError):
        _admin(docker).pull("qwen3:32b")
    _admin(FakeDocker()).pull("qwen3:32b")


def test_an_unusable_lock_file_refuses_cleanly(tmp_path: Path) -> None:
    blocker = tmp_path / "file"
    blocker.write_text("")
    admin = OllamaAdmin(
        FakeDocker(),
        geteuid=lambda: 0,
        container_markers=(),
        environ={},
        lock_path=blocker / "x.lock",
    )
    with pytest.raises(ModelsError, match="lock"):
        admin.remove("qwen3:32b")


@pytest.mark.parametrize(
    "said", ["Error: No such network: lab-ollama-uplink", "network x not found"]
)
def test_detaching_a_network_that_is_not_there_is_not_an_error(said: str) -> None:
    docker = FakeDocker()
    docker.fail["network create"] = CommandResult(("d",), 1, b"", b"permission denied")
    docker.fail["network disconnect"] = CommandResult(("d",), 1, b"", said.encode())
    with pytest.raises(ModelsError) as info:
        _admin(docker).pull("qwen3:32b")
    assert "permission denied" in str(info.value)
    assert "attached to the internet" not in str(info.value)
    assert not any(c[1:3] == ["network", "rm"] for c in docker.calls)


@pytest.mark.parametrize("sig", ["SIGTERM", "SIGHUP", "SIGINT"])
def test_a_signal_while_the_uplink_closes_waits_until_it_is_closed(sig: str) -> None:
    import signal

    docker = FakeDocker()
    real_call = docker.__call__

    def call(argv: Sequence[str], **kw: Any) -> CommandResult:
        if argv[1:3] == ["network", "disconnect"]:
            signal.raise_signal(getattr(signal, sig))  # held: the signals are blocked now
        return real_call(argv, **kw)

    def to_exit(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)

    admin = OllamaAdmin(
        call, geteuid=lambda: 0, container_markers=(), environ={}, stream=docker.stream
    )
    old = {s: signal.signal(s, to_exit) for s in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    try:
        with pytest.raises(SystemExit):
            admin.pull("qwen3:32b")
    finally:
        for s, handler in old.items():
            signal.signal(s, handler)
    # the signal was delivered, but only after disconnect AND rm had both run
    assert docker.verbs()[-2:] == ["network:disconnect", "network:rm"]


class Interrupt(BaseException):
    """Stands for KeyboardInterrupt and SystemExit without ending the test run."""


@pytest.mark.parametrize("exc", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("where", ["network create", "network connect", "ollama pull"])
def test_an_interrupt_anywhere_in_a_pull_still_detaches_the_uplink(
    exc: type[BaseException], where: str
) -> None:
    docker = FakeDocker()
    real_call, real_stream = docker.__call__, docker.stream

    def call(argv: Sequence[str], **kw: Any) -> CommandResult:
        if where in " ".join(argv):
            docker.calls.append(list(argv))
            raise exc()
        return real_call(argv, **kw)

    def stream(argv: Sequence[str]) -> int:
        if where in " ".join(argv):
            docker.calls.append(list(argv))
            raise exc()
        return real_stream(argv)

    admin = OllamaAdmin(call, geteuid=lambda: 0, container_markers=(), environ={}, stream=stream)
    with pytest.raises(exc):
        admin.pull("qwen3:32b")
    assert docker.verbs()[-2:] == ["network:disconnect", "network:rm"]


def test_the_signal_mask_is_restored_after_the_uplink_closes() -> None:
    import signal

    before = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    _admin(FakeDocker()).pull("qwen3:32b")
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == before


def test_the_pull_streams_its_output_instead_of_capturing_it() -> None:
    docker = FakeDocker()
    streamed: list[list[str]] = []

    def stream(argv: Sequence[str]) -> int:
        streamed.append(list(argv))
        return 0

    OllamaAdmin(docker, geteuid=lambda: 0, container_markers=(), environ={}, stream=stream).pull(
        "qwen3:32b"
    )
    assert [a[-3:] for a in streamed] == [["ollama", "pull", "qwen3:32b"]]
    assert not any(c[-3:] == ["ollama", "pull", "qwen3:32b"] for c in docker.calls)


def test_cli_pull_turns_sigterm_and_sighup_into_system_exit(
    cli_admin: Callable[[OllamaAdmin], None],
) -> None:
    import signal

    seen: dict[str, Any] = {}
    docker = FakeDocker()

    def stream(argv: Sequence[str]) -> int:
        for sig in (signal.SIGTERM, signal.SIGHUP):
            with pytest.raises(SystemExit):
                signal.raise_signal(sig)
        seen["done"] = True
        return 0

    before = signal.getsignal(signal.SIGTERM)
    cli_admin(
        OllamaAdmin(docker, geteuid=lambda: 0, container_markers=(), environ={}, stream=stream)
    )
    assert labctl.main(["models", "pull", "qwen3:32b"]) == 0
    assert seen == {"done": True}
    assert signal.getsignal(signal.SIGTERM) == before


def test_a_failed_pull_still_closes_the_uplink() -> None:
    docker = FakeDocker()
    docker.fail["ollama pull"] = CommandResult(("docker",), 1)
    with pytest.raises(ModelsError, match="exit 1"):
        _admin(docker).pull("nope:1b")
    assert docker.verbs()[-2:] == ["network:disconnect", "network:rm"]


def test_an_uplink_that_will_not_close_is_reported_loudly() -> None:
    docker = FakeDocker()
    docker.fail["network disconnect"] = CommandResult(("docker",), 1, b"", b"busy")
    with pytest.raises(ModelsError) as info:
        _admin(docker).pull("qwen3:32b")
    assert "docker network disconnect" in str(info.value)
    assert "internet" in str(info.value)


def test_a_failed_pull_and_a_failed_cleanup_report_both() -> None:
    docker = FakeDocker()
    docker.fail["ollama pull"] = CommandResult(("docker",), 1)
    docker.fail["network disconnect"] = CommandResult(("docker",), 1, b"", b"busy")
    with pytest.raises(ModelsError) as info:
        _admin(docker).pull("qwen3:32b")
    assert "exit 1" in str(info.value)
    assert "docker network disconnect" in str(info.value)


def test_a_leftover_uplink_from_a_crashed_pull_is_reused() -> None:
    docker = FakeDocker()
    docker.fail["network create"] = CommandResult(
        ("docker",), 1, b"", b"network with name x already exists"
    )
    _admin(docker).pull("qwen3:32b")
    assert docker.verbs()[-3:] == ["exec:ollama", "network:disconnect", "network:rm"]


def test_other_network_create_errors_stop_the_pull() -> None:
    docker = FakeDocker()
    docker.fail["network create"] = CommandResult(("docker",), 1, b"", b"permission denied")
    with pytest.raises(ModelsError, match="permission denied"):
        _admin(docker).pull("qwen3:32b")
    assert not any(c[1:3] == ["network", "connect"] for c in docker.calls)


# --------------------------------------------------------------------- rm


def test_rm_removes_one_model_inside_the_container() -> None:
    docker = FakeDocker()
    _admin(docker).remove("qwen3:32b")
    last = docker.calls[-1]
    assert last[1] == "exec" and last[-3:] == ["ollama", "rm", "qwen3:32b"]
    # rm needs no internet: no uplink
    assert not any(c[1] == "network" and c[2] != "ls" for c in docker.calls)


def test_rm_of_a_model_that_is_not_there_says_so() -> None:
    docker = FakeDocker()
    docker.fail["ollama rm"] = CommandResult(("docker",), 1, b"", b"model 'x' not found")
    with pytest.raises(ModelsError, match="not found"):
        _admin(docker).remove("x")


# --------------------------------------------------------------------- the command line


@pytest.fixture
def cli_admin(monkeypatch: pytest.MonkeyPatch) -> Callable[[OllamaAdmin], None]:
    def install(admin: OllamaAdmin) -> None:
        monkeypatch.setattr(labctl, "_ollama_admin", lambda _settings: admin)

    return install


def test_cli_list_prints_name_digest_and_size(
    cli_admin: Callable[[OllamaAdmin], None], capsys: pytest.CaptureFixture[str]
) -> None:
    cli_admin(_admin(FakeDocker()))
    assert labctl.main(["models", "list"]) == 0
    out = capsys.readouterr().out
    assert "qwen3:32b" in out and "sha256:" + DIGEST in out


def test_cli_list_json(
    cli_admin: Callable[[OllamaAdmin], None], capsys: pytest.CaptureFixture[str]
) -> None:
    cli_admin(_admin(FakeDocker()))
    assert labctl.main(["models", "list", "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert {m["name"] for m in data} == {"qwen3:32b", "llama3.1:8b"}
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", m["digest"]) for m in data)


def test_cli_pull_inside_a_cell_exits_1_and_says_why(
    cli_admin: Callable[[OllamaAdmin], None], capsys: pytest.CaptureFixture[str]
) -> None:
    docker = FakeDocker()
    cli_admin(_admin(docker, environ={"LAB_RUN_ID": "run_1"}))
    assert labctl.main(["models", "pull", "qwen3:32b"]) == 1
    err = capsys.readouterr().err
    assert "labctl models" in err and "cell" in err
    assert docker.calls == []


def test_cli_pull_prints_the_digest_it_ended_with(
    cli_admin: Callable[[OllamaAdmin], None], capsys: pytest.CaptureFixture[str]
) -> None:
    cli_admin(_admin(FakeDocker()))
    assert labctl.main(["models", "pull", "qwen3:32b"]) == 0
    assert "sha256:" + DIGEST in capsys.readouterr().out
    # a model that is not listed afterwards is reported, not hidden
    cli_admin(_admin(FakeDocker()))
    assert labctl.main(["models", "pull", "other:1b"]) == 1
    assert "not listed" in capsys.readouterr().err


def test_cli_rm_and_a_bad_id(
    cli_admin: Callable[[OllamaAdmin], None], capsys: pytest.CaptureFixture[str]
) -> None:
    cli_admin(_admin(FakeDocker()))
    assert labctl.main(["models", "rm", "qwen3:32b"]) == 0
    assert labctl.main(["models", "rm", "--bad"]) == 2  # argparse sees an option
    assert labctl.main(["models", "rm", "a b"]) == 1
    assert "model id" in capsys.readouterr().err


def test_cli_needs_a_subcommand() -> None:
    assert labctl.main(["models"]) == 2
