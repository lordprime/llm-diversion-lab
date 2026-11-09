"""The Compose cell backend, driven with a recording fake of the Docker CLI."""

from __future__ import annotations

import hashlib
import io
import ipaddress
import json
import stat
import tarfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from control.core.models import Arm
from control.runner.cell_spec import (
    AgentSpec,
    CellError,
    CellSettings,
    ComposeProject,
    allocate_subnets,
    render_cell,
)
from control.runner.compose_backend import (
    CellHandle,
    CollectReport,
    CommandResult,
    ComposeBackend,
    ContainerState,
    extract_evidence,
    files_tar,
)
from control.runner.experiment import load_experiment
from control.runner.render import render_manifest
from control.runner.schedule import build_schedule

REPO_ROOT = Path(__file__).resolve().parents[2]
KEY = hashlib.sha256(b"compose-backend-test-key").digest()
IMAGES = {
    "lab-cell": "ghcr.io/lordprime/lab-cell@sha256:" + "a" * 64,
    "goat-dvga": "ghcr.io/lordprime/goat-dvga@sha256:" + "b" * 64,
}

Responder = Callable[[tuple[str, ...], bytes | None], CommandResult | None]


@dataclass
class FakeDocker:
    """Records argv; the first responder that answers wins, else exit 0 with no output."""

    responders: list[Responder] = field(default_factory=list)
    calls: list[tuple[tuple[str, ...], bytes | None]] = field(default_factory=list)

    def __call__(
        self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        key = tuple(argv)
        self.calls.append((key, stdin))
        for responder in self.responders:
            result = responder(key, stdin)
            if result is not None:
                return result
        return CommandResult(key, 0)

    def argvs(self) -> list[tuple[str, ...]]:
        return [a for a, _ in self.calls]


def _after_compose(argv: tuple[str, ...]) -> tuple[str, ...]:
    """The Compose subcommand and its arguments (after ``--profile setup``)."""
    return argv[argv.index("setup") + 1 :] if "compose" in argv else argv[1:]


@pytest.fixture(scope="module")
def project() -> ComposeProject:
    experiment = load_experiment(REPO_ROOT / "experiments" / "selftest.yaml")
    run = next(r for r in build_schedule(experiment) if r.arm is Arm.INJECTED)
    manifest = render_manifest(run, experiment, KEY, created_at=datetime(2026, 11, 7, tzinfo=UTC))
    return render_cell(
        run,
        manifest,
        experiment=experiment,
        settings=CellSettings(images=IMAGES),
        subnets=allocate_subnets((ipaddress.IPv4Network("10.231.0.0/16"),), []),
    )


@pytest.fixture(scope="module")
def guarded() -> ComposeProject:
    """A cell whose agent starts containers (so it has a cell-guard and a scratch volume)."""
    experiment = load_experiment(REPO_ROOT / "experiments" / "selftest.yaml")
    run = next(r for r in build_schedule(experiment) if r.arm is Arm.CONTROL)
    manifest = render_manifest(run, experiment, KEY, created_at=datetime(2026, 11, 7, tzinfo=UTC))
    spec = AgentSpec(
        name="scripted",
        image="lab-cell",
        command=("python", "-m", "agents.scripted.agent"),
        needs_docker=True,
    )
    return render_cell(
        run,
        manifest,
        experiment=experiment,
        settings=CellSettings(images=IMAGES),
        subnets=allocate_subnets((ipaddress.IPv4Network("10.231.0.0/16"),), []),
        agent_spec=spec,
    )


def _ps_writer(argv: tuple[str, ...], _stdin: bytes | None) -> CommandResult | None:
    if _after_compose(argv)[:3] == ("ps", "-a", "-q"):
        return CommandResult(argv, 0, b"cid-" + _after_compose(argv)[3].encode() + b"\n")
    return None


def test_up_writes_files_through_the_writer_then_starts_infrastructure_only(
    tmp_path: Path, project: ComposeProject
) -> None:
    docker = FakeDocker([_ps_writer])
    backend = ComposeBackend(docker)
    cell = backend.prepare(project, tmp_path)
    assert docker.calls == []  # prepare only writes the project file
    backend.up(cell)
    assert stat.S_IMODE(cell.compose_file.stat().st_mode) == 0o600
    assert cell.compose_file.read_text() == project.to_yaml()
    steps = [_after_compose(a) for a in docker.argvs()]
    assert steps[0] == ("create", "secrets-writer")
    assert steps[1] == ("ps", "-a", "-q", "secrets-writer")
    volumes = sorted({f.volume for f in project.files})
    copies = docker.calls[2 : 2 + len(volumes)]
    assert sorted(a for a, _ in copies) == sorted(
        ("docker", "cp", "-", f"cid-secrets-writer:/w/{v}") for v in volumes
    )
    rest = steps[2 + len(volumes) :]
    assert rest[0] == ("rm", "-f", "-s", "secrets-writer")
    assert rest[1][:3] == ("up", "-d", "--no-build")
    started = set(rest[1][3:])
    assert "agent" not in started and "secrets-writer" not in started
    assert started == {"goat", "injector", "tap", "stub-llm", "catcher"}
    for argv in docker.argvs():
        if "compose" in argv:
            assert argv[2:6] == ("-p", project.name, "-f", str(cell.compose_file))

    # each copied tar: one root-owned regular file per CellFile of that volume, its mode
    seen = 0
    for argv, stdin in copies:
        volume = argv[3].rpartition("/")[2]
        assert stdin is not None
        with tarfile.open(fileobj=io.BytesIO(stdin)) as tar:
            members = {m.name: m for m in tar.getmembers()}
            expected = [f for f in project.files if f.volume == volume]
            assert set(members) == {f.name for f in expected}
            for f in expected:
                member = members[f.name]
                assert member.isreg() and (member.uid, member.gid, member.mode) == (0, 0, f.mode)
                extracted = tar.extractfile(member)
                assert extracted is not None and extracted.read() == f.content
                seen += 1
                if volume.startswith("secret_"):
                    assert member.mode == 0o400
    assert seen == len(project.files)


@dataclass
class Engine:
    """A tiny container engine: what exists, and how the CLI calls change it.

    Every object here carries the run label. ``down`` fails (network still in use) while
    any container Compose does not manage is attached, as Docker's does.
    """

    project: str
    containers: dict[str, str | None] = field(default_factory=dict)  # id -> compose project
    volumes: set[str] = field(default_factory=set)
    networks: set[str] = field(default_factory=set)
    fail: set[str] = field(default_factory=set)  # steps that fail: "cp", "up", "ls"
    #: volumes that exist without this run's label (a label filter never lists them)
    unlabelled: set[str] = field(default_factory=set)

    def __call__(self, argv: tuple[str, ...], stdin: bytes | None) -> CommandResult | None:
        ok = CommandResult(argv, 0)
        sub = _after_compose(argv) if "compose" in argv else argv[1:]
        if "compose" in argv:
            if sub[0] == "create":
                self.containers["writer"] = self.project
                self.volumes |= {f"{self.project}_cfg", f"{self.project}_secret"}
                self.networks.add(f"{self.project}_agent")
                return ok
            if sub[:3] == ("ps", "-a", "-q"):
                return CommandResult(argv, 0, b"writer\n" if "writer" in self.containers else b"")
            if sub[0] == "rm":
                self.containers.pop("writer", None)
                return ok
            if sub[0] == "up":
                if "up" in self.fail:
                    self.containers["goat"] = self.project  # half started
                    return CommandResult(argv, 1, b"", b"up failed")
                self.containers.update({s: self.project for s in sub[3:]})
                return ok
            if sub[0] == "down":
                self.containers = {k: v for k, v in self.containers.items() if v != self.project}
                # down -v removes the volumes the project declares (never an unknown one)
                self.volumes = {
                    v
                    for v in self.volumes
                    if not v.startswith(self.project + "_") or v in self.unlabelled
                }
                if any(v is None for v in self.containers.values()):
                    return CommandResult(argv, 1, b"", b"network has active endpoints")
                self.networks.clear()
                return ok
            return ok
        if sub[0] == "cp":
            return CommandResult(argv, 1, b"", b"cp failed") if "cp" in self.fail else ok
        if sub[:2] == ("volume", "create"):
            self.volumes.add(sub[-1])
            return ok
        if sub[:2] == ("volume", "inspect"):
            return ok if sub[2] in self.volumes else CommandResult(argv, 1, b"", b"no such volume")
        if sub[1:2] in (("ls",), ("-a",)) and "ls" in self.fail:
            return CommandResult(argv, 1, b"", b"cannot connect to the daemon")
        if sub[:2] == ("ps", "-a"):
            if "--format" in sub:
                rows = "".join(f"{c} {p or ''}\n" for c, p in self.containers.items())
                return CommandResult(argv, 0, rows.encode())
            return CommandResult(argv, 0, "".join(f"{c}\n" for c in self.containers).encode())
        if sub[:2] == ("rm", "-f"):
            for c in sub[3:]:
                self.containers.pop(c, None)
            return ok
        if sub[0] in ("volume", "network") and sub[1] == "ls":
            items = self.volumes - self.unlabelled if sub[0] == "volume" else self.networks
            return CommandResult(argv, 0, "".join(f"{i}\n" for i in sorted(items)).encode())
        if sub[:2] == ("volume", "rm"):
            self.volumes -= set(sub[3:])
            return ok
        if sub[:2] == ("network", "rm"):
            if self.containers:
                return CommandResult(argv, 1, b"", b"in use")
            self.networks -= set(sub[2:])
            return ok
        return ok

    @property
    def empty(self) -> bool:
        return not (self.containers or self.volumes or self.networks)


@pytest.mark.parametrize("step", ["cp", "up"])
def test_a_failed_up_tears_the_cell_down_and_reraises(
    tmp_path: Path, project: ComposeProject, step: str
) -> None:
    engine = Engine(project.name, fail={step})
    backend = ComposeBackend(FakeDocker([engine]))
    cell = backend.prepare(project, tmp_path)
    with pytest.raises(CellError, match=f"{step} failed"):
        backend.up(cell)
    assert engine.empty, engine
    assert not cell.compose_file.exists()


def test_the_scratch_volume_is_created_labelled_and_removed_by_name(
    tmp_path: Path, guarded: ComposeProject
) -> None:
    engine = Engine(guarded.name)
    docker = FakeDocker([engine])
    backend = ComposeBackend(docker)
    cell = backend.prepare(guarded, tmp_path)
    backend.up(cell)
    assert guarded.scratch_volume is not None
    create = ("docker", "volume", "create", "--label", f"lab.run_id={guarded.run_id}")
    # checked absent, then created, before anything starts
    assert docker.argvs()[0] == ("docker", "volume", "inspect", guarded.scratch_volume)
    assert docker.argvs()[1] == (*create, guarded.scratch_volume)
    assert guarded.scratch_volume in engine.volumes
    assert not any("lab.origin" in " ".join(a) for a in docker.argvs())
    backend.teardown(cell)
    assert engine.empty


def test_an_existing_scratch_volume_is_refused_and_left_alone(
    tmp_path: Path, guarded: ComposeProject
) -> None:
    assert guarded.scratch_volume is not None
    other = guarded.scratch_volume
    engine = Engine(guarded.name, volumes={other}, unlabelled={other})  # someone else's
    docker = FakeDocker([engine])
    backend = ComposeBackend(docker)
    cell = backend.prepare(guarded, tmp_path)
    with pytest.raises(CellError, match="already exists"):
        backend.up(cell)
    assert not any(a[1:3] == ("volume", "create") for a in docker.argvs())
    backend.teardown(cell)  # the runner still tears down: never by that name
    assert engine.volumes == {guarded.scratch_volume}


def test_a_failed_log_read_raises(tmp_path: Path, project: ComposeProject) -> None:
    def refuse(argv: tuple[str, ...], _stdin: bytes | None) -> CommandResult | None:
        return CommandResult(argv, 1, b"", b"no such service") if "logs" in argv else None

    with pytest.raises(CellError, match="no such service"):
        ComposeBackend(FakeDocker([refuse])).logs(CellHandle(project, tmp_path / "c.yml"), "tap")


def test_teardown_removes_cell_guard_containers_before_compose_down(
    tmp_path: Path, guarded: ComposeProject
) -> None:
    engine = Engine(guarded.name)
    docker = FakeDocker([engine])
    backend = ComposeBackend(docker)
    cell = backend.prepare(guarded, tmp_path)
    backend.up(cell)
    engine.containers["spawned"] = None  # an agent-started container on the agent network
    engine.volumes.add("anon-of-spawned")
    backend.teardown(cell)
    assert engine.empty
    argvs = docker.argvs()
    first_rm = argvs.index(("docker", "rm", "-f", "-v", "spawned"))
    down = next(i for i, a in enumerate(argvs) if "down" in a)
    assert first_rm < down  # otherwise down fails with the network still in use
    assert not cell.compose_file.exists()  # it held the probe secret


def test_teardown_is_judged_by_listing_again_not_by_downs_exit_code(
    tmp_path: Path, project: ComposeProject
) -> None:
    class Stuck(Engine):
        def __call__(self, argv: tuple[str, ...], stdin: bytes | None) -> CommandResult | None:
            if argv[1:3] == ("network", "rm") or "down" in argv:
                # down "succeeds" without removing the network; the rm fails
                return CommandResult(argv, 0 if "down" in argv else 1, b"", b"busy")
            return super().__call__(argv, stdin)

    engine = Stuck(project.name, networks={"leftover"})
    with pytest.raises(CellError, match="leftover"):
        ComposeBackend(FakeDocker([engine])).teardown(CellHandle(project, tmp_path / "compose.yml"))


def test_cell_guard_evidence_is_collected_from_its_own_path(
    tmp_path: Path, guarded: ComposeProject
) -> None:
    def respond(argv: tuple[str, ...], _stdin: bytes | None) -> CommandResult | None:
        if argv[:2] == ("docker", "cp"):
            service = argv[2].split(":")[0].removeprefix("cid-")
            root = Path(argv[2].split(":")[1]).name
            prefix = guarded.evidence[service]
            return CommandResult(argv, 0, _evidence_tar([(f"{root}/{prefix}/f.txt", b"1")]))
        return _ps_writer(argv, _stdin)

    docker = FakeDocker([respond])
    report = ComposeBackend(docker).collect(
        CellHandle(guarded, tmp_path / "c.yml"), tmp_path / "ev"
    )
    assert "cellguard/f.txt" in report.files and report.refused == []
    assert ("docker", "cp", "cid-cellguard:/var/lib/cellguard-evidence", "-") in docker.argvs()


def test_a_failed_listing_is_a_failed_teardown(tmp_path: Path, project: ComposeProject) -> None:
    engine = Engine(project.name, fail={"ls"})
    with pytest.raises(CellError, match="cannot connect"):
        ComposeBackend(FakeDocker([engine])).teardown(CellHandle(project, tmp_path / "compose.yml"))


def test_health_polls_the_targets_own_script_until_it_passes(
    tmp_path: Path, project: ComposeProject
) -> None:
    answers = iter([1, 1, 0])

    def health(argv: tuple[str, ...], _stdin: bytes | None) -> CommandResult | None:
        if _after_compose(argv)[:3] == ("exec", "-T", "goat"):
            assert _after_compose(argv)[3:] == ("/opt/support/health.sh",)
            return CommandResult(argv, next(answers))
        return None

    backend = ComposeBackend(FakeDocker([health]), health_interval_s=0)
    cell = CellHandle(project, tmp_path / "compose.yml")
    assert backend.health(cell, timeout_s=60) is True
    never = ComposeBackend(FakeDocker([lambda a, _: CommandResult(a, 1)]), health_interval_s=0)
    assert never.health(cell, timeout_s=0) is False


def test_state_parses_compose_ps_json(tmp_path: Path, project: ComposeProject) -> None:
    cell = CellHandle(project, tmp_path / "compose.yml")
    for out, expected in [
        (b'{"State":"running","ExitCode":0}\n', ContainerState("running", 0)),
        (b'[{"State":"exited","ExitCode":3}]', ContainerState("exited", 3)),
        (b"", ContainerState("missing")),
    ]:
        docker = FakeDocker([lambda a, _, o=out: CommandResult(a, 0, o)])
        assert ComposeBackend(docker).state(cell, "agent") == expected
    assert ContainerState("running").running and not ContainerState("exited", 0).running
    created = ContainerState("created")
    assert created.pending and not created.running and not created.ended
    assert ContainerState("exited", 0).ended and ContainerState("dead").ended


def test_subnets_in_use_reads_every_networks_ipam(tmp_path: Path) -> None:
    inspect = [
        {"IPAM": {"Config": [{"Subnet": "10.231.0.0/27"}, {"Subnet": "fd00::/64"}]}},
        {"IPAM": {"Config": None}},
        {"IPAM": {"Config": [{"Subnet": "172.17.0.0/16"}]}},
    ]

    def respond(argv: tuple[str, ...], _stdin: bytes | None) -> CommandResult | None:
        if argv[1:4] == ("network", "ls", "-q"):
            return CommandResult(argv, 0, b"n1\nn2\nn3\n")
        if argv[1:3] == ("network", "inspect"):
            assert argv[3:] == ("n1", "n2", "n3")
            return CommandResult(argv, 0, json.dumps(inspect).encode())
        return None

    nets = ComposeBackend(FakeDocker([respond])).subnets_in_use()
    assert nets == [ipaddress.IPv4Network("10.231.0.0/27"), ipaddress.IPv4Network("172.17.0.0/16")]


def _evidence_tar(entries: list[tuple[str, Any]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, content in entries:
            info = tarfile.TarInfo(name)
            if content == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif isinstance(content, tuple):  # (type, linkname)
                info.type, info.linkname = content
                tar.addfile(info)
            else:
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def test_extract_evidence_keeps_only_the_producers_own_regular_files(tmp_path: Path) -> None:
    data = _evidence_tar(
        [
            ("evidence", "dir"),
            ("evidence/agent", "dir"),
            ("evidence/agent/events.jsonl", b'{"x":1}\n'),
            ("evidence/agent/sub/ok.txt", b"ok"),
            ("evidence/injector/events.jsonl", b"forged"),  # another producer's file
            ("evidence/agent/.hidden", b"h"),
            ("evidence/agent/../../etc/passwd", b"x"),
            ("evidence/agent/link", (tarfile.SYMTYPE, "/etc/shadow")),
            ("evidence/agent/hard", (tarfile.LNKTYPE, "evidence/agent/events.jsonl")),
            ("evidence/agent/fifo", (tarfile.FIFOTYPE, "")),
        ]
    )
    report = CollectReport()
    extract_evidence(data, tmp_path, "agent", report)
    assert sorted(report.files) == ["agent/events.jsonl", "agent/sub/ok.txt"]
    assert (tmp_path / "agent" / "events.jsonl").read_bytes() == b'{"x":1}\n'
    assert not (tmp_path / "injector").exists()
    assert not (tmp_path / "agent" / "link").exists()
    assert not (tmp_path / "agent" / "hard").exists()
    assert not (tmp_path / "agent" / "fifo").exists()
    assert len(report.refused) == 6
    assert not any(p.name == "passwd" for p in tmp_path.rglob("*"))


def test_extract_evidence_never_overwrites(tmp_path: Path) -> None:
    data = _evidence_tar([("evidence/agent/events.jsonl", b"a")])
    extract_evidence(data, tmp_path, "agent", CollectReport())
    with pytest.raises(FileExistsError):
        extract_evidence(data, tmp_path, "agent", CollectReport())


def test_collect_copies_each_producers_evidence_from_its_container(
    tmp_path: Path, project: ComposeProject
) -> None:
    def respond(argv: tuple[str, ...], _stdin: bytes | None) -> CommandResult | None:
        if argv[:2] == ("docker", "cp"):
            container = argv[2].split(":")[0]
            prefix = project.evidence[container.removeprefix("cid-")]
            return CommandResult(argv, 0, _evidence_tar([(f"evidence/{prefix}/f.txt", b"1")]))
        return _ps_writer(argv, _stdin)

    docker = FakeDocker([respond])
    report = ComposeBackend(docker).collect(
        CellHandle(project, tmp_path / "c.yml"), tmp_path / "ev"
    )
    assert sorted(report.files) == sorted(f"{p}/f.txt" for p in project.evidence.values())
    copies = [a for a in docker.argvs() if a[:2] == ("docker", "cp")]
    assert all(a[2].endswith(":/evidence") and a[3] == "-" for a in copies)
    assert set(project.evidence) == {"injector", "tap", "catcher", "agent"}


def test_files_tar_round_trips() -> None:
    from control.runner.cell_spec import CellFile

    data = files_tar([CellFile("cfg_agent", "script.json", b"{}", mode=0o444)])
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        (member,) = tar.getmembers()
        assert member.name == "script.json" and member.mode == 0o444


def test_extract_evidence_accepts_podmans_absolute_member_names(tmp_path: Path) -> None:
    data = _evidence_tar([("/", "dir"), ("/llm", "dir"), ("/llm/events.jsonl", b"{}\n")])
    report = CollectReport()
    extract_evidence(data, tmp_path, "llm", report)
    assert report.files == ["llm/events.jsonl"] and report.refused == []
