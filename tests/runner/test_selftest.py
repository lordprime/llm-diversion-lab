"""``labctl selftest`` against a fake cell backend, real Postgres and the Collector.

The cell is :class:`tests.runner.test_runner.FakeBackend` (it writes the evidence a
scripted-agent cell leaves behind), extended with the catcher's HTTP callback. The
containment probe is the real argv of :class:`DockerContainmentProbe`, answered by
the real ``cell.probe.containment`` module with a fake network, so the flags the
self-test builds are the ones the probe accepts.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import ipaddress
import json
import socket
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from cell.probe import containment
from control.api.app import create_app
from control.cli import main as cli
from control.core.models import Arm, Callback, CallbackChannel, RunManifest
from control.core.selftest_status import read_selftest_status
from control.runner import selftest
from control.runner.cell_spec import CellSettings, ComposeProject
from control.runner.compose_backend import CellHandle, CollectReport, CommandResult, ContainerState
from control.runner.experiment import parse_experiment, read_experiment
from control.runner.selftest import (
    ContainmentGate,
    DockerContainmentProbe,
    SelftestDeps,
    SelftestReport,
    cell_layout,
    derive_experiment,
    run_selftest,
)
from control.runner.ship import CollectorClient
from control.runner.store import RunStore
from tests.runner.test_runner import IMAGES, KEY, TS, FakeBackend, _file, _write_events

REPO_ROOT = Path(__file__).resolve().parents[2]
SELFTEST_YAML = REPO_ROOT / "experiments" / "selftest.yaml"
LAN = "192.168.1.1"


# --------------------------------------------------------------------------- fakes


def _manifest(project: ComposeProject) -> RunManifest:
    return RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))


class SelftestBackend(FakeBackend):
    """The fake cell, plus the catcher's HTTP callback (the DNS one is FakeBackend's)."""

    def __init__(self, *, http_callback: bool = True, wrong_token: bool = False, **kw: Any):
        super().__init__(**kw)
        self.http_callback = http_callback
        self.wrong_token = wrong_token

    def collect(
        self, cell: CellHandle, dest: Path, services: Sequence[str] | None = None
    ) -> CollectReport:
        report = super().collect(cell, dest, services)
        manifest = _manifest(cell.project)
        if self.http_callback and manifest.placements and self.llm_calls:
            placement = manifest.placements[-1]
            token = "a" * 12 if self.wrong_token else placement.token
            _write_events(
                dest / "catcher" / "http" / "events.jsonl",
                [
                    Callback(
                        run_id=manifest.run_id,
                        stream="catcher-http",
                        seq=0,
                        ts=TS,
                        channel=CallbackChannel.HTTP,
                        method="GET",
                        url=f"http://{token}.cb.lab.test/",
                        host=f"{token}.cb.lab.test",
                        token=token,
                        placement_id=None if self.wrong_token else placement.placement_id,
                    )
                ],
            )
        return report


def _network(
    *,
    reachable: Callable[[str, int], bool] = lambda _h, _p: False,
    dead: frozenset[str] = frozenset(),
) -> tuple[containment.Connector, containment.Resolver]:
    """A cell network: cell services answer unless ``dead``; others per ``reachable``."""

    def connect(host: str, port: int, timeout: float) -> None:
        addr = ipaddress.ip_address(host)
        in_cell = isinstance(addr, ipaddress.IPv4Address) and addr in ipaddress.ip_network(
            "10.231.0.0/16"
        )
        # the catcher (.2), the injector (.3) and the tap (.4) of a /27 cell network
        if in_cell and addr.packed[-1] % 32 in (2, 3, 4) and host not in dead:
            return
        if reachable(host, port):
            return
        raise TimeoutError("timed out")

    def resolve(name: str, timeout: float) -> list[str]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    return connect, resolve


class ProbeEngine:
    """A CommandRunner for ``docker run ... python -m cell.probe.containment ...``."""

    def __init__(
        self,
        *,
        reachable: Callable[[str, int], bool] = lambda _h, _p: False,
        dead: frozenset[str] = frozenset(),
        returncode: int | None = None,
        stdout: bytes | None = None,
    ) -> None:
        self.connect, self.resolve = _network(reachable=reachable, dead=dead)
        self.returncode = returncode
        self.stdout = stdout
        self.argvs: list[list[str]] = []
        #: shared with the fake backend, so the probe's place in the lifecycle shows
        self.calls: list[tuple[str, str]] = []

    def __call__(
        self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        self.argvs.append(list(argv))
        if list(argv[:2]) != ["docker", "run"]:
            return CommandResult(tuple(argv), 0)  # e.g. rm -f
        label = next(a for a in argv if a.startswith("lab.run_id="))
        self.calls.append(("probe", label.partition("=")[2]))
        if self.stdout is not None:
            return CommandResult(tuple(argv), self.returncode or 0, self.stdout)
        args = list(argv)
        probe_args = args[args.index("cell.probe.containment") + 1 :]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = containment.main(probe_args, connect=self.connect, resolve=self.resolve)
        return CommandResult(tuple(argv), code, out.getvalue().encode())


@pytest.fixture
def collector(engine: Engine) -> Iterator[CollectorClient]:
    with TestClient(create_app(engine)) as http:
        yield CollectorClient(http)


def _deps(
    engine: Engine,
    collector: CollectorClient,
    tmp_path: Path,
    backend: FakeBackend | None = None,
    probe_engine: ProbeEngine | None = None,
    leftovers: Callable[[str], dict[str, list[str]]] = lambda _r: {},
) -> SelftestDeps:
    settings = CellSettings(images=IMAGES)
    backend = backend or SelftestBackend()
    probe_engine = probe_engine or ProbeEngine()
    probe_engine.calls = backend.calls
    return SelftestDeps(
        engine=engine,
        collector=collector,
        backend=backend,
        probe=DockerContainmentProbe(probe_engine, image=settings.image("lab-cell"), lan=[LAN]),
        leftovers=leftovers,
        settings=settings,
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
        lock_path=tmp_path / "state" / "runner.lock",
        templates_root=REPO_ROOT,
        runner_options={"oracle_interval_s": 0, "tick_s": 0, "sleep": lambda _s: None},
    )


def _failed(report: SelftestReport) -> dict[str, str]:
    return {c.name: c.detail for c in report.checks if not c.ok}


# --------------------------------------------------------------------------- pass


def test_a_healthy_pair_passes(engine: Engine, collector: CollectorClient, tmp_path: Path) -> None:
    backend = SelftestBackend()
    probe_engine = ProbeEngine()
    report = run_selftest(_deps(engine, collector, tmp_path, backend, probe_engine), quick=False)
    assert report.passed, _failed(report)
    assert not report.critical
    assert len(report.runs) == 2 and {r["arm"] for r in report.runs} == {"injected", "control"}
    names = {c.name for c in report.checks}
    for arm in ("injected", "control"):
        assert f"{arm}: valid" in names and f"{arm}: completed" in names
        assert f"{arm}: contained" in names and f"{arm}: nothing left" in names
    assert "injected: callbacks" in names and "control: no tags" in names
    # full mode probes every cell, each before its agent starts
    assert len(report.probes) == 2 and all(p.contained for p in report.probes)
    for run_id in (r["run_id"] for r in report.runs):
        mine = [c for c, arg in backend.calls if arg == run_id]
        assert mine == ["prepare", "up", "health", "probe", "start_agent", "collect", "teardown"]
    # the summary is short and carries no tag or token
    assert report.summary.startswith("passed")
    data = report.to_json()
    assert data["passed"] is True and data["quick"] is False
    json.dumps(data)


def test_quick_runs_the_pair_and_probes_one_cell(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    report = run_selftest(_deps(engine, collector, tmp_path), quick=True)
    assert report.passed, _failed(report)
    assert report.quick and len(report.runs) == 2 and len(report.probes) == 1


def test_selftests_can_run_again_and_again(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    first = run_selftest(_deps(engine, collector, tmp_path / "a"), quick=True)
    second = run_selftest(_deps(engine, collector, tmp_path / "b"), quick=True)
    assert first.passed and second.passed, (_failed(first), _failed(second))
    assert first.experiment_id != second.experiment_id


# --------------------------------------------------------------------------- failures


def test_a_tag_leaked_into_the_control_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    def leak(project: ComposeProject) -> str | None:
        manifest = _manifest(project)
        if manifest.arm is Arm.INJECTED:
            return None
        schedule = RunStore(engine).load_schedule(manifest.experiment_id)
        return next(r.tag for r in schedule if r.pair_id == manifest.pair_id and r.tag)

    report = run_selftest(
        _deps(engine, collector, tmp_path, SelftestBackend(leak=leak)), quick=False
    )
    assert not report.passed
    failed = _failed(report)
    assert "contaminated" in failed["control: valid"]
    assert "control: no tags" in failed
    assert "injected: valid" not in failed


def test_a_crashed_agent_fails_although_the_runs_are_valid(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend(agent_states=[ContainerState("exited", 1)])
    report = run_selftest(_deps(engine, collector, tmp_path, backend), quick=False)
    assert not report.passed
    failed = _failed(report)
    assert "injected: valid" not in failed and "control: valid" not in failed
    assert "crashed" in failed["injected: completed"]
    assert "crashed" in failed["control: completed"]


def test_reachable_internet_is_a_critical_failure_and_the_agent_never_starts(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend()
    probe_engine = ProbeEngine(reachable=lambda host, port: host == "1.1.1.1")
    report = run_selftest(_deps(engine, collector, tmp_path, backend, probe_engine), quick=True)
    assert not report.passed and report.critical
    failed = _failed(report)
    contained = [name for name in failed if name.endswith(": contained")]
    assert len(contained) == 1 and "internet:tcp:1.1.1.1:443 reachable" in failed[contained[0]]
    probed = report.probes[0].run_id
    assert ("start_agent", probed) not in backend.calls
    assert ("teardown", probed) in backend.calls
    assert "CRITICAL" in report.render_text()


@pytest.mark.parametrize(
    ("reachable", "expected"),
    [
        (lambda host, _p: host == LAN, f"lan:tcp:{LAN}:80 reachable"),
        (  # the agent network's gateway (.1 of its /27): the host
            lambda host, _p: host.startswith("10.231.") and int(host.split(".")[-1]) % 32 == 1,
            "host:tcp:",
        ),
    ],
)
def test_reachable_lan_or_host_is_a_critical_failure(
    engine: Engine,
    collector: CollectorClient,
    tmp_path: Path,
    reachable: Callable[[str, int], bool],
    expected: str,
) -> None:
    report = run_selftest(
        _deps(engine, collector, tmp_path, probe_engine=ProbeEngine(reachable=reachable)),
        quick=True,
    )
    assert report.critical
    assert any(expected in d for n, d in _failed(report).items() if n.endswith("contained"))


def test_a_failed_must_reach_is_a_critical_failure(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    class DeadInjector(ProbeEngine):
        def __call__(
            self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
        ) -> CommandResult:
            args = list(argv)
            if "--reach" in args:  # the injector (the first --reach) answers nothing
                self.connect, self.resolve = _network(
                    dead=frozenset({args[args.index("--reach") + 1].rpartition(":")[0]})
                )
            return super().__call__(argv, stdin=stdin, timeout=timeout)

    report = run_selftest(
        _deps(engine, collector, tmp_path, probe_engine=DeadInjector()), quick=True
    )
    assert report.critical
    detail = next(d for n, d in _failed(report).items() if n.endswith("contained"))
    assert "reach:tcp:" in detail and "timeout" in detail


@pytest.mark.parametrize(
    ("probe_engine", "expected"),
    [
        (ProbeEngine(returncode=2, stdout=b"usage: bad flag\n"), "no report"),
        (ProbeEngine(returncode=125, stdout=b""), "exit 125"),
        (
            ProbeEngine(returncode=0, stdout=json.dumps({"contained": True}).encode() + b"\n"),
            "incomplete",
        ),
    ],
)
def test_a_broken_probe_fails_closed(
    engine: Engine,
    collector: CollectorClient,
    tmp_path: Path,
    probe_engine: ProbeEngine,
    expected: str,
) -> None:
    report = run_selftest(_deps(engine, collector, tmp_path, probe_engine=probe_engine), quick=True)
    assert report.critical
    detail = next(d for n, d in _failed(report).items() if n.endswith("contained"))
    assert expected in detail


def test_missing_http_callback_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend(http_callback=False)
    report = run_selftest(_deps(engine, collector, tmp_path, backend), quick=True)
    assert "http" in _failed(report)["injected: callbacks"]
    assert not report.critical


def test_a_callback_whose_token_is_not_the_runs_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend(wrong_token=True)
    report = run_selftest(_deps(engine, collector, tmp_path, backend), quick=True)
    assert "http" in _failed(report)["injected: callbacks"]


def test_leftovers_after_teardown_fail(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    report = run_selftest(
        _deps(engine, collector, tmp_path, leftovers=lambda _r: {"networks": ["n1"]}),
        quick=True,
    )
    failed = _failed(report)
    assert "networks" in failed["injected: nothing left"]
    assert "networks" in failed["control: nothing left"]


def test_another_runner_holding_the_host_lock_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    import fcntl
    import os

    deps = _deps(engine, collector, tmp_path)
    deps.lock_path.parent.mkdir(parents=True)
    fd = os.open(deps.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        report = run_selftest(deps, quick=True)
    finally:
        os.close(fd)
    assert not report.passed
    assert "another runner" in _failed(report)["run the pair"]


# --------------------------------------------------------------------------- pieces


def test_the_probe_argv_uses_the_cell_layout(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    probe_engine = ProbeEngine()
    report = run_selftest(_deps(engine, collector, tmp_path, probe_engine=probe_engine), quick=True)
    assert report.passed, _failed(report)
    argv = next(a for a in probe_engine.argvs if a[:2] == ["docker", "run"])
    run_id = report.probes[0].run_id
    agent_net = next(a for a in argv if a.startswith("labcell-") and a.endswith("_agent"))
    assert agent_net == f"labcell-{run_id.lower()}_agent"
    assert f"lab.run_id={run_id}" in argv
    assert IMAGES["lab-cell"] in argv
    for flag in ("--cap-drop", "--read-only", "--rm"):
        assert flag in argv
    probe_args = argv[argv.index("cell.probe.containment") + 1 :]

    def values(flag: str) -> list[str]:
        return [probe_args[i + 1] for i, a in enumerate(probe_args) if a == flag]

    gateway = values("--host-gateway")[0]
    (sinkhole,) = values("--sinkhole")
    reach = values("--reach")
    assert values("--lan") == [LAN] and "--defaults" in probe_args
    net = ipaddress.ip_network(gateway + "/27", strict=False)
    assert gateway == str(net.network_address + 1)
    assert sinkhole == str(net.network_address + 2)
    assert reach == [f"{net.network_address + 3}:80", f"{net.network_address + 4}:8080"]
    for value in [gateway, sinkhole, *(r.rpartition(":")[0] for r in reach)]:
        ipaddress.ip_address(value)  # IP literals only, never a service name


def test_cell_layout_reads_the_rendered_project(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend()
    run_selftest(_deps(engine, collector, tmp_path, backend), quick=True)
    layout = cell_layout(backend.projects[0])
    assert layout.network.endswith("_agent")
    assert (layout.injector_port, layout.tap_port) == (80, 8080)


def test_derive_experiment_gives_a_fresh_definition_each_time(tmp_path: Path) -> None:
    original = read_experiment(SELFTEST_YAML)
    a = derive_experiment(SELFTEST_YAML, quick=False)
    b = derive_experiment(SELFTEST_YAML, quick=True)
    assert a.experiment.experiment_id != b.experiment.experiment_id
    assert a.experiment.experiment_id.startswith("exp_selftest_")
    assert a.definition_sha256 != original.definition_sha256
    assert a.definition_sha256 == hashlib.sha256(a.definition_yaml.encode()).hexdigest()
    assert parse_experiment(a.definition_yaml) == a.experiment
    assert original.definition_sha256 in a.definition_yaml  # provenance
    # everything but the id is the file's
    assert a.experiment.model_copy(update={"experiment_id": "x"}) == (
        original.experiment.model_copy(update={"experiment_id": "x"})
    )


def test_quick_keeps_only_the_first_target(tmp_path: Path) -> None:
    text = SELFTEST_YAML.read_text()
    block = text.split("targets:\n", 1)[1].split("\nagents:", 1)[0]
    two = text.replace(block, block + "\n" + block.replace("- name: dvga", "- name: other"))
    path = tmp_path / "two.yaml"
    path.write_text(two)
    assert len(read_experiment(path).experiment.targets) == 2
    assert [t.name for t in derive_experiment(path, quick=True).experiment.targets] == ["dvga"]
    assert len(derive_experiment(path, quick=False).experiment.targets) == 2


def test_the_gate_delegates_and_probes_before_the_agent() -> None:
    calls: list[str] = []

    class Inner(FakeBackend):
        def start_agent(self, cell: CellHandle) -> None:
            calls.append("start_agent")

    class Probe:
        def __call__(self, cell: CellHandle) -> selftest.ProbeRecord:
            calls.append("probe")
            return selftest.ProbeRecord(cell.project.run_id, True, {}, ())

    gate = ContainmentGate(Inner(), Probe(), limit=1)
    handle = CellHandle(project=_dummy_project(), compose_file=Path("/nonexistent"))
    gate.start_agent(handle)
    gate.start_agent(handle)  # past the limit: no more probes
    assert calls == ["probe", "start_agent", "start_agent"]
    assert gate.subnets_in_use() == [ipaddress.IPv4Network("10.231.0.0/27")]


def _dummy_project() -> ComposeProject:
    return ComposeProject(
        name="labcell-run_x",
        run_id="run_x",
        document={"services": {}, "networks": {}},
        files=(),
        probe_secret="0" * 32,
    )


# --------------------------------------------------------------------------- labctl


def _report(passed: bool, *, critical: bool = False) -> SelftestReport:
    check = selftest.Check("injected: contained", passed, "" if passed else "breach", critical)
    return SelftestReport(
        quick=True,
        experiment_id="exp_selftest_x",
        started_at=1_800_000_000.0,
        finished_at=1_800_000_100.0,
        checks=(check,),
    )


@pytest.mark.parametrize(("passed", "code"), [(True, 0), (False, 1)])
def test_labctl_selftest_exit_code_and_recorded_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    passed: bool,
    code: int,
) -> None:
    status = tmp_path / "state" / "selftest.json"
    monkeypatch.setenv("LAB_ROOT", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL", "postgresql://lab:x@127.0.0.1:9/lab")
    seen: list[bool] = []

    def fake(context: selftest.LabContext, *, quick: bool) -> SelftestReport:
        seen.append(quick)
        assert context.lab_root == tmp_path
        return _report(passed, critical=not passed)

    monkeypatch.setattr(cli.selftest, "run_lab_selftest", fake)
    assert cli.main(["selftest", "--quick"]) == code
    out = capsys.readouterr().out
    assert seen == [True]
    assert ("PASSED" if passed else "FAILED") in out
    last = read_selftest_status(status).last_run
    assert last is not None and (last.passed, last.quick) == (passed, True)
    assert last.finished_at == 1_800_000_100.0

    assert cli.main(["selftest", "--json"]) == code
    data = json.loads(capsys.readouterr().out)
    assert data["passed"] is passed and data["checks"][0]["name"] == "injected: contained"


def test_labctl_selftest_usage_error_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["selftest", "--bogus"]) == 2


def test_labctl_selftest_without_configuration_fails_and_records_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LAB_ROOT", str(tmp_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert cli.main(["selftest", "--quick"]) == 1
    assert "FAILED" in capsys.readouterr().out
    last = read_selftest_status(tmp_path / "state" / "selftest.json").last_run
    assert last is not None and not last.passed and "DATABASE_URL" in last.summary


def test_lab_selftest_refuses_missing_secrets_before_any_cell(
    engine: Engine, tmp_path: Path
) -> None:
    context = selftest.LabContext(
        lab_root=tmp_path,
        environ={"LAB_DEV": "1", "LAB_CELL_NETWORKS": "10.231.0.0/16", "LAB_PROBE_LAN": LAN},
        collector_url="http://127.0.0.1:9",
        engine=engine,
    )
    report = selftest.run_lab_selftest(context, quick=True)
    assert not report.passed
    assert "hmac.key" in _failed(report)["configuration"]


def test_lab_selftest_needs_a_lan_address_and_host_env_off_dev(
    engine: Engine, tmp_path: Path
) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    (secrets_dir / "hmac.key").write_bytes(b"k" * 32)
    no_host_env = selftest.LabContext(
        lab_root=tmp_path, environ={}, collector_url="http://127.0.0.1:9", engine=engine
    )
    assert (
        "host.env" in _failed(selftest.run_lab_selftest(no_host_env, quick=True))["configuration"]
    )
    (tmp_path / "host.env").write_text("LAB_CELL_NETWORKS=10.231.0.0/16\nLAB_LLM_GATEWAY=\n")
    no_lan = selftest.LabContext(
        lab_root=tmp_path, environ={}, collector_url="http://127.0.0.1:9", engine=engine
    )
    assert (
        "LAB_PROBE_LAN" in _failed(selftest.run_lab_selftest(no_lan, quick=True))["configuration"]
    )
    override = selftest.LabContext(
        lab_root=tmp_path,
        environ={"LAB_PROBE_HOST_GATEWAY": "192.168.1.50", "LAB_PROBE_LAN": LAN},
        collector_url="http://127.0.0.1:9",
        engine=engine,
    )
    assert "LAB_DEV" in _failed(selftest.run_lab_selftest(override, quick=True))["configuration"]


def test_the_host_profile_carries_the_probe_lan() -> None:
    ansible = REPO_ROOT / "deploy" / "ansible"
    template = (ansible / "templates" / "host.env.j2").read_text()
    assert "LAB_PROBE_LAN={{ lab_probe_lan | join(',') }}" in template
    group_vars = yaml.safe_load((ansible / "group_vars" / "all.yml").read_text())
    assert group_vars["lab_probe_lan"] == "{{ lab_upstream_dns }}"
