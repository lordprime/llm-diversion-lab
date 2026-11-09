"""``labctl selftest`` against a fake cell backend, real Postgres and the Collector.

The cell is :class:`tests.runner.test_runner.FakeBackend` (it writes the evidence a
scripted-agent cell leaves behind), extended with the catcher's HTTP callback. The
containment probe is the real argv of :class:`DockerContainmentProbe`, answered by
the real ``cell.probe.containment`` module with a fake network, so the flags the
self-test builds are the ones the probe accepts.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import inspect
import io
import ipaddress
import json
import signal
import socket
import threading
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml
from dnslib import DNSRecord
from fastapi.testclient import TestClient
from sqlalchemy import Engine

from cell.probe import containment
from control.api.app import create_app
from control.cli import main as cli
from control.core.models import (
    Arm,
    Callback,
    CallbackChannel,
    InvalidReason,
    RunManifest,
    RunStatus,
)
from control.core.selftest_status import read_selftest_status
from control.db import tables as t
from control.db.engine import session_scope
from control.runner import selftest
from control.runner.cell_spec import CellError, CellSettings, ComposeProject
from control.runner.compose_backend import CellHandle, CollectReport, CommandResult, ContainerState
from control.runner.experiment import parse_experiment, read_experiment
from control.runner.runner import Runner
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
from tests.runner.test_runner import (
    IMAGES,
    KEY,
    SUCCESS,
    TS,
    UNSUCCESSFUL,
    FakeBackend,
    _file,
    _write_events,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SELFTEST_YAML = REPO_ROOT / "experiments" / "selftest.yaml"
LAN = "192.168.1.1"


# --------------------------------------------------------------------------- fakes


def _manifest(project: ComposeProject) -> RunManifest:
    return RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))


class SelftestBackend(FakeBackend):
    """The fake cell, plus the catcher's HTTP callback (the DNS one is FakeBackend's)."""

    def __init__(
        self,
        *,
        http_callback: bool = True,
        dns_callback: bool = True,
        wrong_token: bool = False,
        cell_dirs: bool = False,
        extra: Callable[[RunManifest, Path], None] | None = None,
        **kw: Any,
    ):
        super().__init__(**kw)
        self.http_callback = http_callback
        self.dns_callback = dns_callback
        self.wrong_token = wrong_token
        self.cell_dirs = cell_dirs
        self.on_collect = extra

    def prepare(self, project: ComposeProject, workdir: Path) -> CellHandle:
        handle = super().prepare(project, workdir)
        if self.cell_dirs:  # a work directory teardown never removes
            (workdir / project.name).mkdir(parents=True, exist_ok=True)
        return handle

    def collect(
        self, cell: CellHandle, dest: Path, services: Sequence[str] | None = None
    ) -> CollectReport:
        report = super().collect(cell, dest, services)
        manifest = _manifest(cell.project)
        if not self.dns_callback:
            (dest / "catcher" / "dns" / "events.jsonl").unlink(missing_ok=True)
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
        if self.on_collect is not None:
            self.on_collect(manifest, dest)
        return report


class FakeResources:
    """Labelled engine resources by run id; ``after`` is what every run leaves."""

    def __init__(
        self,
        left: dict[str, dict[str, list[str]]] | None = None,
        *,
        after: dict[str, list[str]] | None = None,
    ) -> None:
        self.left = dict(left or {})
        self.after = after or {}
        self.removed: list[str] = []

    def leftovers(self, run_id: str) -> dict[str, list[str]]:
        return dict(self.left.get(run_id, self.after))

    def labelled_run_ids(self) -> set[str]:
        return set(self.left)

    def remove(self, run_id: str) -> dict[str, list[str]]:
        self.removed.append(run_id)
        self.left.pop(run_id, None)
        return {}


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
    resources: FakeResources | None = None,
    *,
    is_local: Callable[[str], bool] = lambda _a: True,
    extra_destinations: Sequence[str] = (),
) -> SelftestDeps:
    settings = CellSettings(images=IMAGES)
    backend = backend or SelftestBackend()
    probe_engine = probe_engine or ProbeEngine()
    probe_engine.calls = backend.calls
    return SelftestDeps(
        engine=engine,
        collector=collector,
        backend=backend,
        probe=DockerContainmentProbe(
            probe_engine,
            image=settings.image("lab-cell"),
            lan=[LAN],
            is_local=is_local,
            extra_destinations=extra_destinations,
        ),
        resources=resources or FakeResources(),
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
        _deps(engine, collector, tmp_path, resources=FakeResources(after={"networks": ["n1"]})),
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


def test_a_missing_dns_callback_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend(dns_callback=False)
    report = run_selftest(_deps(engine, collector, tmp_path, backend), quick=True)
    assert _failed(report)["injected: callbacks"] == "no verified callback on dns"


def test_a_host_gateway_that_is_not_this_hosts_fails_but_is_not_a_breach(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend()
    report = run_selftest(
        _deps(engine, collector, tmp_path, backend, is_local=lambda _a: False), quick=True
    )
    assert not report.passed and not report.critical
    detail = next(d for n, d in _failed(report).items() if n.endswith("contained"))
    assert "not an address of this host" in detail
    assert ("probe", report.probes[0].run_id) not in backend.calls  # the probe never ran
    assert ("start_agent", report.probes[0].run_id) not in backend.calls


def test_a_cell_failing_before_its_agent_is_a_cell_failure_not_containment(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    for quick in (True, False):
        report = run_selftest(
            _deps(engine, collector, tmp_path / str(quick), SelftestBackend(healthy=False)),
            quick=quick,
        )
        assert not report.passed and not report.critical
        failed = _failed(report)
        assert "probe_failed" in failed["injected: valid"]
        assert all("not probed" in d for n, d in failed.items() if n.endswith("contained"))
        assert not report.probes


def test_a_cell_left_behind_keeps_the_results(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    report = run_selftest(
        _deps(engine, collector, tmp_path, SelftestBackend(teardown_error="network left")),
        quick=True,
    )
    failed = _failed(report)
    assert "stopped" in failed["run the pair"] and "network left" in failed["run the pair"]
    assert len(report.runs) == 1 and report.runs[0]["reason"] == "teardown_failed"
    assert failed["runs"] == "1 runs, expected 2"


def test_a_work_directory_left_behind_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    report = run_selftest(
        _deps(engine, collector, tmp_path, SelftestBackend(cell_dirs=True)), quick=True
    )
    assert "work_dir" in _failed(report)["injected: nothing left"]


def test_a_failed_engine_listing_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    def refuse(
        argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        return CommandResult(tuple(argv), 1, b"", b"cannot connect")

    leftovers = selftest.DockerLeftovers(refuse)
    assert leftovers.leftovers("run_x") == {
        kind: ["listing failed (exit 1)"] for kind in ("containers", "volumes", "networks")
    }
    report = run_selftest(_deps(engine, collector, tmp_path), quick=True)
    deps = _deps(engine, collector, tmp_path / "b")
    deps.resources = leftovers
    report = run_selftest(deps, quick=True)
    failed = _failed(report)
    assert "listing failed" in failed["injected: nothing left"]
    assert "cannot list" in failed["earlier self-tests swept"]


def _injected_tag(engine: Engine, manifest: RunManifest) -> str:
    schedule = RunStore(engine).load_schedule(manifest.experiment_id)
    tag = next(r.tag for r in schedule if r.pair_id == manifest.pair_id and r.tag)
    assert tag is not None
    return tag


def test_a_base64_tag_in_the_controls_catcher_evidence_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    def extra(manifest: RunManifest, dest: Path) -> None:
        if manifest.arm is not Arm.CONTROL:
            return
        body = f"hello {_injected_tag(engine, manifest)}".encode()
        _write_events(
            dest / "catcher" / "http" / "events.jsonl",
            [
                Callback(
                    run_id=manifest.run_id,
                    stream="catcher-http",
                    seq=0,
                    ts=TS,
                    channel=CallbackChannel.HTTP,
                    method="POST",
                    url="http://other.cb.lab.test/",
                    body_b64=base64.b64encode(body).decode(),
                    body_size=len(body),
                    body_sha256=hashlib.sha256(body).hexdigest(),
                )
            ],
        )

    report = run_selftest(
        _deps(engine, collector, tmp_path, SelftestBackend(extra=extra)), quick=True
    )
    assert "catcher/http/events.jsonl" in _failed(report)["control: no tags"]


def test_an_injected_token_in_the_control_fails(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    # the control runs first here: plant the injected run's token in the control's
    # evidence on disk once the injected run's placements exist
    def extra(manifest: RunManifest, dest: Path) -> None:
        if manifest.arm is not Arm.INJECTED:
            return
        schedule = RunStore(engine).load_schedule(manifest.experiment_id)
        control = next(r for r in schedule if r.pair_id == manifest.pair_id and not r.tag)
        token = manifest.placements[0].token.upper()  # case does not hide it
        path = tmp_path / "runs" / control.run_id / "llm" / "late.req.json"
        path.write_text(json.dumps({"messages": [{"content": f"see {token}"}]}))

    report = run_selftest(
        _deps(engine, collector, tmp_path, SelftestBackend(extra=extra)), quick=True
    )
    assert "llm/late.req.json" in _failed(report)["control: no tags"]


def test_earlier_selftest_leftovers_are_swept_and_study_runs_never(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    earlier = run_selftest(_deps(engine, collector, tmp_path / "a"), quick=True)
    earlier_ids = [r["run_id"] for r in earlier.runs]
    # a study experiment's runs (registered, as a runner would)
    study = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=SelftestBackend(),
        settings=CellSettings(images=IMAGES),
        lab_key=KEY,
        runs_dir=tmp_path / "s" / "runs",
        work_dir=tmp_path / "s" / "work",
    ).register(read_experiment(SELFTEST_YAML))  # experiment_id exp_selftest: no prefix
    study_id = study[0].run_id
    left = {rid: {"containers": [f"c-{rid}"]} for rid in [*earlier_ids, study_id, "run_unknown"]}
    resources = FakeResources(left)
    deps = _deps(engine, collector, tmp_path / "b", resources=resources)
    for rid in (earlier_ids[0], study_id):
        (deps.work_dir / f"labcell-{rid.lower()}").mkdir(parents=True)
    report = run_selftest(deps, quick=True)
    assert report.passed, _failed(report)
    assert sorted(resources.removed) == sorted(earlier_ids)
    assert set(resources.left) == {study_id, "run_unknown"}
    assert not (deps.work_dir / f"labcell-{earlier_ids[0].lower()}").exists()
    assert (deps.work_dir / f"labcell-{study_id.lower()}").exists()
    swept = next(c for c in report.checks if c.name == "earlier self-tests swept")
    assert "2 earlier" in swept.detail


def test_selftest_runs_are_left_out_of_the_study_counters(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    from control.api.metrics import _query
    from control.db.engine import session_scope
    from control.db.repo import invalid_runs_by_reason

    report = run_selftest(
        _deps(engine, collector, tmp_path, SelftestBackend(healthy=False)), quick=True
    )
    assert not report.passed  # two invalid self-test runs exist
    with session_scope(engine) as s:
        assert invalid_runs_by_reason(s) == {}
    counts = _query(engine)
    assert counts.finished == [] and counts.invalid == []


def test_extra_destinations_are_probed_and_must_appear_in_the_report(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    dests = ["host:tcp:172.31.231.5:8000", "host:tcp:192.168.1.97:22"]
    probe_engine = ProbeEngine()
    report = run_selftest(
        _deps(engine, collector, tmp_path, probe_engine=probe_engine, extra_destinations=dests),
        quick=True,
    )
    assert report.passed, _failed(report)
    argv = next(a for a in probe_engine.argvs if a[:2] == ["docker", "run"])
    assert [argv[i + 1] for i, a in enumerate(argv) if a == "--dest"] == dests
    # a probe that ignores a destination is not a pass
    lying = ProbeEngine()
    real = containment.main

    def drop_dests(argv: Sequence[str] | None = None, **kw: Any) -> int:
        args = list(argv or [])
        while "--dest" in args:
            i = args.index("--dest")
            del args[i : i + 2]
        return real(args, **kw)

    import unittest.mock

    with unittest.mock.patch.object(containment, "main", drop_dests):
        report = run_selftest(
            _deps(engine, collector, tmp_path / "b", probe_engine=lying, extra_destinations=dests),
            quick=True,
        )
    detail = next(d for n, d in _failed(report).items() if n.endswith("contained"))
    assert "host:tcp:172.31.231.5:8000 was not probed" in detail and report.critical


def test_control_plane_destinations_come_from_the_compose_file_and_the_engine() -> None:
    compose = REPO_ROOT / "deploy" / "compose" / "control-plane.yml"
    addresses = {"db": "172.31.231.2", "collector": "172.31.231.3"}

    def engine_cli(
        argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        if argv[1] == "ps":
            service = argv[-1].rpartition("=")[2]
            return CommandResult(tuple(argv), 0, f"id-{service}\n".encode())
        service = argv[-1].removeprefix("id-")
        doc = [
            {
                "NetworkSettings": {
                    "Networks": {
                        "lab_control": {"IPAddress": addresses[service]},
                        "x": {"IPAddress": "10.0.0.9"},
                    }
                }
            }
        ]
        return CommandResult(tuple(argv), 0, json.dumps(doc).encode())

    dests = selftest.control_plane_destinations(engine_cli, compose)
    assert set(dests) == {
        "host:tcp:172.31.231.1:5432",
        "host:tcp:172.31.231.1:8100",
        "host:tcp:172.31.231.2:5432",
        "host:tcp:172.31.231.3:8000",
    }

    def nothing_running(
        argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        return CommandResult(tuple(argv), 0, b"")

    with pytest.raises(selftest.SelftestConfigError, match="not running"):
        selftest.control_plane_destinations(nothing_running, compose)


def test_address_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    assert selftest.is_local_address("127.0.0.1")
    assert not selftest.is_local_address("192.0.2.1")
    assert not selftest.is_local_address("not-an-ip")
    assert selftest.lan_answers("127.0.0.1")  # refused on 80 and 443: it answered
    monkeypatch.setattr(selftest.shutil, "which", lambda _n: None)
    assert not selftest.lan_answers("192.0.2.1", timeout_s=0.2)


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
    assert parse_experiment(a.definition_yaml, selftest=True) == a.experiment
    with pytest.raises(ValueError, match="reserved"):  # never as a study experiment
        parse_experiment(a.definition_yaml)
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


@pytest.mark.parametrize(
    "argv_env",
    [
        {"DATABASE_URL": "not a url at all"},  # unparsable: still a recorded failure
        {"DATABASE_URL": ""},
    ],
)
def test_labctl_selftest_records_a_bad_database_url_as_a_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    argv_env: dict[str, str],
) -> None:
    monkeypatch.setenv("LAB_ROOT", str(tmp_path))
    for key, value in argv_env.items():
        monkeypatch.setenv(key, value)
    assert cli.main(["selftest"]) == 1
    last = read_selftest_status(tmp_path / "state" / "selftest.json").last_run
    assert last is not None and not last.passed and "configuration" in last.summary


def test_labctl_selftest_records_an_internal_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LAB_ROOT", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL", "postgresql://lab:x@127.0.0.1:9/lab")

    def boom(context: selftest.LabContext, *, quick: bool) -> SelftestReport:
        raise RuntimeError("unexpected")

    monkeypatch.setattr(cli.selftest, "run_lab_selftest", boom)
    assert cli.main(["selftest", "--quick"]) == 1
    assert "FAILED" in capsys.readouterr().out
    last = read_selftest_status(tmp_path / "state" / "selftest.json").last_run
    assert last is not None and not last.passed and "RuntimeError" in last.summary


def test_run_lab_selftest_turns_any_exception_into_a_failed_report(
    engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(_root: Path) -> bytes:
        raise ValueError("odd")

    monkeypatch.setattr(selftest, "_lab_key", broken)
    report = selftest.run_lab_selftest(_context(engine, tmp_path, {}), quick=True)
    assert "ValueError: odd" in _failed(report)["internal"]


# ----------------------------------------------------------------- the lab's configuration

PINNED_LOCK = """images:
  - name: lab-cell
    image: ghcr.io/lordprime/lab-cell
    digest: sha256:{a}
    role: infra
  - name: goat-dvga
    image: ghcr.io/lordprime/goat-dvga
    digest: sha256:{b}
    role: target
""".format(a="a" * 64, b="b" * 64)


def _context(
    engine: Engine,
    root: Path,
    environ: dict[str, str],
    *,
    key: bool = True,
    is_local: Callable[[str], bool] = lambda _a: True,
    lan_ok: bool = True,
) -> selftest.LabContext:
    if key:
        (root / "secrets").mkdir(parents=True, exist_ok=True)
        (root / "secrets" / "hmac.key").write_bytes(b"k" * 32)
    return selftest.LabContext(
        lab_root=root,
        environ=environ,
        collector_url="http://127.0.0.1:9",
        engine=engine,
        is_local=is_local,
        lan_answers=lambda _a: lan_ok,
    )


def _production(tmp_path: Path, profile: str | None) -> dict[str, str]:
    tree = tmp_path / "tree"
    (tree / "deploy").mkdir(parents=True)
    (tree / "deploy" / "images.lock").write_text(PINNED_LOCK)
    env = {"LAB_RELEASE_TREE": str(tree), "LAB_HOST_ENV": str(tmp_path / "host.env")}
    if profile is not None:
        (tmp_path / "host.env").write_text(profile)
    return env


def _dev(**extra: str) -> dict[str, str]:
    return {
        "LAB_DEV": "1",
        "LAB_ENGINE": "podman",
        "LAB_REQUIRE_DIGESTS": "0",
        "LAB_CELL_NETWORKS": "10.231.0.0/16",
        "LAB_IMAGE_OVERRIDES": "lab-cell=localhost/lab-cell:dev,goat-dvga=localhost/goat:dev",
        "LAB_PROBE_LAN": LAN,
        **extra,
    }


def test_lab_selftest_refuses_a_missing_lab_key(engine: Engine, tmp_path: Path) -> None:
    report = selftest.run_lab_selftest(_context(engine, tmp_path, _dev(), key=False), quick=True)
    assert "hmac.key" in _failed(report)["configuration"]


def test_production_needs_the_host_profile(engine: Engine, tmp_path: Path) -> None:
    env = _production(tmp_path, None)
    report = selftest.run_lab_selftest(_context(engine, tmp_path, env), quick=True)
    assert "host profile" in _failed(report)["configuration"]


def test_production_reads_the_probe_lan_from_the_profile_only(
    engine: Engine, tmp_path: Path
) -> None:
    env = _production(tmp_path, "LAB_CELL_NETWORKS=10.231.0.0/16\nLAB_LLM_GATEWAY=\n")
    env["LAB_PROBE_LAN"] = LAN  # ignored in production
    report = selftest.run_lab_selftest(_context(engine, tmp_path, env), quick=True)
    assert "LAB_PROBE_LAN" in _failed(report)["configuration"]


def test_a_lan_address_that_does_not_answer_proves_nothing(engine: Engine, tmp_path: Path) -> None:
    profile = f"LAB_CELL_NETWORKS=10.231.0.0/16\nLAB_LLM_GATEWAY=\nLAB_PROBE_LAN={LAN}\n"
    env = _production(tmp_path, profile)
    report = selftest.run_lab_selftest(_context(engine, tmp_path, env, lan_ok=False), quick=True)
    assert "does not answer" in _failed(report)["configuration"]


@pytest.mark.parametrize(
    ("environ", "is_local", "expected"),
    [
        ({}, True, "development on Podman only"),  # production
        ({"LAB_ENGINE": "docker"}, True, "development on Podman only"),  # dev, Docker
        ({}, False, "not an address of this host"),  # dev, Podman, not local
    ],
)
def test_the_host_gateway_override_is_dev_podman_and_local_only(
    engine: Engine, tmp_path: Path, environ: dict[str, str], is_local: bool, expected: str
) -> None:
    if environ == {} and expected.startswith("development"):
        profile = f"LAB_CELL_NETWORKS=10.231.0.0/16\nLAB_LLM_GATEWAY=\nLAB_PROBE_LAN={LAN}\n"
        env = {**_production(tmp_path, profile), "LAB_PROBE_HOST_GATEWAY": "192.168.1.50"}
    else:
        env = _dev(LAB_PROBE_HOST_GATEWAY="192.168.1.50", **environ)
    context = _context(engine, tmp_path, env, is_local=lambda _a: is_local)
    report = selftest.run_lab_selftest(context, quick=True)
    assert expected in _failed(report)["configuration"]


def test_production_forces_the_trees_images_lock(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    env = {"LAB_IMAGES_LOCK": "/elsewhere.lock", "LAB_IMAGE_OVERRIDES": "lab-cell=evil:latest"}
    prod = selftest._cell_env(env, tree)
    assert prod["LAB_IMAGES_LOCK"] == str(tree / "deploy" / "images.lock")
    assert "LAB_IMAGE_OVERRIDES" not in prod
    dev = selftest._cell_env({**env, "LAB_DEV": "1"}, tree)
    assert dev["LAB_IMAGES_LOCK"] == "/elsewhere.lock" and dev["LAB_IMAGE_OVERRIDES"]


def test_the_release_tree_is_resolved_once(tmp_path: Path) -> None:
    release = tmp_path / "releases" / "v1"
    (release / "experiments").mkdir(parents=True)
    (release / "experiments" / "selftest.yaml").write_text("x")
    (tmp_path / "current").symlink_to(release)
    assert selftest._release_tree(tmp_path, {}) == release.resolve()


def test_the_host_profile_carries_the_probe_lan() -> None:
    ansible = REPO_ROOT / "deploy" / "ansible"
    template = (ansible / "templates" / "host.env.j2").read_text()
    assert "LAB_PROBE_LAN={{ lab_probe_lan | join(',') }}" in template
    group_vars = yaml.safe_load((ansible / "group_vars" / "all.yml").read_text())
    assert group_vars["lab_probe_lan"] == "{{ lab_upstream_dns }}"


# --------------------------------------------------------------------------- final fix pass


def test_the_control_must_score_outcome_true(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    """The scripted agent runs importPaste in both arms, so the control's Outcome is true
    too; a stored verdict alone (any outcome) would let a dead oracle pass."""
    backend = SelftestBackend(done=[(0, UNSUCCESSFUL)])
    report = run_selftest(_deps(engine, collector, tmp_path, backend), quick=True)
    failed = _failed(report)
    assert "outcome False" in failed["control: oracle"]
    assert "injected: oracle" in failed


def test_an_oracle_reporting_success_before_the_agent_fails_the_self_test(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = SelftestBackend(done=[(0, SUCCESS)])
    report = run_selftest(_deps(engine, collector, tmp_path, backend), quick=True)
    failed = _failed(report)
    assert "probe_failed" in failed["injected: valid"]
    assert "success before the agent" in failed["control: valid"]
    assert not any(c == "start_agent" for c, _ in backend.calls)


def test_after_a_breach_no_later_cell_starts_its_agent(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    """Quick mode probes only the first cell; once that one is not contained, the gate
    stays shut, so the second cell's agent never starts unprobed."""
    backend = SelftestBackend()
    probe_engine = ProbeEngine(reachable=lambda host, port: host == "1.1.1.1")
    report = run_selftest(_deps(engine, collector, tmp_path, backend, probe_engine), quick=True)
    assert report.critical and len(report.probes) == 1
    assert not any(c == "start_agent" for c, _ in backend.calls)
    assert {r["status"] for r in report.runs} == {"invalid"}
    unprobed = next(r for r in report.runs if r["run_id"] != report.probes[0].run_id)
    assert unprobed["reason"] == "cell_failed"


def test_the_gate_latches_after_any_cell_not_proven_contained() -> None:
    record = selftest.ProbeRecord("run_a", False, None, ("probe not run",))
    calls: list[str] = []

    class Inner:
        def start_agent(self, cell: Any) -> None:
            calls.append(cell.project.run_id)

    class Cell:
        def __init__(self, run_id: str) -> None:
            self.project = type("P", (), {"run_id": run_id})()

    gate = ContainmentGate(Inner(), lambda _cell: record, limit=1)  # type: ignore[arg-type]
    for run_id in ("run_a", "run_b", "run_c"):
        with pytest.raises(CellError):
            gate.start_agent(Cell(run_id))  # type: ignore[arg-type]
    assert calls == [] and len(gate.records) == 1


def test_stale_running_and_queued_selftest_runs_are_marked_abandoned_and_study_runs_never(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    def claimed(ef: Any, where: Path) -> tuple[str, list[str]]:
        """Register ``ef``, claim its first run; return it and the runs left queued."""
        runner = Runner(
            store=RunStore(engine),
            collector=collector,
            backend=SelftestBackend(),
            settings=CellSettings(images=IMAGES),
            lab_key=KEY,
            runs_dir=where / "runs",
            work_dir=where / "work",
        )
        schedule = runner.register(ef)
        run = RunStore(engine).claim_next(ef.experiment.experiment_id, schedule)
        assert run is not None
        queued = [r.run_id for r in schedule if r.run_id != run.run_id]
        assert queued
        return run.run_id, queued

    killed, never_run = claimed(derive_experiment(SELFTEST_YAML, quick=True), tmp_path / "k")
    study, study_queued = claimed(read_experiment(SELFTEST_YAML), tmp_path / "s")
    report = run_selftest(_deps(engine, collector, tmp_path / "b"), quick=True)
    assert report.passed, _failed(report)
    with session_scope(engine) as s:
        for run_id, was in [(killed, "running"), *((q, "queued") for q in never_run)]:
            old = s.get(t.Run, run_id)
            assert old is not None
            assert (old.status, old.invalid_reason) == (RunStatus.INVALID, InvalidReason.INTERNAL)
            assert old.invalid_detail is not None and old.finished_at is not None
            assert old.invalid_detail.startswith(f"abandoned: still {was}")
        other = s.get(t.Run, study)
        assert other is not None and other.status is RunStatus.RUNNING
        for run_id in study_queued:
            row = s.get(t.Run, run_id)
            assert row is not None and row.status is RunStatus.QUEUED
    swept = next(c for c in report.checks if c.name == "earlier self-tests swept")
    assert "1 abandoned running" in swept.detail
    assert f"{len(never_run)} abandoned queued" in swept.detail


def test_selftest_runs_are_left_out_of_the_in_flight_gauge(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    from control.api.metrics import _query

    ef = derive_experiment(SELFTEST_YAML, quick=True)
    runner = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=SelftestBackend(),
        settings=CellSettings(images=IMAGES),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
    )
    schedule = runner.register(ef)
    assert RunStore(engine).claim_next(ef.experiment.experiment_id, schedule) is not None
    in_flight = _query(engine).in_flight
    assert in_flight and all(count == 0 for _, count in in_flight)


def test_a_host_with_nonlocal_bind_checks_its_own_addresses() -> None:
    """With ip_nonlocal_bind=1 any address binds, so bind() would call a foreign gateway
    this host's; the address must then be one the host actually has."""
    own = {"10.0.0.5"}
    assert selftest.is_local_address(
        "10.0.0.5", nonlocal_bind=lambda _v: True, host_addresses=lambda: own
    )
    assert not selftest.is_local_address(
        "192.0.2.1", nonlocal_bind=lambda _v: True, host_addresses=lambda: own
    )
    assert not selftest.is_local_address(  # addresses unknown: nothing is proven
        "10.0.0.5", nonlocal_bind=lambda _v: True, host_addresses=lambda: None
    )
    assert selftest.is_local_address("127.0.0.1", nonlocal_bind=lambda _v: False)
    assert not selftest.is_local_address("192.0.2.1", nonlocal_bind=lambda _v: False)
    assert selftest._nonlocal_bind(4) in (True, False)  # reads this host's sysctl


def test_host_addresses_come_from_ip_json() -> None:
    doc = [
        {"ifname": "lo", "addr_info": [{"family": "inet", "local": "127.0.0.1"}]},
        {"ifname": "eth0", "addr_info": [{"family": "inet6", "local": "fe80::1"}]},
    ]

    def run(argv: Sequence[str], **_kw: Any) -> CommandResult:
        assert list(argv[1:]) == ["-j", "address", "show"]
        return CommandResult(tuple(argv), 0, json.dumps(doc).encode())

    def failed(argv: Sequence[str], **_kw: Any) -> CommandResult:
        return CommandResult(tuple(argv), 1, b"")

    assert selftest._host_addresses(run) == {"127.0.0.1", "fe80::1"}
    assert selftest._host_addresses(failed) is None


def _dns_responder(answer: bool) -> tuple[socket.socket, int]:
    """A UDP socket on 127.0.0.1 that answers one query (a DNS reply, or garbage)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve() -> None:
        with contextlib.suppress(OSError):
            data, peer = sock.recvfrom(4096)
            reply = DNSRecord.parse(data).reply().pack() if answer else b"garbage"
            sock.sendto(reply, peer)

    threading.Thread(target=serve, daemon=True).start()
    return sock, sock.getsockname()[1]


@pytest.mark.parametrize(("answer", "expected"), [(True, True), (False, False)])
def test_a_lan_resolver_that_answers_dns_answers(answer: bool, expected: bool) -> None:
    """The host firewall may let only DNS to the LAN resolver through: a DNS reply over
    UDP/53 proves the address answers (a non-DNS reply does not)."""
    sock, port = _dns_responder(answer)
    try:
        got = selftest.lan_answers(
            "127.0.0.1", timeout_s=1.0, tcp_ports=(), dns_port=port, use_ping=False
        )
        assert got is expected
    finally:
        sock.close()


def test_lan_answers_probes_every_containment_lan_port() -> None:
    default = inspect.signature(selftest.lan_answers).parameters["tcp_ports"].default
    assert default is containment.LAN_PORTS


def test_labctl_records_an_in_progress_marker_before_the_self_test(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A self-test killed mid-way leaves "aborted", never the previous pass, as its last
    run; the last success stays."""
    status = tmp_path / "state" / "selftest.json"
    monkeypatch.setenv("LAB_ROOT", str(tmp_path))
    monkeypatch.setenv("DATABASE_URL", "postgresql://lab:x@127.0.0.1:9/lab")
    monkeypatch.setattr(cli.selftest, "run_lab_selftest", lambda _c, *, quick: _report(True))
    assert cli.main(["selftest", "--quick"]) == 0
    seen: list[Any] = []

    def killed(_context: selftest.LabContext, *, quick: bool) -> SelftestReport:
        seen.append(read_selftest_status(status))
        raise SystemExit(143)  # SIGTERM, as labctl maps it

    monkeypatch.setattr(cli.selftest, "run_lab_selftest", killed)
    with pytest.raises(SystemExit):
        cli.main(["selftest", "--quick"])
    during = seen[0]
    assert during.last_run is not None and not during.last_run.passed
    assert "in progress" in during.last_run.summary
    after = read_selftest_status(status)
    assert after.last_run is not None and not after.last_run.passed
    assert "aborted" in after.last_run.summary
    assert after.last_success is not None and after.last_success.passed


def test_labctl_turns_sigterm_and_sighup_into_system_exit() -> None:
    previous = {s: signal.getsignal(s) for s in (signal.SIGTERM, signal.SIGHUP)}
    try:
        cli._exit_on_signals()
        for sig in (signal.SIGTERM, signal.SIGHUP):
            handler = signal.getsignal(sig)
            assert callable(handler)
            with pytest.raises(SystemExit) as err:
                handler(sig, None)
            assert err.value.code == 128 + sig
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
