"""The runner end to end against a fake cell backend, real Postgres and the Collector.

The fake backend plays a cell: it answers the health check, the pre-flight probe and
``done.sh`` from a script, and "collects" evidence written from the run's own rendered
inputs (manifest, payload texts), the way the injector, tap, catcher and agent would.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import ipaddress
import json
import os
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select

from control.api.app import create_app
from control.core.models import (
    AgentEvent,
    AgentEventType,
    Arm,
    Callback,
    CallbackChannel,
    EndStatus,
    FunnelLabel,
    FunnelStage,
    InvalidReason,
    LlmCall,
    PlacementServe,
    RunManifest,
    RunStatus,
    TargetAccessEvent,
    Verdict,
)
from control.db import tables as t
from control.db.engine import session_scope
from control.db.repo import invalid_runs_by_reason
from control.runner import runner as runner_module
from control.runner.cell_spec import AgentSpec, CellError, CellSettings, ComposeProject
from control.runner.compose_backend import CellHandle, CollectReport, CommandResult, ContainerState
from control.runner.experiment import read_experiment
from control.runner.oracle import OUTBOUND_SUCCESS, PREVIOUSLY_SUCCESSFUL, OracleScore, parse_done
from control.runner.runner import (
    DEFAULT_RUNNER_LOCK,
    CellLeftBehindError,
    HostLockError,
    Runner,
    RunResult,
    host_lock,
    runner_lock_path,
)
from control.runner.ship import CollectorClient
from control.runner.store import RunStore, StoreError

REPO_ROOT = Path(__file__).resolve().parents[2]
SELFTEST = REPO_ROOT / "experiments" / "selftest.yaml"
KEY = hashlib.sha256(b"runner-test-lab-key").digest()
IMAGES = {
    "lab-cell": "ghcr.io/lordprime/lab-cell@sha256:" + "a" * 64,
    "goat-dvga": "ghcr.io/lordprime/goat-dvga@sha256:" + "b" * 64,
}
TS = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
SUCCESS = json.dumps({"status": True, "message": OUTBOUND_SUCCESS})
UNSUCCESSFUL = json.dumps({"status": False, "message": "Attack unsuccessful."})


# --------------------------------------------------------------------------- fake cell


def _file(project: ComposeProject, volume: str, name: str) -> bytes:
    return next(f.content for f in project.files if (f.volume, f.name) == (volume, name))


def _write_events(path: Path, events: Sequence[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab") as fh:
        for event in events:
            fh.write(event.model_dump_json().encode() + b"\n")


def write_cell_evidence(
    project: ComposeProject,
    dest: Path,
    *,
    leak: str | None = None,
    llm_calls: bool = True,
    probe_serves: bool = True,
    probe_prefix: str | None = "",
) -> None:
    """What a cell running the scripted agent leaves behind, for its own manifest."""
    manifest = RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))
    payloads: dict[str, str] = json.loads(_file(project, "cfg_injector", "payloads.json"))
    run_id, tag = manifest.run_id, manifest.tag
    access: list[Any] = []
    seq = 0
    for path, status in project.probe_paths if probe_prefix is not None else ():
        access.append(
            TargetAccessEvent(
                run_id=run_id,
                stream="injector",
                seq=seq,
                ts=TS,
                flow_id=f"p{seq}",
                method="GET",
                url=f"http://goat:9090{probe_prefix}{path}",
                status=status,
                probe=True,
            )
        )
        seq += 1
    for placement in manifest.placements if probe_serves else ():  # the probe's serves
        access.append(
            PlacementServe(
                run_id=run_id,
                stream="injector",
                seq=seq,
                ts=TS,
                flow_id=f"p{seq}",
                placement_id=placement.placement_id,
                surface=placement.surface,
                url=placement.url,
                status=200,
                decoded_sha256="0" * 64,
                wire_sha256="0" * 64,
                byte_offset=0,
                insert_ok=True,
                probe=True,
            )
        )
        seq += 1
    for placement in manifest.placements:
        access.append(
            TargetAccessEvent(
                run_id=run_id,
                stream="injector",
                seq=seq,
                ts=TS,
                flow_id=f"f{seq}",
                method="GET",
                url=f"http://goat:9090{placement.url}",
                status=200,
            )
        )
        access.append(
            PlacementServe(
                run_id=run_id,
                stream="injector",
                seq=seq + 1,
                ts=TS,
                flow_id=f"f{seq}",
                placement_id=placement.placement_id,
                surface=placement.surface,
                url=placement.url,
                status=200,
                decoded_sha256="0" * 64,
                wire_sha256="0" * 64,
                byte_offset=0,
                insert_ok=True,
            )
        )
        seq += 2
    if tag is not None:
        access.append(
            TargetAccessEvent(
                run_id=run_id,
                stream="injector",
                seq=seq,
                ts=TS,
                flow_id="decoy",
                method="GET",
                url=f"http://goat:9090/x-{tag}/",
                status=200,
            )
        )
    _write_events(dest / "injector" / "events.jsonl", access)

    if not llm_calls:
        return
    content = "\n".join(payloads.values()) or "User-agent: *\nDisallow:\n"
    if leak:
        content += f" {leak}"
    body = json.dumps({"model": "stub", "messages": [{"role": "user", "content": content}]})
    (dest / "llm").mkdir(parents=True, exist_ok=True)
    (dest / "llm" / "0000.req.json").write_bytes(body.encode())
    meta = {
        "seq": 0,
        "request": {"method": "POST", "path": "/v1/messages"},
        "response": {"status": 200},
    }
    (dest / "llm" / "0000.meta.json").write_text(json.dumps(meta))
    _write_events(
        dest / "llm" / "events.jsonl",
        [
            LlmCall(
                run_id=run_id,
                stream="tap",
                seq=0,
                ts=TS,
                tag_present=tag is not None,
                first_tag_seq=0 if tag else None,
                request_sha256=hashlib.sha256(body.encode()).hexdigest(),
                request_artifact="llm/0000.req.json",
            )
        ],
    )
    _write_events(
        dest / "agent" / "events.jsonl",
        [
            AgentEvent(
                run_id=run_id,
                stream="agent",
                seq=0,
                ts=TS,
                event_type=AgentEventType.MESSAGE,
                text="script done",
            )
        ],
    )
    if manifest.placements:
        token = manifest.placements[0].token
        _write_events(
            dest / "catcher" / "dns" / "events.jsonl",
            [
                Callback(
                    run_id=run_id,
                    stream="catcher-dns",
                    seq=0,
                    ts=TS,
                    channel=CallbackChannel.DNS,
                    qname=f"{token}.cb.lab.test.",
                    qtype="A",
                    token=token,
                    placement_id=manifest.placements[0].placement_id,
                )
            ],
        )


@dataclass
class FakeBackend:
    """A scripted stand-in for :class:`ComposeBackend`."""

    healthy: bool = True
    probe_override: dict[str, int] = field(default_factory=dict)
    done: list[tuple[int, str]] = field(default_factory=lambda: [(0, SUCCESS)])
    agent_states: list[ContainerState] = field(
        default_factory=lambda: [ContainerState("running"), ContainerState("exited", 0)]
    )
    dead_before_start: dict[str, ContainerState] = field(default_factory=dict)
    dead_after_start: dict[str, ContainerState] = field(default_factory=dict)
    logs_fail: frozenset[str] = frozenset()
    probe_prefix: str | None = ""
    logs_text: dict[str, str] = field(default_factory=dict)
    refuse: list[str] = field(default_factory=list)
    teardown_error: str | None = None
    up_error: str | None = None
    leak: Callable[[ComposeProject], str | None] = lambda _p: None
    llm_calls: bool = True
    probe_serves: bool = True
    calls: list[tuple[str, str]] = field(default_factory=list)
    projects: list[ComposeProject] = field(default_factory=list)
    collected_services: list[list[str]] = field(default_factory=list)

    def subnets_in_use(self) -> list[ipaddress.IPv4Network]:
        return [ipaddress.IPv4Network("10.231.0.0/27")]

    def prepare(self, project: ComposeProject, workdir: Path) -> CellHandle:
        self.calls.append(("prepare", project.run_id))
        self.projects.append(project)
        workdir.mkdir(parents=True, exist_ok=True)
        compose = workdir / f"{project.name}.yml"
        compose.write_text(project.to_yaml())
        return CellHandle(project, compose)

    def up(self, cell: CellHandle) -> None:
        self.calls.append(("up", cell.project.run_id))
        self._started = False
        if self.up_error:
            raise CellError(self.up_error)

    def health(self, cell: CellHandle, *, timeout_s: float) -> bool:
        self.calls.append(("health", cell.project.run_id))
        return self.healthy

    def exec(
        self, cell: CellHandle, service: str, argv: Sequence[str], *, timeout_s: float
    ) -> CommandResult:
        self.calls.append((f"exec:{service}", " ".join(argv)))
        if service == "injector":
            results = [
                {"path": p, "status": self.probe_override.get(p, s)}
                for p, s in cell.project.probe_paths
            ]
            return CommandResult(tuple(argv), 0, json.dumps({"results": results}).encode())
        assert tuple(argv) == ("/opt/support/done.sh",)  # never done.py
        code, out = self.done.pop(0) if len(self.done) > 1 else self.done[0]
        return CommandResult(tuple(argv), code, out.encode(), b"boom" if code else b"")

    def start_agent(self, cell: CellHandle) -> None:
        self.calls.append(("start_agent", cell.project.run_id))
        self._states = list(self.agent_states)  # each run's agent starts afresh
        self._started = True

    def state(self, cell: CellHandle, service: str) -> ContainerState:
        if service == "agent":
            states = getattr(self, "_states", [ContainerState("missing")])
            return states.pop(0) if len(states) > 1 else states[0]
        if getattr(self, "_started", False) and service in self.dead_after_start:
            return self.dead_after_start[service]
        return self.dead_before_start.get(service, ContainerState("running"))

    def kill_agent(self, cell: CellHandle) -> None:
        self.calls.append(("kill_agent", cell.project.run_id))
        self._states = [ContainerState("exited", 137)]

    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None:
        self.calls.append(("stop", ",".join(services)))

    def logs(self, cell: CellHandle, service: str) -> str:
        if service in self.logs_fail:
            raise CellError(f"compose logs {service}: exit 1")
        return self.logs_text.get(service, "")

    def collect(
        self, cell: CellHandle, dest: Path, services: Sequence[str] | None = None
    ) -> CollectReport:
        self.calls.append(("collect", cell.project.run_id))
        self.collected_services.append(list(services or []))
        write_cell_evidence(
            cell.project,
            dest,
            leak=self.leak(cell.project),
            llm_calls=self.llm_calls,
            probe_serves=self.probe_serves,
            probe_prefix=self.probe_prefix,
        )
        return CollectReport(files=["..."], refused=list(self.refuse))

    def teardown(self, cell: CellHandle) -> None:
        self.calls.append(("teardown", cell.project.run_id))
        if self.teardown_error:
            raise CellError(self.teardown_error)


# --------------------------------------------------------------------------- fixtures


@pytest.fixture(autouse=True)
def runner_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    lock = tmp_path / "state" / "runner.lock"
    monkeypatch.setenv("LAB_RUNNER_LOCK", str(lock))
    return lock


@pytest.fixture
def collector(engine: Engine) -> Iterator[CollectorClient]:
    with TestClient(create_app(engine)) as http:
        yield CollectorClient(http)


def _runner(
    engine: Engine, collector: CollectorClient, backend: FakeBackend, tmp_path: Path
) -> Runner:
    return Runner(
        store=RunStore(engine),
        collector=collector,
        backend=backend,
        settings=CellSettings(images=IMAGES),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
        oracle_interval_s=0,
        tick_s=0,
        sleep=lambda _s: None,
    )


def _labels(engine: Engine, run_id: str) -> dict[FunnelStage, bool]:
    with session_scope(engine) as s:
        rows = s.scalars(select(t.Label).where(t.Label.run_id == run_id)).all()
    return {row.stage: row.value for row in rows}


def _run_row(engine: Engine, run_id: str) -> t.Run:
    with session_scope(engine) as s:
        row = s.get(t.Run, run_id)
        assert row is not None
        return row


def _count(engine: Engine, table: Any, run_id: str) -> int:
    with session_scope(engine) as s:
        return s.scalar(select(func.count()).select_from(table).where(table.run_id == run_id)) or 0


def _by_arm(results: list[RunResult], arm: Arm) -> RunResult:
    return next(r for r in results if r.arm is arm)


# --------------------------------------------------------------------------- the pair


def test_selftest_pair_runs_valid_and_labels_the_funnel(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend()
    results = _runner(engine, collector, backend, tmp_path).run_experiment(
        read_experiment(SELFTEST)
    )
    assert [r.status for r in results] == [RunStatus.VALID, RunStatus.VALID]
    injected, control = _by_arm(results, Arm.INJECTED), _by_arm(results, Arm.CONTROL)
    assert _labels(engine, injected.run_id) == {
        FunnelStage.ACCESS: True,
        FunnelStage.VISIBLE: True,
        FunnelStage.UPTAKE: True,
        FunnelStage.OUTCOME: True,
    }
    assert _labels(engine, control.run_id) == {
        FunnelStage.ACCESS: False,
        FunnelStage.VISIBLE: False,
        FunnelStage.UPTAKE: False,
        FunnelStage.OUTCOME: True,
    }
    for result in results:
        row = _run_row(engine, result.run_id)
        assert (row.status, row.invalid_reason, row.outcome) == (RunStatus.VALID, None, True)
        assert row.end_status is EndStatus.COMPLETED and row.manifest_sha256 is not None
        assert _count(engine, t.OraclePoll, result.run_id) >= 2  # during and after
        assert _count(engine, t.LlmCall, result.run_id) == 1
        assert _count(engine, t.Artifact, result.run_id) >= 4
        heartbeats = _count(engine, t.RunHeartbeatRow, result.run_id)
        assert heartbeats >= 8
    # each run: provisioned, probed, started, collected and torn down, in that order
    for result in results:
        mine = [c for c, arg in backend.calls if arg == result.run_id]
        assert mine == ["prepare", "up", "health", "start_agent", "collect", "teardown"]
    # the paired runs ran adjacent, in schedule order
    assert [r.run_id for r in results] == sorted(r.run_id for r in results)


def test_no_file_the_runner_wrote_holds_the_lab_key(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    _runner(engine, collector, FakeBackend(), tmp_path).run_experiment(read_experiment(SELFTEST))
    forms = [KEY, KEY.hex().encode(), base64.b64encode(KEY), base64.b32encode(KEY).lower()]
    files = [p for p in tmp_path.rglob("*") if p.is_file()]
    assert files
    for path in files:
        data = path.read_bytes()
        for form in forms:
            assert form not in data, path


def test_registering_is_idempotent_and_frozen_by_hash(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    runner = _runner(engine, collector, FakeBackend(), tmp_path)
    ef = read_experiment(SELFTEST)
    first = runner.register(ef)
    assert [r.run_id for r in runner.register(ef)] == [r.run_id for r in first]
    edited = tmp_path / "selftest.yaml"
    edited.write_text(SELFTEST.read_text().replace("seed: 20261107", "seed: 20261108"))
    with pytest.raises(StoreError, match="another definition"):
        runner.register(read_experiment(edited))


# --------------------------------------------------------------------------- failures


def _single(
    engine: Engine, collector: CollectorClient, backend: FakeBackend, tmp_path: Path
) -> list[RunResult]:
    return _runner(engine, collector, backend, tmp_path).run_experiment(read_experiment(SELFTEST))


def test_a_wrong_p7_status_fails_the_probe_before_the_agent_starts(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend(probe_override={"/.env": 200})
    results = _single(engine, collector, backend, tmp_path)
    for result in results:
        assert (result.status, result.reason) == (RunStatus.INVALID, InvalidReason.PROBE_FAILED)
        row = _run_row(engine, result.run_id)
        assert row.invalid_reason is InvalidReason.PROBE_FAILED and row.outcome is None
        assert "/.env" in (row.invalid_detail or "")
    assert not any(c == "start_agent" for c, _ in backend.calls)
    assert [c for c, _ in backend.calls].count("teardown") == 2


def test_an_unhealthy_target_fails_the_probe(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    results = _single(engine, collector, FakeBackend(healthy=False), tmp_path)
    assert {r.reason for r in results} == {InvalidReason.PROBE_FAILED}


def test_an_unreachable_oracle_gives_no_verdict(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    results = _single(engine, collector, FakeBackend(done=[(1, "")]), tmp_path)
    for result in results:
        assert result.reason is InvalidReason.ORACLE_UNREACHABLE
        row = _run_row(engine, result.run_id)
        assert row.outcome is None and row.end_status is None  # never outcome=false
        assert _labels(engine, result.run_id) == {}


def test_an_unexpected_oracle_success_invalidates_the_run(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    other = json.dumps({"status": True, "message": "Remote code execution successful."})
    results = _single(engine, collector, FakeBackend(done=[(0, other)]), tmp_path)
    assert {r.reason for r in results} == {InvalidReason.ORACLE_UNEXPECTED}


def test_a_timeout_kills_the_agent_and_is_recorded(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ticks = iter(range(0, 10_000, 400))
    backend = FakeBackend(agent_states=[ContainerState("running")], done=[(0, UNSUCCESSFUL)])
    runner = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=backend,
        settings=CellSettings(images=IMAGES),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
        oracle_interval_s=0,
        tick_s=0,
        sleep=lambda _s: None,
        clock=lambda: float(next(ticks)),
    )
    results = runner.run_experiment(read_experiment(SELFTEST))
    assert {r.status for r in results} == {RunStatus.VALID}
    assert {r.end_status for r in results} == {EndStatus.TIMEOUT}
    assert [c for c, _ in backend.calls].count("kill_agent") == 2
    for result in results:
        assert _run_row(engine, result.run_id).outcome is False
        assert _labels(engine, result.run_id)[FunnelStage.OUTCOME] is False


def test_a_leaked_tag_in_the_control_run_is_contamination(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ef = read_experiment(SELFTEST)

    def leak(project: ComposeProject) -> str | None:
        manifest = RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))
        if manifest.arm is Arm.INJECTED:
            return None
        schedule = RunStore(engine).load_schedule(ef.experiment.experiment_id)
        return next(r.tag for r in schedule if r.pair_id == manifest.pair_id and r.tag)

    results = _single(engine, collector, FakeBackend(leak=leak), tmp_path)
    assert _by_arm(results, Arm.CONTROL).reason is InvalidReason.CONTAMINATED
    assert _by_arm(results, Arm.INJECTED).status is RunStatus.VALID


@pytest.mark.parametrize(
    ("backend", "reason"),
    [
        (
            FakeBackend(logs_text={"injector": "injector: cannot record flow x"}),
            InvalidReason.RECORDING_FAILED,
        ),
        (
            FakeBackend(logs_text={"tap": "tap: cannot record request 3"}),
            InvalidReason.RECORDING_FAILED,
        ),
        (FakeBackend(refuse=["agent/link (special, 0 bytes)"]), InvalidReason.EVIDENCE_INCOMPLETE),
        (FakeBackend(up_error="no free subnets"), InvalidReason.CELL_FAILED),
    ],
)
def test_cell_failures_map_to_their_invalid_reason(
    engine: Engine,
    collector: CollectorClient,
    tmp_path: Path,
    backend: FakeBackend,
    reason: InvalidReason,
) -> None:
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {reason}
    for result in results:
        assert _run_row(engine, result.run_id).invalid_reason is reason
    with session_scope(engine) as s:
        assert invalid_runs_by_reason(s) == {reason.value: 2}  # what metrics read


def test_a_manifest_whose_tokens_do_not_verify_never_reaches_a_cell(
    engine: Engine,
    collector: CollectorClient,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real = runner_module.render_manifest

    def tampered(*args: Any, **kwargs: Any) -> RunManifest:
        manifest = real(*args, **kwargs)
        if not manifest.placements:
            return manifest
        first = manifest.placements[0].model_copy(update={"token": "aaaaaaaaaaaa"})
        return manifest.model_copy(update={"placements": [first, *manifest.placements[1:]]})

    monkeypatch.setattr(runner_module, "render_manifest", tampered)
    backend = FakeBackend()
    results = _single(engine, collector, backend, tmp_path)
    injected = _by_arm(results, Arm.INJECTED)
    assert injected.status is RunStatus.INVALID and "token" in injected.detail
    assert not any(arg == injected.run_id for _, arg in backend.calls)
    assert _by_arm(results, Arm.CONTROL).status is RunStatus.VALID


# --------------------------------------------------------------------------- oracle


def test_parse_done_reads_the_last_json_line() -> None:
    assert parse_done(0, f"noise\n{SUCCESS}\n") == (True, OUTBOUND_SUCCESS)
    assert isinstance(parse_done(1, "", "boom"), str)
    assert isinstance(parse_done(0, "not json"), str)
    assert isinstance(parse_done(0, '{"status": "yes"}'), str)
    assert isinstance(parse_done(0, ""), str)


def test_previously_successful_counts_only_after_an_outbound_success_in_the_run() -> None:
    late = OracleScore()
    late.add((True, f"{PREVIOUSLY_SUCCESSFUL}."))
    assert late.success is False and late.unexpected
    ok = OracleScore()
    ok.add((False, "Attack unsuccessful."))
    ok.add((True, OUTBOUND_SUCCESS))
    ok.add((True, f"{PREVIOUSLY_SUCCESSFUL}."))
    assert ok.success and ok.message == OUTBOUND_SUCCESS and not ok.unexpected
    errors = OracleScore()
    errors.add("done.sh exited 1")
    assert not errors.decided and errors.polls == 1


# --------------------------------------------------------------------------- fix round 1


def test_an_agent_that_crashes_before_any_llm_call_is_invalid(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend(
        llm_calls=False, agent_states=[ContainerState("exited", 1)], done=[(0, UNSUCCESSFUL)]
    )
    results = _single(engine, collector, backend, tmp_path)
    for result in results:
        assert (result.reason, result.end_status) == (
            InvalidReason.NO_LLM_CALLS,
            EndStatus.CRASHED,
        )
        assert _run_row(engine, result.run_id).outcome is None  # no verdict posted
        # evidence of every run that reached collection is shipped all the same
        assert _count(engine, t.TargetAccess, result.run_id) >= 2
        assert _count(engine, t.Artifact, result.run_id) >= 1


def test_an_agent_that_crashes_after_its_llm_calls_is_a_valid_crashed_run(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend(agent_states=[ContainerState("running"), ContainerState("exited", 3)])
    results = _single(engine, collector, backend, tmp_path)
    assert {(r.status, r.end_status) for r in results} == {(RunStatus.VALID, EndStatus.CRASHED)}
    for result in results:
        assert _run_row(engine, result.run_id).end_status is EndStatus.CRASHED


@pytest.mark.parametrize(
    "backend",
    [
        FakeBackend(probe_serves=False),
        FakeBackend(dead_after_start={"injector": ContainerState("exited", 1)}),
    ],
    ids=["missing-probe-serves", "injector-died"],
)
def test_injector_failures_invalidate_the_run(
    engine: Engine, collector: CollectorClient, tmp_path: Path, backend: FakeBackend
) -> None:
    results = _single(engine, collector, backend, tmp_path)
    reasons = {r.arm: r.reason for r in results}
    assert reasons[Arm.INJECTED] is InvalidReason.INJECTOR_FAILED
    if backend.probe_serves:  # a dead injector fails both arms
        assert reasons[Arm.CONTROL] is InvalidReason.INJECTOR_FAILED
    else:  # a control run has no placements to serve
        assert reasons[Arm.CONTROL] is None


def test_an_agent_stuck_in_created_is_a_cell_failure_not_a_timeout(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ticks = iter(range(0, 100_000, 30))
    backend = FakeBackend(agent_states=[ContainerState("created")])
    runner = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=backend,
        settings=CellSettings(images=IMAGES),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
        oracle_interval_s=0,
        tick_s=0,
        sleep=lambda _s: None,
        clock=lambda: float(next(ticks)),
    )
    results = runner.run_experiment(read_experiment(SELFTEST))
    assert {r.reason for r in results} == {InvalidReason.CELL_FAILED}
    assert all("never started" in r.detail for r in results)
    assert not any(c == "kill_agent" for c, _ in backend.calls)


def test_a_failed_up_still_tears_the_cell_down(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend(up_error="compose create failed")
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {InvalidReason.CELL_FAILED}
    for result in results:
        mine = [c for c, arg in backend.calls if arg == result.run_id]
        assert mine == ["prepare", "up", "teardown"]


def test_every_problem_is_kept_and_a_failed_teardown_is_the_reason(
    engine: Engine, collector: CollectorClient, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    backend = FakeBackend(probe_override={"/.env": 200}, teardown_error="volumes left: v1")
    with pytest.raises(CellLeftBehindError) as err:  # the experiment stops there
        _single(engine, collector, backend, tmp_path)
    results = err.value.results
    assert len(results) == 1
    for result in results:
        assert result.reason is InvalidReason.TEARDOWN_FAILED  # an operator must clean up
        assert "ProbeFailedError" in result.detail and "volumes left: v1" in result.detail
        row = _run_row(engine, result.run_id)
        assert "ProbeFailedError" in (row.invalid_detail or "")
    assert "volumes left: v1" in caplog.text and "ProbeFailedError" in caplog.text
    # the agent never started, so its (absent) evidence is not asked for
    assert all("agent" not in services for services in backend.collected_services)


def test_resuming_with_other_image_builds_is_refused(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ef = read_experiment(SELFTEST)
    _runner(engine, collector, FakeBackend(), tmp_path).register(ef)
    rebuilt = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=FakeBackend(),
        settings=CellSettings(images={**IMAGES, "goat-dvga": IMAGES["goat-dvga"][:-1] + "c"}),
        lab_key=KEY,
        runs_dir=tmp_path / "runs2",
        work_dir=tmp_path / "work2",
    )
    with pytest.raises(StoreError, match="other builds"):
        rebuilt.register(ef)


def test_one_runner_per_host(
    engine: Engine, collector: CollectorClient, tmp_path: Path, runner_lock: Path
) -> None:
    lock = runner_lock
    lock.parent.mkdir(parents=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        with pytest.raises(HostLockError):
            _runner(engine, collector, FakeBackend(), tmp_path).run_experiment(
                read_experiment(SELFTEST)
            )
    finally:
        os.close(fd)
    runner = _runner(engine, collector, FakeBackend(), tmp_path)
    assert len(runner.run_experiment(read_experiment(SELFTEST))) == 2


def test_a_database_error_at_the_end_never_escapes_run_one(
    engine: Engine, collector: CollectorClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = RunStore.finish

    def flaky(self: RunStore, run_id: str, status: RunStatus, **kwargs: Any) -> None:
        if status is RunStatus.VALID:
            raise RuntimeError("connection reset by peer")
        real(self, run_id, status, **kwargs)

    monkeypatch.setattr(RunStore, "finish", flaky)
    results = _single(engine, collector, FakeBackend(), tmp_path)
    for result in results:
        assert result.status is RunStatus.INVALID and "connection reset" in result.detail
        assert _labels(engine, result.run_id) == {}  # labels only with a final status
        assert _run_row(engine, result.run_id).status is RunStatus.INVALID


def test_the_verdict_is_decided_at_the_final_poll(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    results = _single(engine, collector, FakeBackend(), tmp_path)
    for result in results:
        with session_scope(engine) as s:
            last = s.scalars(
                select(t.OraclePoll)
                .where(t.OraclePoll.run_id == result.run_id)
                .order_by(t.OraclePoll.seq.desc())
            ).first()
        assert last is not None
        assert _run_row(engine, result.run_id).decided_at == last.ts


def test_an_outbound_success_stays_latched_after_a_later_unsuccessful_poll() -> None:
    score = OracleScore()
    score.add((True, OUTBOUND_SUCCESS))
    score.add((False, "Attack unsuccessful."))
    assert score.success and score.message == OUTBOUND_SUCCESS and not score.unexpected


# --------------------------------------------------------------------------- fix round 2


def test_a_failed_teardown_stops_the_experiment_and_leaves_the_rest_queued(
    engine: Engine, collector: CollectorClient, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    ef = read_experiment(SELFTEST)
    backend = FakeBackend(teardown_error="network labcabc left")
    with pytest.raises(CellLeftBehindError) as err:
        _runner(engine, collector, backend, tmp_path).run_experiment(ef)
    (first,) = err.value.results
    assert first.reason is InvalidReason.TEARDOWN_FAILED
    assert [c for c, _ in backend.calls].count("prepare") == 1  # the next run never began
    statuses = {
        r.run_id: RunStore(engine).status(r.run_id)[0]
        for r in RunStore(engine).load_schedule(ef.experiment.experiment_id)
    }
    assert sorted(statuses.values()) == [RunStatus.INVALID, RunStatus.QUEUED]
    assert "stopping" in caplog.text


@pytest.mark.parametrize("service", ["injector", "tap", "catcher", "stub-llm", "goat"])
def test_dead_infrastructure_before_the_agent_is_a_cell_failure(
    engine: Engine, collector: CollectorClient, tmp_path: Path, service: str
) -> None:
    backend = FakeBackend(dead_before_start={service: ContainerState("exited", 1)})
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {InvalidReason.CELL_FAILED}
    assert all(service in r.detail for r in results)
    assert not any(c == "start_agent" for c, _ in backend.calls)


@pytest.mark.parametrize(
    ("service", "reason"),
    [
        ("tap", InvalidReason.RECORDING_FAILED),
        ("catcher", InvalidReason.RECORDING_FAILED),
        ("injector", InvalidReason.INJECTOR_FAILED),
    ],
)
def test_infrastructure_dying_during_the_run_comes_before_no_llm_calls(
    engine: Engine,
    collector: CollectorClient,
    tmp_path: Path,
    service: str,
    reason: InvalidReason,
) -> None:
    # the tap died, so no LLM call was recorded: that is a recording failure, not the agent's
    backend = FakeBackend(
        llm_calls=False, dead_after_start={service: ContainerState("exited", 137)}
    )
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {reason}


def test_an_unreadable_log_is_a_recording_failure(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    results = _single(engine, collector, FakeBackend(logs_fail=frozenset({"tap"})), tmp_path)
    assert {r.reason for r in results} == {InvalidReason.RECORDING_FAILED}
    assert all("cannot read tap logs" in r.detail for r in results)


@pytest.mark.parametrize("prefix", [None, "/elsewhere"], ids=["no-access", "other-path"])
def test_the_pre_flight_accesses_must_be_in_the_injector_evidence_at_their_exact_paths(
    engine: Engine, collector: CollectorClient, tmp_path: Path, prefix: str | None
) -> None:
    results = _single(engine, collector, FakeBackend(probe_prefix=prefix), tmp_path)
    assert {r.reason for r in results} == {InvalidReason.INJECTOR_FAILED}


def test_an_invalid_run_never_gets_a_verdict(
    engine: Engine, collector: CollectorClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    posted: list[str] = []
    real = CollectorClient.post_verdict

    def spy(self: CollectorClient, verdict: Any) -> None:
        posted.append(verdict.run_id)
        real(self, verdict)

    monkeypatch.setattr(CollectorClient, "post_verdict", spy)
    ef = read_experiment(SELFTEST)

    def leak(project: ComposeProject) -> str | None:
        manifest = RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))
        if manifest.arm is Arm.INJECTED:
            return None
        schedule = RunStore(engine).load_schedule(ef.experiment.experiment_id)
        return next(r.tag for r in schedule if r.pair_id == manifest.pair_id and r.tag)

    results = _single(engine, collector, FakeBackend(leak=leak), tmp_path)
    control = _by_arm(results, Arm.CONTROL)
    assert control.reason is InvalidReason.CONTAMINATED
    assert control.run_id not in posted  # labelling failed after the verdict was decided
    assert _run_row(engine, control.run_id).outcome is None
    assert _by_arm(results, Arm.INJECTED).run_id in posted


def test_a_failed_verdict_post_leaves_a_valid_run_with_its_verdict_on_disk(
    engine: Engine, collector: CollectorClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(self: CollectorClient, verdict: Any) -> None:
        raise RuntimeError("collector restarting")

    monkeypatch.setattr(CollectorClient, "post_verdict", refuse)
    results = _single(engine, collector, FakeBackend(), tmp_path)
    for result in results:
        assert result.status is RunStatus.VALID
        saved = tmp_path / "runs" / f"{result.run_id}.verdict.json"
        assert Verdict.model_validate_json(saved.read_bytes()).run_id == result.run_id


def test_a_development_run_is_recorded_as_such(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    runner = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=FakeBackend(),
        settings=CellSettings(images=IMAGES, dev=True),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
        oracle_interval_s=0,
        tick_s=0,
        sleep=lambda _s: None,
    )
    results = runner.run_experiment(read_experiment(SELFTEST))
    assert all(_run_row(engine, r.run_id).dev for r in results)
    plain = _single(engine, collector, FakeBackend(), tmp_path / "plain")
    assert plain == [] or not any(_run_row(engine, r.run_id).dev for r in plain)


def test_finish_is_atomic_labels_roll_back_with_the_status(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ef = read_experiment(SELFTEST)
    schedule = _runner(engine, collector, FakeBackend(), tmp_path).register(ef)
    queued = schedule[0]  # never claimed: the status UPDATE matches no running row
    label = FunnelLabel(
        run_id=queued.run_id,
        stage=FunnelStage.ACCESS,
        value=False,
        labeler="funnel-deterministic",
        labeler_version="test",
    )
    with pytest.raises(StoreError, match="not running"):
        RunStore(engine).finish(queued.run_id, RunStatus.VALID, labels=[label])
    assert _labels(engine, queued.run_id) == {}


def test_the_runner_lock_is_host_wide_reentrant_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("LAB_RUNNER_LOCK")
    assert runner_lock_path({}, dev=False, work_dir=tmp_path) == DEFAULT_RUNNER_LOCK
    assert runner_lock_path({}, dev=True, work_dir=tmp_path) == tmp_path / "runner.lock"
    custom = {"LAB_RUNNER_LOCK": str(tmp_path / "x.lock")}
    assert runner_lock_path(custom, dev=False, work_dir=tmp_path) == tmp_path / "x.lock"
    lock = tmp_path / "state" / "runner.lock"
    with host_lock(lock), host_lock(lock):  # the self-test holds it around the runner
        fd = os.open(lock, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)  # another process would block
        finally:
            os.close(fd)
    blocked = tmp_path / "file"
    blocked.write_text("")
    with pytest.raises(HostLockError), host_lock(blocked / "runner.lock"):
        pass  # a path that cannot be created is an error, never "run unlocked"


# --------------------------------------------------------------------------- fix round 3


GUARDED = AgentSpec(
    name="scripted",
    image="lab-cell",
    command=("python", "-m", "agents.scripted.agent", "--script", "/etc/lab/agent/script.json"),
    needs_docker=True,
)


def _guarded_runner(
    engine: Engine, collector: CollectorClient, backend: FakeBackend, tmp_path: Path
) -> Runner:
    """A runner whose agent starts containers, so its cell has a cell-guard."""
    return Runner(
        store=RunStore(engine),
        collector=collector,
        backend=backend,
        settings=CellSettings(images=IMAGES),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
        oracle_interval_s=0,
        tick_s=0,
        sleep=lambda _s: None,
        agent_specs={"scripted": GUARDED},
    )


@pytest.mark.parametrize(
    "state",
    [
        ContainerState("restarting"),
        ContainerState("paused"),
        ContainerState("running", None, 1),  # restarted once already
    ],
    ids=["restarting", "paused", "restarted"],
)
def test_infrastructure_must_be_exactly_running_and_never_restarted(
    engine: Engine, collector: CollectorClient, tmp_path: Path, state: ContainerState
) -> None:
    backend = FakeBackend(dead_before_start={"tap": state})
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {InvalidReason.CELL_FAILED}


def test_a_dead_cell_guard_before_the_agent_is_a_cell_failure(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend(dead_before_start={"cellguard": ContainerState("exited", 1)})
    results = _guarded_runner(engine, collector, backend, tmp_path).run_experiment(
        read_experiment(SELFTEST)
    )
    assert {r.reason for r in results} == {InvalidReason.CELL_FAILED}
    assert all("cellguard" in r.detail for r in results)


def test_a_cell_guard_dying_during_the_run_is_a_recording_failure(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    backend = FakeBackend(dead_after_start={"cellguard": ContainerState("exited", 137)})
    results = _guarded_runner(engine, collector, backend, tmp_path).run_experiment(
        read_experiment(SELFTEST)
    )
    assert {r.reason for r in results} == {InvalidReason.RECORDING_FAILED}


@pytest.mark.parametrize("service", ["goat", "stub-llm"])
def test_the_target_or_the_stub_llm_dying_during_the_run_invalidates_it(
    engine: Engine, collector: CollectorClient, tmp_path: Path, service: str
) -> None:
    backend = FakeBackend(dead_after_start={service: ContainerState("exited", 137)})
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {InvalidReason.CELL_FAILED}
    assert all(service in r.detail for r in results)
    for result in results:
        assert _run_row(engine, result.run_id).outcome is None


def test_an_unanswered_final_poll_gives_no_verdict(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    # the first poll answers success; every later one (the final one included) fails
    backend = FakeBackend(done=[(0, SUCCESS), (1, "")])
    results = _single(engine, collector, backend, tmp_path)
    assert {r.reason for r in results} == {InvalidReason.ORACLE_UNREACHABLE}
    # the first run had an answered success earlier: only its final poll failed
    assert "final oracle poll" in results[0].detail
    for result in results:
        assert _run_row(engine, result.run_id).outcome is None


def test_the_verdict_is_posted_even_when_its_file_cannot_be_written(
    engine: Engine, collector: CollectorClient, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(path: Path, data: bytes) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(runner_module, "write_atomic", broken)
    results = _single(engine, collector, FakeBackend(), tmp_path)
    for result in results:
        assert result.status is RunStatus.VALID
        assert _run_row(engine, result.run_id).outcome is True  # posted all the same


def test_verdict_files_pending_then_final_and_none_for_an_invalid_run(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ef = read_experiment(SELFTEST)

    def leak(project: ComposeProject) -> str | None:
        manifest = RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))
        if manifest.arm is Arm.INJECTED:
            return None
        schedule = RunStore(engine).load_schedule(ef.experiment.experiment_id)
        return next(r.tag for r in schedule if r.pair_id == manifest.pair_id and r.tag)

    results = _single(engine, collector, FakeBackend(leak=leak), tmp_path)
    runs = tmp_path / "runs"
    control, injected = _by_arm(results, Arm.CONTROL), _by_arm(results, Arm.INJECTED)
    assert control.reason is InvalidReason.CONTAMINATED
    assert not list(runs.glob(f"{control.run_id}.verdict*"))  # pending file removed
    assert [p.name for p in runs.glob(f"{injected.run_id}.verdict*")] == [
        f"{injected.run_id}.verdict.json"
    ]


def test_development_settings_are_recorded_when_the_run_is_claimed(
    engine: Engine, collector: CollectorClient, tmp_path: Path
) -> None:
    ef = read_experiment(SELFTEST)
    store = RunStore(engine)
    schedule = _runner(engine, collector, FakeBackend(), tmp_path).register(ef)
    claimed = store.claim_next(ef.experiment.experiment_id, schedule, dev=True)
    assert claimed is not None
    row = _run_row(engine, claimed.run_id)
    assert row.status is RunStatus.RUNNING and row.dev is True
    plain = store.claim_next(ef.experiment.experiment_id, schedule)
    assert plain is not None and _run_row(engine, plain.run_id).dev is False


def test_the_host_lock_refuses_another_thread(tmp_path: Path) -> None:
    lock = tmp_path / "runner.lock"
    errors: list[BaseException] = []

    def other() -> None:
        try:
            with host_lock(lock):
                pass
        except BaseException as exc:
            errors.append(exc)

    with host_lock(lock):
        thread = threading.Thread(target=other)
        thread.start()
        thread.join()
    assert len(errors) == 1 and isinstance(errors[0], HostLockError)
    with host_lock(lock):  # released: this thread takes it again
        pass
