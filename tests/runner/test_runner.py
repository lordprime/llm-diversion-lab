"""The runner end to end against a fake cell backend, real Postgres and the Collector.

The fake backend plays a cell: it answers the health check, the pre-flight probe and
``done.sh`` from a script, and "collects" evidence written from the run's own rendered
inputs (manifest, payload texts), the way the injector, tap, catcher and agent would.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
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
    FunnelStage,
    InvalidReason,
    LlmCall,
    PlacementServe,
    RunManifest,
    RunStatus,
    TargetAccessEvent,
)
from control.db import tables as t
from control.db.engine import session_scope
from control.db.repo import invalid_runs_by_reason
from control.runner import runner as runner_module
from control.runner.cell_spec import CellError, CellSettings, ComposeProject
from control.runner.compose_backend import CellHandle, CollectReport, CommandResult, ContainerState
from control.runner.experiment import read_experiment
from control.runner.oracle import OUTBOUND_SUCCESS, PREVIOUSLY_SUCCESSFUL, OracleScore, parse_done
from control.runner.runner import Runner, RunResult
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


def write_cell_evidence(project: ComposeProject, dest: Path, *, leak: str | None = None) -> None:
    """What a cell running the scripted agent leaves behind, for its own manifest."""
    manifest = RunManifest.model_validate_json(_file(project, "cfg_injector", "manifest.json"))
    payloads: dict[str, str] = json.loads(_file(project, "cfg_injector", "payloads.json"))
    run_id, tag = manifest.run_id, manifest.tag
    access: list[Any] = []
    seq = 0
    for path, status in project.probe_paths:  # the pre-flight probe
        access.append(
            TargetAccessEvent(
                run_id=run_id,
                stream="injector",
                seq=seq,
                ts=TS,
                flow_id=f"p{seq}",
                method="GET",
                url=f"http://goat:9090{path}",
                status=status,
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
    logs_text: dict[str, str] = field(default_factory=dict)
    refuse: list[str] = field(default_factory=list)
    teardown_error: str | None = None
    up_error: str | None = None
    leak: Callable[[ComposeProject], str | None] = lambda _p: None
    calls: list[tuple[str, str]] = field(default_factory=list)
    projects: list[ComposeProject] = field(default_factory=list)

    def subnets_in_use(self) -> list[ipaddress.IPv4Network]:
        return [ipaddress.IPv4Network("10.231.0.0/27")]

    def up(self, project: ComposeProject, workdir: Path) -> CellHandle:
        self.calls.append(("up", project.run_id))
        if self.up_error:
            raise CellError(self.up_error)
        self.projects.append(project)
        workdir.mkdir(parents=True, exist_ok=True)
        compose = workdir / f"{project.name}.yml"
        compose.write_text(project.to_yaml())
        return CellHandle(project, compose)

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

    def agent_state(self, cell: CellHandle) -> ContainerState:
        states = getattr(self, "_states", [ContainerState("missing")])
        return states.pop(0) if len(states) > 1 else states[0]

    def kill_agent(self, cell: CellHandle) -> None:
        self.calls.append(("kill_agent", cell.project.run_id))
        self._states = [ContainerState("exited", 137)]

    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None:
        self.calls.append(("stop", ",".join(services)))

    def logs(self, cell: CellHandle, service: str) -> str:
        return self.logs_text.get(service, "")

    def collect(self, cell: CellHandle, dest: Path) -> CollectReport:
        self.calls.append(("collect", cell.project.run_id))
        write_cell_evidence(cell.project, dest, leak=self.leak(cell.project))
        return CollectReport(files=["..."], refused=list(self.refuse))

    def teardown(self, cell: CellHandle) -> None:
        self.calls.append(("teardown", cell.project.run_id))
        if self.teardown_error:
            raise CellError(self.teardown_error)


# --------------------------------------------------------------------------- fixtures


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
        assert mine == ["up", "health", "start_agent", "collect", "teardown"]
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
        (FakeBackend(teardown_error="containers left"), InvalidReason.TEARDOWN_FAILED),
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
