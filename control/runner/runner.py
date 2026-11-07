"""The runner: one experiment's runs, each in a fresh cell, from claim to label.

:meth:`Runner.run_experiment` registers the experiment and its matched-pair schedule
(:class:`~control.runner.store.RunStore`), checks the whole stored schedule with
:func:`~control.runner.schedule.check_schedule` (``experiment=``, all attempts) and then
claims and runs queued runs one at a time. :meth:`Runner.run_one` walks a run through:

1. **claim** -- render the manifest with the lab key and verify every token
   (:func:`~control.runner.render.verify_manifest_tokens`) before anything sees it; post
   it to the Collector (before any event batch);
2. **provision** -- allocate subnets inside ``LAB_CELL_NETWORKS``, render the cell
   (:func:`~control.runner.cell_spec.render_cell`: fresh canaries, token-only catcher
   file, no lab key) and bring up its infrastructure (:class:`CellBackend`);
3. **probe** -- the target's own health script, then the injector's pre-flight probe:
   every probed path must answer its expected status (the P7 path its 404, robots.txt
   200). A failure stops here: the agent never starts, no token is spent;
4. **run** -- start the agent; poll the oracle (``/opt/support/done.sh`` only) every
   15 s while it runs, stop it at the run's ``timeout_s``, poll once more after;
5. **collect** -- stop the agent, then the infrastructure with SIGTERM (the tap drains
   in-flight calls), copy each producer's evidence out of its stopped container;
6. **teardown** -- remove the cell and everything labelled with the run;
7. **ship** -- the verdict (only if the oracle answered at least once), every stored
   event line verbatim, every artifact with its sha256;
8. **label** -- re-check the full schedule, load the evidence of the torn-down cell
   with the run's forbidden tags and the verdict, label the funnel, store the labels;
9. **classify** -- valid, or invalid with one :class:`~control.core.models.InvalidReason`.

Every failure maps to an invalid reason in exactly one place (:func:`_reason`); nothing
fails silently into a valid run. Heartbeats (``RunPhase``) are posted at each step. The
lab key is only ever an argument here; it never reaches a cell, a file or a log line.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from control.core.models import (
    Arm,
    EndStatus,
    FunnelLabel,
    InvalidReason,
    RunHeartbeat,
    RunManifest,
    RunPhase,
    RunStatus,
    Verdict,
)
from control.labeler.funnel import (
    ContaminationError,
    IncompleteEvidenceError,
    LabelingError,
    label_run,
    load_run_evidence,
)
from control.runner.cell_spec import (
    AGENT_SPECS,
    REPO_ROOT,
    AgentSpec,
    CellError,
    CellSettings,
    ComposeProject,
    allocate_subnets,
    render_cell,
)
from control.runner.compose_backend import CellBackend, CellHandle
from control.runner.experiment import ExperimentFile
from control.runner.oracle import DONE_COMMAND, POLL_INTERVAL_S, OracleLog, OracleScore, parse_done
from control.runner.render import forbidden_tags_for, render_manifest, verify_manifest_tokens
from control.runner.schedule import ScheduledRun, ScheduleError, build_schedule, check_schedule
from control.runner.ship import (
    CollectorClient,
    CollectorError,
    EvidenceError,
    read_event_lines,
    scan_artifacts,
)
from control.runner.store import (
    AgentRecord,
    RunCatalog,
    RunStore,
    TargetRecord,
    placement_map_sha256,
)

__all__ = [
    "PREFLIGHT_COMMAND",
    "RECORDING_FAILURE_MARKERS",
    "ProbeFailedError",
    "RunResult",
    "Runner",
    "catalog_for",
]

log = logging.getLogger(__name__)

PREFLIGHT_COMMAND: Final = ("python", "-m", "cell.injector.preflight", "--port", "80")
#: Log lines of cell components that mean evidence could not be recorded (the
#: component then withheld the response, so the agent's path changed: invalid run).
RECORDING_FAILURE_MARKERS: Final = {
    "injector": ("injector: cannot",),
    "tap": ("tap: cannot",),
    "cellguard": ("cell-guard: cannot record",),
}
HEALTH_TIMEOUT_S: Final = 300.0
STOP_TIMEOUT_S: Final = 15


class ProbeFailedError(RuntimeError):
    """The pre-flight probe failed: the cell is not the one the experiment describes."""


class _OracleUnexpectedError(RuntimeError):
    pass


class _OracleUnreachableError(RuntimeError):
    pass


class _RecordingFailedError(RuntimeError):
    pass


class _TeardownError(RuntimeError):
    pass


def _reason(exc: BaseException) -> InvalidReason:
    """The one place a failure becomes an invalid-run reason."""
    if isinstance(exc, ProbeFailedError):
        return InvalidReason.PROBE_FAILED
    if isinstance(exc, _OracleUnreachableError):
        return InvalidReason.ORACLE_UNREACHABLE
    if isinstance(exc, _OracleUnexpectedError):
        return InvalidReason.ORACLE_UNEXPECTED
    if isinstance(exc, _RecordingFailedError):
        return InvalidReason.RECORDING_FAILED
    if isinstance(exc, ContaminationError):
        return InvalidReason.CONTAMINATED
    if isinstance(exc, IncompleteEvidenceError | LabelingError | EvidenceError):
        return InvalidReason.EVIDENCE_INCOMPLETE
    if isinstance(exc, CollectorError):
        return InvalidReason.COLLECTOR_REJECTED
    if isinstance(exc, _TeardownError):
        return InvalidReason.TEARDOWN_FAILED
    if isinstance(exc, CellError):
        return InvalidReason.CELL_FAILED
    return InvalidReason.INTERNAL


@dataclass(frozen=True, slots=True)
class RunResult:
    run_id: str
    arm: Arm
    status: RunStatus
    reason: InvalidReason | None = None
    detail: str = ""
    end_status: EndStatus | None = None
    outcome: bool | None = None
    labels: tuple[FunnelLabel, ...] = ()


def catalog_for(
    ef: ExperimentFile,
    settings: CellSettings,
    *,
    templates_root: Path = REPO_ROOT,
    agent_specs: Mapping[str, AgentSpec] = AGENT_SPECS,
) -> RunCatalog:
    """The registry records of an experiment's builds on this host."""
    targets: dict[str, TargetRecord] = {}
    for target in ef.experiment.targets:
        cell_file = templates_root / "deploy" / "compose" / f"cell.{target.name}.yml"
        target_file = templates_root / "targets" / target.name / "compose.cell.yml"
        pack = hashlib.sha256(cell_file.read_bytes() + b"\0" + target_file.read_bytes())
        targets[target.name] = TargetRecord(
            image_digest=settings.image(f"goat-{target.name}"),
            content_pack_sha256=pack.hexdigest(),
            placement_map_sha256=placement_map_sha256(target.placements),
            oracle_grader="cvebench:outbound_service",
        )
    agents: dict[str, AgentRecord] = {}
    for agent in ef.experiment.agents:
        spec = agent_specs.get(agent)
        if spec is None:
            raise CellError(f"no agent spec for agent {agent!r}")
        agents[agent] = AgentRecord(
            adapter_version="1",
            framework_version=f"{agent}-1",
            image_digests={spec.image: settings.image(spec.image)},
        )
    return RunCatalog(targets=targets, agents=agents)


@dataclass(slots=True)
class _RunState:
    run: ScheduledRun
    evidence_dir: Path
    heartbeat_seq: int = 0
    manifest: RunManifest | None = None
    cell: CellHandle | None = None
    end_status: EndStatus | None = None
    score: OracleScore = field(default_factory=OracleScore)
    verdict: Verdict | None = None
    problems: list[BaseException] = field(default_factory=list)


class Runner:
    """Runs an experiment's queued runs one by one (``max_parallel_cells`` 1 in M0)."""

    def __init__(
        self,
        *,
        store: RunStore,
        collector: CollectorClient,
        backend: CellBackend,
        settings: CellSettings,
        lab_key: bytes,
        runs_dir: Path,
        work_dir: Path,
        oracle_interval_s: float = POLL_INTERVAL_S,
        tick_s: float = 1.0,
        health_timeout_s: float = HEALTH_TIMEOUT_S,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        agent_specs: Mapping[str, AgentSpec] = AGENT_SPECS,
        templates_root: Path = REPO_ROOT,
    ) -> None:
        if not lab_key:
            raise ValueError("lab_key must be non-empty")
        self._store = store
        self._collector = collector
        self._backend = backend
        self._settings = settings
        self._lab_key = lab_key
        self._runs_dir = runs_dir
        self._work_dir = work_dir
        self._oracle_interval_s = oracle_interval_s
        self._tick_s = tick_s
        self._health_timeout_s = health_timeout_s
        self._sleep = sleep
        self._clock = clock
        self._agent_specs = agent_specs
        self._templates_root = templates_root
        self._ef: ExperimentFile | None = None

    def __repr__(self) -> str:  # the key never appears in a repr or traceback local
        return f"Runner(runs_dir={self._runs_dir!s})"

    # experiment

    def register(self, ef: ExperimentFile) -> list[ScheduledRun]:
        """Register ``ef`` (idempotent) and return its stored, checked schedule."""
        catalog = catalog_for(
            ef, self._settings, templates_root=self._templates_root, agent_specs=self._agent_specs
        )
        schedule = self._store.register(ef, build_schedule(ef.experiment), catalog)
        check_schedule(schedule, experiment=ef.experiment)
        self._ef = ef
        return schedule

    def run_experiment(self, ef: ExperimentFile) -> list[RunResult]:
        """Register, then run every queued run of the experiment in schedule order."""
        schedule = self.register(ef)
        results: list[RunResult] = []
        while True:
            schedule = self._store.load_schedule(ef.experiment.experiment_id)
            check_schedule(schedule, experiment=ef.experiment)
            run = self._store.claim_next(ef.experiment.experiment_id, schedule)
            if run is None:
                return results
            results.append(self.run_one(run))

    # one run

    def run_one(self, run: ScheduledRun) -> RunResult:
        """Run a claimed run end to end; never raises for a run-level failure."""
        if self._ef is None:
            raise RuntimeError("register the experiment first")
        state = _RunState(run, self._runs_dir / run.run_id)
        labels: tuple[FunnelLabel, ...] = ()
        try:
            self._heartbeat(state, RunPhase.CLAIMED)
            self._prepare(state)
            try:
                self._provision_and_run(state)
            finally:
                self._collect_and_teardown(state)
            if state.problems:
                raise state.problems[0]
            self._ship(state)
            labels = self._label(state)
        except Exception as exc:  # every failure becomes an invalid run
            return self._finish_invalid(state, exc)
        self._store.finish(run.run_id, RunStatus.VALID)
        self._heartbeat(state, RunPhase.FINISHED, "valid", best_effort=True)
        return RunResult(
            run_id=run.run_id,
            arm=run.arm,
            status=RunStatus.VALID,
            end_status=state.end_status,
            outcome=state.verdict.outcome if state.verdict else None,
            labels=labels,
        )

    def _finish_invalid(self, state: _RunState, exc: BaseException) -> RunResult:
        reason = _reason(exc)
        detail = f"{type(exc).__name__}: {exc}"
        log.warning("run %s invalid (%s): %s", state.run.run_id, reason.value, detail)
        try:
            self._store.finish(state.run.run_id, RunStatus.INVALID, reason=reason, detail=detail)
        except Exception:
            log.exception("run %s: cannot record its invalid status", state.run.run_id)
        self._heartbeat(state, RunPhase.FINISHED, f"invalid: {reason.value}", best_effort=True)
        return RunResult(
            run_id=state.run.run_id,
            arm=state.run.arm,
            status=RunStatus.INVALID,
            reason=reason,
            detail=detail,
            end_status=state.end_status,
        )

    def _heartbeat(
        self, state: _RunState, phase: RunPhase, message: str = "", *, best_effort: bool = False
    ) -> None:
        heartbeat = RunHeartbeat(
            run_id=state.run.run_id,
            seq=state.heartbeat_seq,
            phase=phase,
            ts=datetime.now(UTC),
            message=message[:500],
        )
        state.heartbeat_seq += 1
        try:
            self._collector.post_status(heartbeat)
        except Exception:
            if not best_effort:
                raise
            log.exception("run %s: heartbeat %s not stored", state.run.run_id, phase.value)

    def _prepare(self, state: _RunState) -> None:
        assert self._ef is not None  # noqa: S101 - checked by run_one
        manifest = render_manifest(state.run, self._ef.experiment, self._lab_key)
        verify_manifest_tokens(manifest, self._lab_key)
        state.evidence_dir.mkdir(parents=True, exist_ok=False)
        (state.evidence_dir.parent / f"{state.run.run_id}.manifest.json").write_bytes(
            manifest.model_dump_json().encode()
        )
        self._collector.post_manifest(manifest)
        state.manifest = manifest

    def _provision_and_run(self, state: _RunState) -> None:
        assert self._ef is not None and state.manifest is not None  # noqa: S101
        experiment = self._ef.experiment
        self._heartbeat(state, RunPhase.CELL_STARTING)
        subnets = allocate_subnets(self._settings.cell_networks, self._backend.subnets_in_use())
        project = render_cell(
            state.run,
            state.manifest,
            experiment=experiment,
            settings=self._settings,
            subnets=subnets,
            agent_spec=self._agent_specs.get(state.run.agent),
            templates_root=self._templates_root,
        )
        state.cell = self._backend.up(project, self._work_dir)

        self._heartbeat(state, RunPhase.PROBING)
        self._probe(state.cell, project)

        self._heartbeat(state, RunPhase.AGENT_RUNNING)
        oracle_log = OracleLog(state.run.run_id, state.evidence_dir)
        self._backend.start_agent(state.cell)
        started = self._clock()
        next_poll = started
        timeout_s = float(experiment.limits.timeout_s)
        while True:
            now = self._clock()
            if now >= next_poll:
                self._poll(state, oracle_log)
                next_poll = now + self._oracle_interval_s
            agent = self._backend.agent_state(state.cell)
            if not agent.running:
                state.end_status = (
                    EndStatus.COMPLETED if agent.exit_code == 0 else EndStatus.CRASHED
                )
                break
            if now - started >= timeout_s:
                self._backend.kill_agent(state.cell)
                state.end_status = EndStatus.TIMEOUT
                break
            self._sleep(self._tick_s)
        self._poll(state, oracle_log)  # the final word, after the agent stopped

    def _probe(self, cell: CellHandle, project: ComposeProject) -> None:
        if not self._backend.health(cell, timeout_s=self._health_timeout_s):
            raise ProbeFailedError("the target never became healthy")
        paths = [path for path, _ in project.probe_paths]
        result = self._backend.exec(
            cell, project.injector_service, [*PREFLIGHT_COMMAND, *paths], timeout_s=120
        )
        try:
            doc = json.loads(result.text.strip().splitlines()[-1])
            got = {r["path"]: r.get("status") for r in doc["results"]}
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise ProbeFailedError(
                f"pre-flight probe gave no result: {result.text[-300:]!r}"
            ) from exc
        wrong = {
            path: (expected, got.get(path))
            for path, expected in project.probe_paths
            if got.get(path) != expected
        }
        if wrong:
            raise ProbeFailedError(f"pre-flight statuses (expected, got): {wrong}")

    def _poll(self, state: _RunState, oracle_log: OracleLog) -> None:
        assert state.cell is not None  # noqa: S101
        result = self._backend.exec(
            state.cell, state.cell.project.target_service, DONE_COMMAND, timeout_s=120
        )
        parsed = parse_done(
            result.returncode, result.text, result.stderr.decode("utf-8", "replace")
        )
        oracle_log.record(parsed)
        state.score.add(parsed)

    def _collect_and_teardown(self, state: _RunState) -> None:
        cell = state.cell
        if cell is None:
            return
        self._heartbeat(state, RunPhase.COLLECTING, best_effort=True)
        project = cell.project
        try:
            if self._backend.agent_state(cell).running:
                self._backend.kill_agent(cell)
            self._backend.stop(cell, [project.agent_service], timeout_s=STOP_TIMEOUT_S)
            self._backend.stop(cell, list(project.infra_services), timeout_s=STOP_TIMEOUT_S)
            for service, markers in RECORDING_FAILURE_MARKERS.items():
                if service in project.document["services"]:
                    text = self._backend.logs(cell, service)
                    hit = [m for m in markers if m in text]
                    if hit:
                        state.problems.append(
                            _RecordingFailedError(f"{service} could not record evidence")
                        )
            report = self._backend.collect(cell, state.evidence_dir)
            if report.refused:
                state.problems.append(
                    EvidenceError(f"evidence refused at collection: {report.refused[:10]}")
                )
        except Exception as exc:
            state.problems.append(exc)
        finally:
            self._heartbeat(state, RunPhase.TEARDOWN, best_effort=True)
            try:
                self._backend.teardown(cell)
            except Exception as exc:
                state.problems.append(_TeardownError(str(exc)))

    def _ship(self, state: _RunState) -> None:
        run = state.run
        self._heartbeat(state, RunPhase.SHIPPING)
        if state.score.unexpected:
            raise _OracleUnexpectedError(f"unexpected oracle success: {state.score.unexpected}")
        if not state.score.decided:
            raise _OracleUnreachableError(f"none of {state.score.polls} oracle polls answered")
        if state.end_status is None:  # pragma: no cover - set whenever the agent ran
            raise RuntimeError("the agent's end status is unknown")
        state.verdict = Verdict(
            run_id=run.run_id,
            end_status=state.end_status,
            outcome=state.score.success,
            oracle_message=state.score.message,
            decided_at=datetime.now(UTC),
        )
        self._collector.post_verdict(state.verdict)
        skipped: list[str] = []
        lines = read_event_lines(state.evidence_dir, run.run_id, skipped)
        self._collector.post_events(run.run_id, lines)
        self._collector.post_artifacts(run.run_id, scan_artifacts(state.evidence_dir))

    def _label(self, state: _RunState) -> tuple[FunnelLabel, ...]:
        assert self._ef is not None and state.manifest is not None  # noqa: S101
        schedule = self._store.load_schedule(self._ef.experiment.experiment_id)
        try:
            check_schedule(schedule, experiment=self._ef.experiment)
        except ScheduleError as exc:
            raise LabelingError(f"schedule check before labelling: {exc}") from exc
        evidence = load_run_evidence(
            state.evidence_dir,
            state.manifest,
            forbidden_tags=forbidden_tags_for(state.run, schedule),
            verdict=state.verdict,
        )
        labels = tuple(label_run(evidence))
        self._store.record_labels(list(labels))
        return labels


def results_summary(results: Sequence[RunResult]) -> dict[str, int]:
    """Counts by status (for logs and the self-test)."""
    summary: dict[str, int] = {}
    for result in results:
        summary[result.status.value] = summary.get(result.status.value, 0) + 1
    return summary
