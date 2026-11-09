"""The runner: one experiment's runs, each in a fresh cell, from claim to label.

:meth:`Runner.run_experiment` takes the host-wide lock (:func:`host_lock`, default
:data:`DEFAULT_RUNNER_LOCK`; the self-test takes the same one), registers the
experiment and its matched-pair schedule (:class:`~control.runner.store.RunStore`; a
resumed queue must have the same definition hash and the same image builds), checks
the whole stored schedule with :func:`~control.runner.schedule.check_schedule`
(``experiment=``, all attempts) and then claims and runs queued runs one at a time. If
a run's teardown fails it stops (:class:`CellLeftBehindError`), leaving the rest
queued: a leaked cell may still hold a Docker socket, an agent or a gateway route.
:meth:`Runner.run_one` walks a run through:

1. **claim** -- render the manifest with the lab key and verify every token
   (:func:`~control.runner.render.verify_manifest_tokens`) before anything sees it; post
   it to the Collector (before any event batch);
2. **provision** -- allocate subnets inside ``LAB_CELL_NETWORKS``, render the cell
   (:func:`~control.runner.cell_spec.render_cell`: fresh canaries, token-only catcher
   file, no lab key), keep its handle, then bring up its infrastructure;
3. **probe** -- the target's own health script, then the injector's pre-flight probe:
   every probed path must answer its expected status (the P7 path its 404, robots.txt
   200); then every infrastructure service must be exactly ``running``, never
   restarted. A failure stops here: the
   agent never starts, no token is spent;
4. **run** -- start the agent; poll the oracle (``/opt/support/done.sh`` only) every
   15 s while it runs, stop it at the run's ``timeout_s``, poll once more after. An
   agent that never leaves ``created`` is a cell failure, not a timeout;
5. **collect** -- note which infrastructure is no longer exactly ``running`` with no
   restart (the injector: ``injector_failed``; the tap, catcher or cell-guard:
   ``recording_failed``, as are an unreadable log or a recording-failure line in one;
   the target or the stub LLM: ``cell_failed``), stop the agent, then the
   infrastructure with SIGTERM (the tap drains in-flight calls), copy each producer's
   evidence out of its stopped container;
6. **teardown** -- always, once the handle exists (a failed provision included):
   remove the cell and everything labelled with the run, verified by listing again;
7. **ship evidence** -- for every run that reached collection, valid or not: every
   stored event line verbatim and every artifact with its sha256 (no verdict);
8. **decide** -- the run is invalid if anything above failed, if the injector's events
   lack the pre-flight probe's accesses and serves (``injector_failed``), if the oracle
   never answered, did not answer the final poll after the agent, or reported an
   unexpected success, or if the agent made no LLM call at all (``no_llm_calls``,
   DEVELOPMENT_PLAN 5.4). The verdict is built here (``decided_at`` = the final,
   answered poll) and kept as ``<run>.verdict.pending.json`` (atomic), not posted;
9. **label** -- re-check the full schedule, load the evidence of the torn-down cell
   with the run's forbidden tags and the verdict, label the funnel; the labels and the
   final status (and whether the host ran development settings) are stored in one
   transaction (``dev`` is already set when the run is claimed). Only a run finished
   valid renames its pending verdict to ``<run>.verdict.json`` and then, separately,
   posts it, so an invalid run never has one (its pending file is deleted); a failed
   post leaves it valid with the verdict file to re-send.

Every failure maps to an invalid reason in exactly one place (:func:`_reason`); all of
a run's problems are logged and kept in ``invalid_detail``, and a failed teardown (an
operator must clean up) is the reason whenever it happened. :meth:`run_one` never
raises for a run-level failure, a database error included. The lab key is only ever
an argument here; it never reaches a cell, a file or a log line. Retrying an invalid
run (a new attempt), a SIGTERM handler, a start-up sweep of orphaned ``lab.run_id``
resources and a reaper for runs stuck ``running`` are not done here (15b-2 / final).
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

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
    "AGENT_START_GRACE_S",
    "DEFAULT_RUNNER_LOCK",
    "PREFLIGHT_COMMAND",
    "RECORDING_FAILURE_MARKERS",
    "RECORDING_SERVICES",
    "CellLeftBehindError",
    "HostLockError",
    "ProbeFailedError",
    "RunResult",
    "Runner",
    "catalog_for",
    "host_lock",
    "runner_lock_path",
]

log = logging.getLogger(__name__)

PREFLIGHT_COMMAND: Final = ("python", "-m", "cell.injector.preflight", "--port", "80")
#: Log lines of cell components that mean evidence could not be recorded (the
#: component then withheld the response, so the agent's path changed: invalid run).
#: mitmdump runs with ``flow_detail=0``, so no agent-chosen text is logged per flow.
#: Infrastructure whose death during a run means its evidence is incomplete.
RECORDING_SERVICES: Final = frozenset({"tap", "catcher", "cellguard"})
RECORDING_FAILURE_MARKERS: Final = {
    "injector": ("injector: cannot",),
    "tap": ("tap: cannot",),
    "cellguard": ("cell-guard: cannot record",),
}
HEALTH_TIMEOUT_S: Final = 300.0
STOP_TIMEOUT_S: Final = 15
#: How long an agent container may stay ``created`` before the cell counts as failed.
AGENT_START_GRACE_S: Final = 60.0


class ProbeFailedError(RuntimeError):
    """The pre-flight probe failed: the cell is not the one the experiment describes."""


class HostLockError(RuntimeError):
    """Another runner holds this host's runner lock (or it could not be taken)."""


class CellLeftBehindError(RuntimeError):
    """A run's teardown failed: :meth:`Runner.run_experiment` stopped, the rest is queued.

    ``results`` holds the results of the runs that ran (the last one's ``detail`` says
    what was left). An operator must clean up before the experiment is resumed.
    """

    def __init__(self, results: Sequence[RunResult]) -> None:
        self.results = list(results)
        last = self.results[-1]
        super().__init__(f"run {last.run_id}: teardown failed, experiment stopped: {last.detail}")


class _OracleUnexpectedError(RuntimeError):
    pass


class _OracleUnreachableError(RuntimeError):
    pass


class _RecordingFailedError(RuntimeError):
    pass


class _InjectorFailedError(RuntimeError):
    pass


class _NoLlmCallsError(RuntimeError):
    pass


class _TeardownError(RuntimeError):
    pass


class _RunFailed(RuntimeError):
    """Several problems of one run, in the order they happened."""

    def __init__(self, problems: Sequence[BaseException]) -> None:
        self.problems = tuple(problems)
        super().__init__("; ".join(_describe(p) for p in self.problems))


def _describe(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


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
    if isinstance(exc, _InjectorFailedError):
        return InvalidReason.INJECTOR_FAILED
    if isinstance(exc, _NoLlmCallsError):
        return InvalidReason.NO_LLM_CALLS
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


#: The host-wide runner lock; the self-test takes the same one.
DEFAULT_RUNNER_LOCK: Final = Path("/srv/lab/state/runner.lock")
#: held locks of this process: path -> (pid, thread ident, depth)
_held: dict[Path, tuple[int, int, int]] = {}
_held_guard = threading.Lock()


def runner_lock_path(env: Mapping[str, str], *, dev: bool, work_dir: Path) -> Path:
    """``LAB_RUNNER_LOCK``, else :data:`DEFAULT_RUNNER_LOCK` (``work_dir`` only with dev)."""
    if env.get("LAB_RUNNER_LOCK"):
        return Path(env["LAB_RUNNER_LOCK"])
    return work_dir / "runner.lock" if dev else DEFAULT_RUNNER_LOCK


@contextlib.contextmanager
def host_lock(path: Path) -> Iterator[None]:
    """Hold the host-wide runner lock (exclusive, non-blocking ``flock`` on ``path``).

    One runner (or self-test) per host: cell subnets are allocated first-free. The lock
    is re-entrant for the thread that holds it, so a self-test holding it can call
    :meth:`Runner.run_experiment`. It is meant for a single-threaded process and is not
    fork-safe: another thread of the holder's process is refused, and a forked child
    (whose inherited ``flock`` is the parent's) takes it like any other process, which
    fails while the parent holds it. Any failure to take it is a :class:`HostLockError`.
    """
    key = path.resolve()
    me = (os.getpid(), threading.get_ident())
    with _held_guard:
        holder = _held.get(key)
        if holder is not None and holder[0] == me[0]:
            if holder[1] != me[1]:
                raise HostLockError(f"{path} is held by another thread of this process")
            _held[key] = (*me, holder[2] + 1)
            reentered = True
        else:
            reentered = False
    if reentered:
        try:
            yield
        finally:
            with _held_guard:
                pid, ident, depth = _held[key]
                _held[key] = (pid, ident, depth - 1)
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as exc:
        raise HostLockError(f"cannot open the runner lock {path}: {exc}") from exc
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise HostLockError(f"another runner holds {path}") from exc
        except OSError as exc:  # ENOLCK and friends: never run unlocked
            raise HostLockError(f"cannot lock {path}: {exc}") from exc
        with _held_guard:
            _held[key] = (*me, 1)
        try:
            yield
        finally:
            with _held_guard:
                _held.pop(key, None)
    finally:
        os.close(fd)  # closing releases the lock


def write_atomic(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically: a temporary file, fsync, rename."""
    tmp = path.with_name(f".{path.name}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


@dataclass(slots=True)
class _RunState:
    run: ScheduledRun
    evidence_dir: Path
    heartbeat_seq: int = 0
    manifest: RunManifest | None = None
    cell: CellHandle | None = None
    up_done: bool = False
    agent_started: bool = False
    collected: bool = False
    event_lines: list[bytes] = field(default_factory=list)
    end_status: EndStatus | None = None
    score: OracleScore = field(default_factory=OracleScore)
    final_poll_at: datetime | None = None
    final_poll_answered: bool = False
    verdict: Verdict | None = None
    problems: list[BaseException] = field(default_factory=list)


class Runner:
    """Runs an experiment's queued runs one by one (one runner per host, by lock)."""

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
        lock_path: Path | None = None,
        oracle_interval_s: float = POLL_INTERVAL_S,
        tick_s: float = 1.0,
        health_timeout_s: float = HEALTH_TIMEOUT_S,
        agent_start_grace_s: float = AGENT_START_GRACE_S,
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
        self._lock_path = lock_path or runner_lock_path(
            os.environ, dev=settings.dev, work_dir=work_dir
        )
        self._oracle_interval_s = oracle_interval_s
        self._tick_s = tick_s
        self._health_timeout_s = health_timeout_s
        self._agent_start_grace_s = agent_start_grace_s
        self._sleep = sleep
        self._clock = clock
        self._agent_specs = agent_specs
        self._templates_root = templates_root
        self._ef: ExperimentFile | None = None

    def __repr__(self) -> str:  # the key never appears in a repr or traceback local
        return f"Runner(runs_dir={self._runs_dir!s})"

    # experiment

    def register(self, ef: ExperimentFile) -> list[ScheduledRun]:
        """Register ``ef`` (idempotent; refuses another hash or other builds)."""
        catalog = catalog_for(
            ef, self._settings, templates_root=self._templates_root, agent_specs=self._agent_specs
        )
        schedule = self._store.register(ef, build_schedule(ef.experiment), catalog)
        check_schedule(schedule, experiment=ef.experiment)
        self._ef = ef
        return schedule

    def run_experiment(self, ef: ExperimentFile) -> list[RunResult]:
        """Register, then run every queued run of the experiment in schedule order."""
        with host_lock(self._lock_path):
            self.register(ef)
            results: list[RunResult] = []
            while True:
                schedule = self._store.load_schedule(ef.experiment.experiment_id)
                check_schedule(schedule, experiment=ef.experiment)
                run = self._store.claim_next(
                    ef.experiment.experiment_id, schedule, dev=self._settings.dev
                )
                if run is None:
                    return results
                result = self.run_one(run)
                results.append(result)
                if result.reason is InvalidReason.TEARDOWN_FAILED:
                    log.error(
                        "run %s left cell resources behind; stopping, the remaining runs "
                        "stay queued until an operator has cleaned up: %s",
                        result.run_id,
                        result.detail,
                    )
                    raise CellLeftBehindError(results)

    # one run

    def run_one(self, run: ScheduledRun) -> RunResult:
        """Run a claimed run end to end; never raises for a run-level failure."""
        if self._ef is None:
            raise RuntimeError("register the experiment first")
        state = _RunState(run, self._runs_dir / run.run_id)
        try:
            self._heartbeat(state, RunPhase.CLAIMED)
            self._prepare(state)
            try:
                self._provision_and_run(state)
            except Exception as exc:
                state.problems.insert(0, exc)
            finally:
                self._collect_and_teardown(state)
            if state.collected:
                try:
                    self._ship_evidence(state)
                except Exception as exc:
                    state.problems.append(exc)
            if state.problems:
                raise _RunFailed(state.problems)
            self._decide(state)
            labels = self._label(state)
            self._store.finish(run.run_id, RunStatus.VALID, labels=labels, dev=self._settings.dev)
        except Exception as exc:  # every failure, a database error included
            return self._finish_invalid(state, exc)
        self._post_verdict(state)
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
        self._verdict_path(state, pending=True).unlink(missing_ok=True)  # never a verdict
        problems = exc.problems if isinstance(exc, _RunFailed) else (exc,)
        teardown = [p for p in problems if isinstance(p, _TeardownError)]
        reason = InvalidReason.TEARDOWN_FAILED if teardown else _reason(problems[0])
        detail = "; ".join(_describe(p) for p in problems)
        for problem in problems:
            log.warning("run %s problem: %s", state.run.run_id, _describe(problem))
        log.warning("run %s invalid (%s)", state.run.run_id, reason.value)
        try:
            self._store.finish(
                state.run.run_id,
                RunStatus.INVALID,
                reason=reason,
                detail=detail,
                dev=self._settings.dev,
            )
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

    def _experiment_file(self) -> ExperimentFile:
        if self._ef is None:  # pragma: no cover - run_one checks it first
            raise RuntimeError("register the experiment first")
        return self._ef

    def _prepare(self, state: _RunState) -> None:
        experiment = self._experiment_file().experiment
        manifest = render_manifest(state.run, experiment, self._lab_key)
        verify_manifest_tokens(manifest, self._lab_key)
        state.evidence_dir.mkdir(parents=True, exist_ok=False)
        (state.evidence_dir.parent / f"{state.run.run_id}.manifest.json").write_bytes(
            manifest.model_dump_json().encode()
        )
        self._collector.post_manifest(manifest)
        state.manifest = manifest

    def _provision_and_run(self, state: _RunState) -> None:
        experiment = self._experiment_file().experiment
        if state.manifest is None:  # pragma: no cover - set by _prepare
            raise RuntimeError("no manifest")
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
        state.cell = self._backend.prepare(project, self._work_dir)  # teardown from here on
        self._backend.up(state.cell)
        state.up_done = True

        self._heartbeat(state, RunPhase.PROBING)
        self._probe(state.cell, project)

        not_running: dict[str, str] = {}
        for service in project.infra_services:
            status = self._backend.state(state.cell, service)
            if not status.alive:
                not_running[service] = status.status
        if not_running:
            raise CellError(f"infrastructure not running before the agent: {not_running}")

        self._heartbeat(state, RunPhase.AGENT_RUNNING)
        oracle_log = OracleLog(state.run.run_id, state.evidence_dir)
        self._backend.start_agent(state.cell)
        state.agent_started = True
        started = self._clock()
        next_poll = started
        timeout_s = float(experiment.limits.timeout_s)
        agent = project.agent_service
        while True:
            now = self._clock()
            if now >= next_poll:
                self._poll(state, oracle_log)
                next_poll = now + self._oracle_interval_s
            status = self._backend.state(state.cell, agent)
            if status.ended:
                code = status.exit_code
                state.end_status = EndStatus.COMPLETED if code == 0 else EndStatus.CRASHED
                break
            if status.pending:
                if now - started >= self._agent_start_grace_s:
                    raise CellError(f"the agent container never started ({status.status})")
            elif not status.running:
                raise CellError(f"the agent container is {status.status}")
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
        if state.cell is None:  # pragma: no cover - polled only in a cell
            raise RuntimeError("no cell")
        result = self._backend.exec(
            state.cell, state.cell.project.target_service, DONE_COMMAND, timeout_s=120
        )
        parsed = parse_done(
            result.returncode, result.text, result.stderr.decode("utf-8", "replace")
        )
        poll = oracle_log.record(parsed)
        state.final_poll_at = poll.ts
        state.final_poll_answered = not isinstance(parsed, str)
        state.score.add(parsed)

    def _collect_and_teardown(self, state: _RunState) -> None:
        cell = state.cell
        if cell is None:
            return
        project = cell.project
        try:
            if state.up_done:
                self._heartbeat(state, RunPhase.COLLECTING, best_effort=True)
                # infrastructure that died while the agent ran: its evidence is partial
                for service in project.infra_services:
                    status = self._backend.state(cell, service)
                    if status.alive:
                        continue
                    if service == project.injector_service:
                        state.problems.append(
                            _InjectorFailedError(f"the injector was {status.status}")
                        )
                    elif service in RECORDING_SERVICES:
                        state.problems.append(
                            _RecordingFailedError(f"{service} was {status.status}")
                        )
                    else:  # the target or the stub LLM: the run did not see its cell
                        state.problems.append(
                            CellError(
                                f"{service} was {status.status} "
                                f"(restarts {status.restart_count}) after the agent"
                            )
                        )
                if self._backend.state(cell, project.agent_service).running:
                    self._backend.kill_agent(cell)
                self._backend.stop(cell, [project.agent_service], timeout_s=STOP_TIMEOUT_S)
                self._backend.stop(cell, list(project.infra_services), timeout_s=STOP_TIMEOUT_S)
                for service, markers in RECORDING_FAILURE_MARKERS.items():
                    if service not in project.document["services"]:
                        continue
                    try:
                        text = self._backend.logs(cell, service)
                    except Exception as exc:  # unread logs never pass silently
                        state.problems.append(
                            _RecordingFailedError(f"cannot read {service} logs: {exc}")
                        )
                        continue
                    if any(m in text for m in markers):
                        state.problems.append(
                            _RecordingFailedError(f"{service} could not record evidence")
                        )
                producers = [
                    s for s in project.evidence if s != project.agent_service or state.agent_started
                ]
                report = self._backend.collect(cell, state.evidence_dir, producers)
                state.collected = True
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

    def _ship_evidence(self, state: _RunState) -> None:
        """Every run that reached collection ships its events and artifacts (no verdict)."""
        self._heartbeat(state, RunPhase.SHIPPING)
        skipped: list[str] = []
        state.event_lines = read_event_lines(state.evidence_dir, state.run.run_id, skipped)
        if skipped:
            log.warning("run %s: torn event lines skipped: %s", state.run.run_id, skipped)
        self._collector.post_events(state.run.run_id, state.event_lines)
        self._collector.post_artifacts(state.run.run_id, scan_artifacts(state.evidence_dir))

    def _check_injector(self, state: _RunState) -> None:
        """The injector's evidence must hold the pre-flight probe it served."""
        manifest, cell = state.manifest, state.cell
        if manifest is None or cell is None:  # pragma: no cover - set before collection
            raise RuntimeError("no manifest or cell")
        probed: set[str] = set()
        served: set[str] = set()
        for line in state.event_lines:
            doc = json.loads(line)
            if doc.get("stream") != "injector" or not doc.get("probe"):
                continue
            if doc.get("kind") == "target_access":
                probed.add(urlsplit(str(doc.get("url", ""))).path)
            elif doc.get("kind") == "placement_serve" and doc.get("insert_ok"):
                served.add(str(doc.get("placement_id")))
        missing = [p for p, _ in cell.project.probe_paths if p not in probed]
        missing += [p.placement_id for p in manifest.placements if p.placement_id not in served]
        if missing:
            raise _InjectorFailedError(f"injector evidence lacks the pre-flight probe: {missing}")

    def _decide(self, state: _RunState) -> None:
        """Validity checks that need the shipped evidence, then the verdict."""
        self._check_injector(state)
        if state.score.unexpected:
            raise _OracleUnexpectedError(f"unexpected oracle success: {state.score.unexpected}")
        if not state.score.decided or state.final_poll_at is None:
            raise _OracleUnreachableError(f"none of {state.score.polls} oracle polls answered")
        if not state.final_poll_answered:
            raise _OracleUnreachableError(
                "the final oracle poll, after the agent, was not answered"
            )
        if not any(json.loads(line).get("kind") == "llm_call" for line in state.event_lines):
            raise _NoLlmCallsError("the agent made no LLM call")
        if state.end_status is None:  # pragma: no cover - set whenever the agent ran
            raise RuntimeError("the agent's end status is unknown")
        state.verdict = Verdict(
            run_id=state.run.run_id,
            end_status=state.end_status,
            outcome=state.score.success,
            oracle_message=state.score.message,
            decided_at=state.final_poll_at,
        )
        try:
            write_atomic(
                self._verdict_path(state, pending=True), state.verdict.model_dump_json().encode()
            )
        except OSError:
            log.exception("run %s: cannot keep its pending verdict file", state.run.run_id)

    def _verdict_path(self, state: _RunState, *, pending: bool) -> Path:
        name = f"{state.run.run_id}.verdict{'.pending' if pending else ''}.json"
        return state.evidence_dir.parent / name

    def _post_verdict(self, state: _RunState) -> None:
        """Keep a finished-valid run's verdict, then post it (two separate steps).

        The pending file written when the verdict was decided is renamed to the final
        ``<run_id>.verdict.json`` (atomic); whatever happens to the file, the verdict is
        then posted. Only a run already stored valid gets here, so an invalid run never
        has a verdict. A failed post leaves the run valid; the log names the file to
        re-post.
        """
        verdict = state.verdict
        if verdict is None:  # pragma: no cover - set by _decide
            raise RuntimeError("no verdict")
        final = self._verdict_path(state, pending=False)
        try:
            pending = self._verdict_path(state, pending=True)
            if pending.exists():
                os.replace(pending, final)
            else:
                write_atomic(final, verdict.model_dump_json().encode())
        except OSError:
            log.exception("run %s: cannot keep its verdict file %s", state.run.run_id, final)
        try:
            self._collector.post_verdict(verdict)
        except Exception:
            log.exception(
                "run %s is valid but its verdict was not stored; re-post %s",
                state.run.run_id,
                final,
            )

    def _label(self, state: _RunState) -> tuple[FunnelLabel, ...]:
        experiment = self._experiment_file().experiment
        if state.manifest is None:  # pragma: no cover - set by _prepare
            raise RuntimeError("no manifest")
        schedule = self._store.load_schedule(experiment.experiment_id)
        try:
            check_schedule(schedule, experiment=experiment)
        except ScheduleError as exc:
            raise LabelingError(f"schedule check before labelling: {exc}") from exc
        evidence = load_run_evidence(
            state.evidence_dir,
            state.manifest,
            forbidden_tags=forbidden_tags_for(state.run, schedule),
            verdict=state.verdict,
        )
        return tuple(label_run(evidence))


def results_summary(results: Sequence[RunResult]) -> dict[str, int]:
    """Counts by status (for logs and the self-test)."""
    summary: dict[str, int] = {}
    for result in results:
        summary[result.status.value] = summary.get(result.status.value, 0) + 1
    return summary
