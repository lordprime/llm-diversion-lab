"""The instrumentation self-test: ``labctl selftest [--quick]`` (DEVELOPMENT_PLAN 5.3).

It runs ``experiments/selftest.yaml`` (one injected and one matched control DVGA cell,
the scripted agent, the stub LLM; no model is called) through the real
:class:`~control.runner.runner.Runner`, and then checks the result from the database,
the evidence on disk and the container engine. It **passes** only if all of these
hold:

* both runs are ``valid`` **and** ended ``completed`` (a crashed agent still gives a
  valid run: crashing is an outcome, so ``valid`` alone is not enough);
* injected run: Access, Visible, Uptake and Outcome are all true; the oracle's verdict
  is true; the catcher recorded a callback on **both** channels (HTTP and DNS) whose
  token is the one the lab key derives for one of the run's own placements;
* control run: Access, Visible and Uptake are false, its oracle verdict is decided,
  no token callback reached it, and no file of its evidence holds any injected run's
  tag (the labeller's forbidden-tag check already made a leaking control
  ``contaminated``; the file scan repeats it independently);
* **containment** (critical): before a cell is trusted, i.e. after the runner's health
  check and pre-flight probe and before its agent starts, ``cell/probe/containment.py``
  runs in a sibling container on the cell's agent network (the agent's own network
  position, the lab-cell image, the run's label, no capabilities) with the full flag
  set: ``--host-gateway`` (the agent network's gateway, ``.1``), ``--lan`` (from
  ``LAB_PROBE_LAN``), ``--sinkhole`` (the catcher, ``.2``) and ``--reach`` the
  injector (``.3``) and the tap (``.4``), IP literals only. Anything reachable on the
  internet, the host or the LAN, a must-reach that failed, or a probe that gave no
  complete report fails the self-test critically, and that cell's agent never starts
  (:class:`ContainmentGate` raises, so the run is invalid ``cell_failed``);
* after teardown nothing (container, volume, network) is labelled with either run id.

``--quick`` is what ``deploy/remote/release.sh`` runs after every deploy. It keeps the
**first target only** (one matched pair: two cells, the smallest unit the matched-pair
schedule can run, and the control's zero-tag check is a core claim) and runs the
containment probe in the **first cell only** (the cells differ only by subnet; the
host firewall covers the whole cell range). Every other check is the same. With
M0's single target, full mode differs from quick mode only by probing every cell.

Each invocation registers a **fresh experiment** (``exp_selftest_<ULID>``; the file's
text with that id and a provenance comment), so self-tests can be repeated and a new
release's image builds are never refused as "registered with other builds".

The lab wiring (:func:`run_lab_selftest`) reads, on the host (``LAB_ROOT=/srv/lab``):

* ``secrets/hmac.key`` (the lab key; read by root only);
* ``host.env`` (``LAB_CELL_NETWORKS``, ``LAB_LLM_GATEWAY``, ``LAB_PROBE_LAN``;
  ``$LAB_HOST_ENV`` overrides the path; a missing file is an error unless ``LAB_DEV=1``);
* the release tree ``current/`` (``$LAB_RELEASE_TREE`` overrides): the experiment, the
  cell templates and ``deploy/images.lock`` (labctl is installed non-editable, so the
  package's own directory holds none of them);
* runs' evidence under ``artifacts/``, cell work files under ``cells/``, the runner's
  host lock at ``state/runner.lock`` (``$LAB_RUNNER_LOCK``), shared with the runner.

``LAB_PROBE_HOST_GATEWAY`` (development only, ``LAB_DEV=1``) replaces the probed host
address: under rootless Podman the network's gateway is the rootless network
namespace, not the host, and answers with a reset.
"""

from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import logging
import re
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

import httpx
import yaml
from sqlalchemy import Engine, select

from control.core.ids import new_id
from control.core.models import (
    Arm,
    CallbackChannel,
    EndStatus,
    FunnelStage,
    RunStatus,
)
from control.core.selftest_status import MAX_SUMMARY_CHARS
from control.core.tokens import derive_token
from control.db import tables as t
from control.db.engine import session_scope
from control.runner.cell_spec import (
    REPO_ROOT,
    RUN_LABEL,
    CellError,
    CellSettings,
    read_host_env,
)
from control.runner.compose_backend import (
    CellBackend,
    CellHandle,
    CollectReport,
    CommandResult,
    CommandRunner,
    ComposeBackend,
    ContainerState,
    SubprocessRunner,
)
from control.runner.experiment import ExperimentFile, parse_experiment
from control.runner.runner import HostLockError, Runner, RunResult
from control.runner.ship import CollectorClient
from control.runner.store import RunStore

__all__ = [
    "SELFTEST_EXPERIMENT",
    "CellLayout",
    "Check",
    "ContainmentGate",
    "ContainmentProbe",
    "DockerContainmentProbe",
    "DockerLeftovers",
    "LabContext",
    "LeftoverCheck",
    "ProbeRecord",
    "SelftestConfigError",
    "SelftestDeps",
    "SelftestReport",
    "cell_layout",
    "derive_experiment",
    "failed_report",
    "run_lab_selftest",
    "run_selftest",
    "runner_lock_path",
]

log = logging.getLogger(__name__)

#: The self-test experiment, relative to the release tree.
SELFTEST_EXPERIMENT: Final = Path("experiments") / "selftest.yaml"
#: Seconds per probed destination (the probe allows 1-60).
PROBE_TIMEOUT_S: Final = 2.0
#: Most seconds the probe container may take (about 15 destinations at 2 s each).
PROBE_RUN_TIMEOUT_S: Final = 300.0
#: Port the tap listens on (deploy/compose/cell.<target>.yml).
_TAP_PORT_DEFAULT: Final = 8080
_EXPERIMENT_ID_LINE = re.compile(r"^experiment_id:[ \t]*\S+[ \t]*$", re.MULTILINE)


class SelftestConfigError(RuntimeError):
    """The self-test cannot be set up on this host (no secret in the message)."""


# --------------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class Check:
    """One assertion of the self-test. ``critical``: a containment failure."""

    name: str
    ok: bool
    detail: str = ""
    critical: bool = False

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "critical": self.critical}


@dataclass(frozen=True, slots=True)
class ProbeRecord:
    """The containment probe's verdict on one cell (``report``: the probe's JSON)."""

    run_id: str
    contained: bool
    report: Mapping[str, Any] | None
    problems: tuple[str, ...] = ()

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "contained": self.contained,
            "problems": list(self.problems),
            "report": self.report,
        }


@dataclass(frozen=True, slots=True)
class SelftestReport:
    quick: bool
    experiment_id: str | None
    started_at: float
    finished_at: float
    checks: tuple[Check, ...]
    runs: tuple[Mapping[str, Any], ...] = ()
    probes: tuple[ProbeRecord, ...] = ()

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(c.ok for c in self.checks)

    @property
    def critical(self) -> bool:
        return any(c.critical and not c.ok for c in self.checks)

    @property
    def failures(self) -> tuple[Check, ...]:
        return tuple(c for c in self.checks if not c.ok)

    @property
    def summary(self) -> str:
        """One short line for the status file (no tags, tokens or evidence)."""
        n = len(self.checks)
        if self.passed:
            return f"passed: {n} checks"
        head = "CRITICAL (containment) " if self.critical else ""
        text = f"{head}failed {len(self.failures)} of {n}: " + "; ".join(
            f"{c.name}: {c.detail}" for c in self.failures
        )
        return text[:MAX_SUMMARY_CHARS]

    def to_json(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "critical": self.critical,
            "quick": self.quick,
            "experiment_id": self.experiment_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary,
            "checks": [c.to_json() for c in self.checks],
            "runs": [dict(r) for r in self.runs],
            "probes": [p.to_json() for p in self.probes],
        }

    def render_text(self) -> str:
        mode = "quick" if self.quick else "full"
        lines = [f"self-test ({mode}), experiment {self.experiment_id or '-'}"]
        for run in self.runs:
            labels = run.get("labels") or {}
            shown = " ".join(f"{k}={str(v).lower()}" for k, v in labels.items()) or "no labels"
            lines.append(
                f"  run {run['run_id']} {run['arm']}: {run['status']}"
                + (f" ({run['reason']})" if run.get("reason") else "")
                + f", end {run.get('end_status') or '-'}, outcome "
                + f"{'-' if run.get('outcome') is None else str(run['outcome']).lower()}, {shown}"
            )
        for check in self.checks:
            mark = "ok  " if check.ok else ("CRIT" if check.critical else "FAIL")
            lines.append(f"  {mark} {check.name}" + (f": {check.detail}" if check.detail else ""))
        verdict = "PASSED" if self.passed else "FAILED"
        if self.critical:
            verdict += " (CRITICAL: containment)"
        took = self.finished_at - self.started_at
        lines.append(
            f"self-test {verdict}: {sum(c.ok for c in self.checks)}/{len(self.checks)} "
            f"checks in {took:.0f} s"
        )
        return "\n".join(lines)


def failed_report(
    quick: bool, name: str, detail: str, *, started_at: float | None = None
) -> SelftestReport:
    """A self-test that could not run: one failed check."""
    now = time.time()
    return SelftestReport(
        quick=quick,
        experiment_id=None,
        started_at=now if started_at is None else started_at,
        finished_at=now,
        checks=(Check(name, False, detail),),
    )


# --------------------------------------------------------------------------- experiment


def derive_experiment(
    path: Path, *, quick: bool, experiment_id: str | None = None
) -> ExperimentFile:
    """The self-test experiment of one invocation: a fresh id, the first target if quick.

    The stored definition is exactly what runs: the file's text with the new id and a
    provenance comment naming the source file's sha256 (re-dumped YAML only when quick
    mode drops targets).
    """
    data = path.read_bytes()
    text = data.decode("utf-8")
    source_sha = hashlib.sha256(data).hexdigest()
    new = experiment_id or f"exp_{new_id('selftest')}"
    if len(_EXPERIMENT_ID_LINE.findall(text)) != 1:
        raise ValueError(f"{path}: expected exactly one top-level experiment_id line")
    body = _EXPERIMENT_ID_LINE.sub(f"experiment_id: {new}", text)
    if quick and len(parse_experiment(body).targets) > 1:
        doc = yaml.safe_load(body)
        doc["targets"] = doc["targets"][:1]
        body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    header = (
        f"# labctl selftest ({'quick' if quick else 'full'}): derived from "
        f"{SELFTEST_EXPERIMENT.as_posix()} sha256 {source_sha}\n"
    )
    final = header + body
    return ExperimentFile(
        experiment=parse_experiment(final),
        definition_yaml=final,
        definition_sha256=hashlib.sha256(final.encode("utf-8")).hexdigest(),
    )


# --------------------------------------------------------------------------- containment


@dataclass(frozen=True, slots=True)
class CellLayout:
    """Where things are on a rendered cell's agent network (IP literals)."""

    network: str
    gateway: str
    catcher: str
    injector: str
    injector_port: int
    tap: str
    tap_port: int


def _listen_port(service: Mapping[str, Any], default: int) -> int:
    command = [str(c) for c in service.get("command") or []]
    if "--listen-port" in command:
        return int(command[command.index("--listen-port") + 1])
    return default


def cell_layout(project: Any) -> CellLayout:
    """Read the agent network's name, gateway and static addresses from the project.

    Raises :class:`CellError` if any is missing (the probe would then test nothing).
    """
    doc = project.document
    try:
        net = doc["networks"]["agent"]
        ipam = net["ipam"]["config"][0]
        services = doc["services"]

        def address(service: str) -> str:
            return str(services[service]["networks"]["agent"]["ipv4_address"])

        layout = CellLayout(
            network=str(net["name"]),
            gateway=str(ipam["gateway"]),
            catcher=address("catcher"),
            injector=address("injector"),
            injector_port=_listen_port(services["injector"], 80),
            tap=address("tap"),
            tap_port=_listen_port(services["tap"], _TAP_PORT_DEFAULT),
        )
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise CellError(f"{project.name}: cannot read the agent network layout: {exc!r}") from exc
    for value in (layout.gateway, layout.catcher, layout.injector, layout.tap):
        ipaddress.IPv4Address(value)  # IP literals only
    return layout


class ContainmentProbe(Protocol):
    def __call__(self, cell: CellHandle) -> ProbeRecord: ...


class DockerContainmentProbe:
    """Run ``cell.probe.containment`` in a sibling container on the cell's agent network.

    The container uses the cell's own image (``lab-cell``), the agent's resolver (the
    catcher), no capabilities, a read-only root and the run's label, so teardown removes
    it whatever happens. A report counts as contained only if the probe exited 0, said
    so, covered every category and reached both the injector and the tap.
    """

    def __init__(
        self,
        run: CommandRunner,
        *,
        image: str,
        lan: Sequence[str],
        docker: str = "docker",
        host_gateway: str | None = None,
        timeout_s: float = PROBE_TIMEOUT_S,
    ) -> None:
        if not lan:
            raise SelftestConfigError("the containment probe needs a LAN address")
        self._run = run
        self._image = image
        self._lan = tuple(lan)
        self._docker = docker
        self._host_gateway = host_gateway
        self._timeout_s = timeout_s

    def argv(self, cell: CellHandle) -> list[str]:
        layout = cell_layout(cell.project)
        project = cell.project
        probe = [
            "python",
            "-m",
            "cell.probe.containment",
            "--defaults",
            "--host-gateway",
            self._host_gateway or layout.gateway,
            "--sinkhole",
            layout.catcher,
            "--reach",
            f"{layout.injector}:{layout.injector_port}",
            "--reach",
            f"{layout.tap}:{layout.tap_port}",
            "--timeout",
            str(self._timeout_s),
        ]
        for addr in self._lan:
            probe += ["--lan", addr]
        return [
            self._docker,
            "run",
            "--rm",
            "--name",
            f"{project.name}-probe",
            "--label",
            f"{RUN_LABEL}={project.run_id}",
            "--label",
            "lab.role=probe",
            "--network",
            layout.network,
            "--dns",
            layout.catcher,
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--read-only",
            "--pids-limit",
            "64",
            "--memory",
            "128m",
            self._image,
            *probe,
        ]

    def __call__(self, cell: CellHandle) -> ProbeRecord:
        run_id = cell.project.run_id
        try:
            argv = self.argv(cell)
        except (CellError, ValueError) as exc:
            return ProbeRecord(run_id, False, None, (f"probe not run: {exc}",))
        layout = cell_layout(cell.project)
        result = self._run(argv, timeout=PROBE_RUN_TIMEOUT_S)
        if result.returncode not in (0, 1):
            # the probe never judged (usage error, engine failure, timeout): fail closed
            self._run([self._docker, "rm", "-f", f"{cell.project.name}-probe"])
            err = result.stderr.decode("utf-8", "replace").strip()[-300:]
            out = result.text.strip()[-300:]
            return ProbeRecord(
                run_id,
                False,
                None,
                (f"the probe gave no report (exit {result.returncode}): {err or out}",),
            )
        return self._judge(run_id, result, layout)

    def _judge(self, run_id: str, result: CommandResult, layout: CellLayout) -> ProbeRecord:
        lines = [line for line in result.text.splitlines() if line.strip()]
        try:
            doc = json.loads(lines[-1])
            if not isinstance(doc, dict):
                raise TypeError("not an object")
        except (IndexError, ValueError, TypeError):
            return ProbeRecord(
                run_id, False, None, (f"the probe gave no report: {result.text[-300:]!r}",)
            )
        problems: list[str] = []
        results = doc.get("results")
        if not isinstance(results, list) or doc.get("missing_categories") != []:
            problems.append(
                f"incomplete report (missing categories: {doc.get('missing_categories')!r})"
            )
            results = results if isinstance(results, list) else []
        for item in results:
            if not isinstance(item, dict) or item.get("ok") is not True:
                label = item.get("label") if isinstance(item, dict) else item
                outcome = item.get("outcome") if isinstance(item, dict) else "?"
                problems.append(f"{label} {outcome}")
        reached = {
            f"{item.get('target')}:{item.get('port')}"
            for item in results
            if isinstance(item, dict) and item.get("must_reach") and item.get("ok") is True
        }
        for need in (
            f"{layout.injector}:{layout.injector_port}",
            f"{layout.tap}:{layout.tap_port}",
        ):
            if need not in reached:
                problems.append(f"must-reach {need} not reached")
        if doc.get("contained") is not True or result.returncode != 0:
            problems.append(f"probe verdict: contained={doc.get('contained')!r}")
        problems = list(dict.fromkeys(problems))
        return ProbeRecord(run_id, not problems, doc, tuple(problems))


class ContainmentGate:
    """A :class:`CellBackend` that probes a cell's containment before its agent starts.

    Everything is delegated to ``inner``; :meth:`start_agent` first runs ``probe`` (for
    the first ``limit`` cells, all if ``None``) and raises :class:`CellError` if the cell
    is not contained, so the agent never starts there and the runner tears it down.
    """

    def __init__(
        self, inner: CellBackend, probe: ContainmentProbe, *, limit: int | None = None
    ) -> None:
        self._inner = inner
        self._probe = probe
        self._limit = limit
        self.records: list[ProbeRecord] = []

    def start_agent(self, cell: CellHandle) -> None:
        if self._limit is None or len(self.records) < self._limit:
            record = self._probe(cell)
            self.records.append(record)
            if not record.contained:
                log.error(
                    "selftest: cell of run %s is NOT contained: %s",
                    record.run_id,
                    "; ".join(record.problems),
                )
                raise CellError("containment probe failed: " + "; ".join(record.problems)[:500])
            log.info("selftest: cell of run %s is contained", record.run_id)
        self._inner.start_agent(cell)

    # delegation

    def subnets_in_use(self) -> list[ipaddress.IPv4Network]:
        return self._inner.subnets_in_use()

    def prepare(self, project: Any, workdir: Path) -> CellHandle:
        return self._inner.prepare(project, workdir)

    def up(self, cell: CellHandle) -> None:
        self._inner.up(cell)

    def health(self, cell: CellHandle, *, timeout_s: float) -> bool:
        return self._inner.health(cell, timeout_s=timeout_s)

    def exec(
        self, cell: CellHandle, service: str, argv: Sequence[str], *, timeout_s: float
    ) -> CommandResult:
        return self._inner.exec(cell, service, argv, timeout_s=timeout_s)

    def state(self, cell: CellHandle, service: str) -> ContainerState:
        return self._inner.state(cell, service)

    def kill_agent(self, cell: CellHandle) -> None:
        self._inner.kill_agent(cell)

    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None:
        self._inner.stop(cell, services, timeout_s=timeout_s)

    def logs(self, cell: CellHandle, service: str) -> str:
        return self._inner.logs(cell, service)

    def collect(
        self, cell: CellHandle, dest: Path, services: Sequence[str] | None = None
    ) -> CollectReport:
        return self._inner.collect(cell, dest, services)

    def teardown(self, cell: CellHandle) -> None:
        self._inner.teardown(cell)


# --------------------------------------------------------------------------- leftovers


class LeftoverCheck(Protocol):
    def __call__(self, run_id: str) -> dict[str, list[str]]: ...


class DockerLeftovers:
    """Containers, volumes and networks still labelled with a run (a failed listing
    is reported as a leftover, never as "none")."""

    def __init__(self, run: CommandRunner, *, docker: str = "docker") -> None:
        self._run = run
        self._docker = docker

    def __call__(self, run_id: str) -> dict[str, list[str]]:
        label = f"label={RUN_LABEL}={run_id}"
        left: dict[str, list[str]] = {}
        for kind, argv in (
            ("containers", ["ps", "-a", "-q"]),
            ("volumes", ["volume", "ls", "-q"]),
            ("networks", ["network", "ls", "-q"]),
        ):
            result = self._run([self._docker, *argv, "--filter", label])
            if result.returncode != 0:
                left[kind] = [f"listing failed (exit {result.returncode})"]
            elif words := result.text.split():
                left[kind] = words
        return left


# --------------------------------------------------------------------------- the self-test


@dataclass(slots=True)
class SelftestDeps:
    """Everything the self-test talks to (fakes in tests, the lab's on the host)."""

    engine: Engine
    collector: CollectorClient
    backend: CellBackend
    probe: ContainmentProbe
    leftovers: LeftoverCheck
    settings: CellSettings
    lab_key: bytes = field(repr=False)
    runs_dir: Path
    work_dir: Path
    lock_path: Path
    templates_root: Path = REPO_ROOT
    #: extra Runner keyword arguments (tests: no sleeping)
    runner_options: Mapping[str, Any] = field(default_factory=dict)


def run_selftest(
    deps: SelftestDeps, *, quick: bool, clock: Callable[[], float] = time.time
) -> SelftestReport:
    """Run the self-test pair and check it; never raises for a failed self-test."""
    started = clock()
    try:
        ef = derive_experiment(deps.templates_root / SELFTEST_EXPERIMENT, quick=quick)
    except (OSError, ValueError) as exc:
        return failed_report(quick, "experiment", str(exc)[:300], started_at=started)
    experiment_id = ef.experiment.experiment_id
    gate = ContainmentGate(deps.backend, deps.probe, limit=1 if quick else None)
    runner = Runner(
        store=RunStore(deps.engine),
        collector=deps.collector,
        backend=gate,
        settings=deps.settings,
        lab_key=deps.lab_key,
        runs_dir=deps.runs_dir,
        work_dir=deps.work_dir,
        lock_path=deps.lock_path,
        templates_root=deps.templates_root,
        **deps.runner_options,
    )
    log.info("selftest: running %s (%s)", experiment_id, "quick" if quick else "full")
    checks: list[Check] = []
    results: list[RunResult] = []
    try:
        results = runner.run_experiment(ef)
    except HostLockError as exc:
        checks.append(Check("run the pair", False, f"another runner is active: {exc}"))
    except Exception as exc:
        log.exception("selftest: the runner failed")
        checks.append(Check("run the pair", False, f"{type(exc).__name__}: {str(exc)[:300]}"))
    if not checks:
        try:
            checks += _check_results(deps, ef, results, gate.records, quick=quick)
        except Exception as exc:
            log.exception("selftest: checking the results failed")
            checks.append(Check("check results", False, f"{type(exc).__name__}: {exc}"[:300]))
    runs = tuple(_run_summary(deps.engine, r) for r in results)
    report = SelftestReport(
        quick=quick,
        experiment_id=experiment_id,
        started_at=started,
        finished_at=clock(),
        checks=tuple(checks),
        runs=runs,
        probes=tuple(gate.records),
    )
    log.info("selftest: %s", report.summary)
    return report


def _labels(engine: Engine, run_id: str) -> dict[FunnelStage, bool]:
    with session_scope(engine) as s:
        rows = s.scalars(select(t.Label).where(t.Label.run_id == run_id)).all()
        return {row.stage: row.value for row in rows}


def _run_summary(engine: Engine, result: RunResult) -> dict[str, Any]:
    return {
        "run_id": result.run_id,
        "arm": result.arm.value,
        "status": result.status.value,
        "reason": result.reason.value if result.reason else None,
        "end_status": result.end_status.value if result.end_status else None,
        "outcome": result.outcome,
        "labels": {stage.value: value for stage, value in _labels(engine, result.run_id).items()},
    }


def _check_results(
    deps: SelftestDeps,
    ef: ExperimentFile,
    results: Sequence[RunResult],
    probes: Sequence[ProbeRecord],
    *,
    quick: bool,
) -> list[Check]:
    checks: list[Check] = []
    expected = 2 * len(ef.experiment.targets)
    checks.append(
        Check("runs", len(results) == expected, f"{len(results)} runs, expected {expected}")
    )
    for arm in (Arm.INJECTED, Arm.CONTROL):
        if not any(r.arm is arm for r in results):
            checks.append(Check(f"{arm.value}: valid", False, "no run of this arm"))
    with session_scope(deps.engine) as s:
        tags = {
            row.tag
            for row in s.scalars(
                select(t.Run).where(t.Run.experiment_id == ef.experiment.experiment_id)
            ).all()
            if row.tag
        }
    probed = {p.run_id: p for p in probes}
    for result in results:
        arm_name = result.arm.value
        valid = result.status is RunStatus.VALID
        detail = "" if valid else f"{result.status.value} ({result.reason}): {result.detail[:300]}"
        checks.append(Check(f"{arm_name}: valid", valid, detail))
        completed = result.end_status is EndStatus.COMPLETED
        checks.append(
            Check(
                f"{arm_name}: completed",
                completed,
                "" if completed else f"agent end status {result.end_status or 'none'}",
            )
        )
        labels = _labels(deps.engine, result.run_id)
        if result.arm is Arm.INJECTED:
            checks.append(_funnel_check(arm_name, labels, want_true=tuple(FunnelStage)))
            checks.append(
                Check(
                    f"{arm_name}: oracle",
                    result.outcome is True,
                    "" if result.outcome is True else f"verdict {result.outcome}",
                )
            )
            checks.append(_callback_check(deps, result.run_id))
        else:
            checks.append(
                _funnel_check(
                    arm_name,
                    labels,
                    want_false=(FunnelStage.ACCESS, FunnelStage.VISIBLE, FunnelStage.UPTAKE),
                )
            )
            checks.append(
                Check(
                    f"{arm_name}: oracle",
                    result.outcome is not None,
                    "" if result.outcome is not None else "no verdict",
                )
            )
            checks.append(_control_clean(deps, result.run_id, tags))
        if not quick or result.run_id in probed:
            record = probed.get(result.run_id)
            if record is None:
                checks.append(
                    Check(f"{arm_name}: contained", False, "the probe never ran", critical=True)
                )
            else:
                checks.append(
                    Check(
                        f"{arm_name}: contained",
                        record.contained,
                        "; ".join(record.problems)[:500],
                        critical=not record.contained,
                    )
                )
        left = deps.leftovers(result.run_id)
        checks.append(
            Check(f"{arm_name}: nothing left", not left, "" if not left else json.dumps(left)[:300])
        )
    if quick and not probes:
        checks.append(Check("contained", False, "the probe never ran", critical=True))
    return checks


def _funnel_check(
    arm: str,
    labels: Mapping[FunnelStage, bool],
    *,
    want_true: Sequence[FunnelStage] = (),
    want_false: Sequence[FunnelStage] = (),
) -> Check:
    wrong = [
        f"{stage.value}={labels.get(stage)}"
        for stage, want in [(s, True) for s in want_true] + [(s, False) for s in want_false]
        if labels.get(stage) is not want
    ]
    if len(labels) != len(FunnelStage):
        wrong.append(f"{len(labels)} of {len(FunnelStage)} stages labelled")
    return Check(f"{arm}: funnel", not wrong, ", ".join(wrong))


def _callback_check(deps: SelftestDeps, run_id: str) -> Check:
    """A token-verified callback mapped to one of the run's placements, per channel."""
    with session_scope(deps.engine) as s:
        placements = {
            p.placement_id: p.token
            for p in s.scalars(select(t.Placement).where(t.Placement.run_id == run_id)).all()
        }
        callbacks = [
            (c.channel, c.token, c.placement_id)
            for c in s.scalars(select(t.Callback).where(t.Callback.run_id == run_id)).all()
        ]
    verified = {
        channel
        for channel, token, placement_id in callbacks
        if token
        and placement_id in placements
        and placements[placement_id] == token
        and derive_token(deps.lab_key, run_id, placement_id) == token
    }
    missing = [c.value for c in (CallbackChannel.HTTP, CallbackChannel.DNS) if c not in verified]
    detail = "" if not missing else f"no verified callback on {', '.join(missing)}"
    return Check("injected: callbacks", not missing, detail)


def _control_clean(deps: SelftestDeps, run_id: str, tags: set[str]) -> Check:
    problems: list[str] = []
    with session_scope(deps.engine) as s:
        tokened = [
            c.channel.value
            for c in s.scalars(select(t.Callback).where(t.Callback.run_id == run_id)).all()
            if c.token
        ]
    if tokened:
        problems.append(f"token callbacks reached the control: {sorted(set(tokened))}")
    needles = [tag.encode() for tag in tags]
    evidence = deps.runs_dir / run_id
    leaked = sorted(
        str(path.relative_to(evidence))
        for path in _files(evidence)
        if any(needle in path.read_bytes() for needle in needles)
    )
    if leaked:
        problems.append(f"an injected tag is in {len(leaked)} evidence files: {leaked[:5]}")
    if not evidence.is_dir():
        problems.append("no evidence directory")
    return Check("control: no tags", not problems, "; ".join(problems))


def _files(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        if path.is_file() and not path.is_symlink():
            yield path


# --------------------------------------------------------------------------- the lab's wiring


@dataclass(frozen=True, slots=True)
class LabContext:
    """What labctl knows: the lab root, the environment, the Collector and the database."""

    lab_root: Path
    environ: Mapping[str, str]
    collector_url: str
    engine: Engine


def runner_lock_path(lab_root: Path, environ: Mapping[str, str]) -> Path:
    """The host's runner lock, shared with every runner (``$LAB_RUNNER_LOCK``)."""
    return Path(environ.get("LAB_RUNNER_LOCK") or lab_root / "state" / "runner.lock")


def _dev(environ: Mapping[str, str]) -> bool:
    return environ.get("LAB_DEV") == "1"


def _host_env(lab_root: Path, environ: Mapping[str, str]) -> dict[str, str] | None:
    """``host.env`` (``$LAB_HOST_ENV``); missing is an error unless ``LAB_DEV=1``."""
    path = Path(environ.get("LAB_HOST_ENV") or lab_root / "host.env")
    try:
        return read_host_env(path)
    except FileNotFoundError:
        if _dev(environ):
            log.warning("selftest: no %s (LAB_DEV=1: settings from the environment)", path)
            return None
        raise SelftestConfigError(f"no host profile at {path} (set LAB_DEV=1 off-host)") from None
    except (OSError, CellError) as exc:
        raise SelftestConfigError(f"cannot read {path}: {exc}") from exc


def _lab_key(lab_root: Path) -> bytes:
    path = lab_root / "secrets" / "hmac.key"
    try:
        key = path.read_bytes()
    except OSError as exc:
        raise SelftestConfigError(
            f"cannot read the lab key {path} ({exc.strerror}); run labctl as root"
        ) from None
    if len(key) < 16:
        raise SelftestConfigError(f"the lab key {path} is too short")
    return key


def _probe_lan(environ: Mapping[str, str], host_env: Mapping[str, str] | None) -> list[str]:
    host_value = (host_env or {}).get("LAB_PROBE_LAN", "")
    env_value = environ.get("LAB_PROBE_LAN", "")
    if host_value and env_value and env_value != host_value:
        raise SelftestConfigError(
            f"LAB_PROBE_LAN {env_value!r} differs from the host's configured {host_value!r}"
        )
    raw = host_value or env_value
    lan = [part.strip() for part in raw.split(",") if part.strip()]
    if not lan:
        raise SelftestConfigError(
            "no home-LAN address for the containment probe: set LAB_PROBE_LAN in host.env"
        )
    for addr in lan:
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise SelftestConfigError(f"LAB_PROBE_LAN: {addr!r} is not an IP address") from None
    return lan


def _host_gateway_override(environ: Mapping[str, str]) -> str | None:
    value = environ.get("LAB_PROBE_HOST_GATEWAY", "").strip()
    if not value:
        return None
    if not _dev(environ):
        raise SelftestConfigError("LAB_PROBE_HOST_GATEWAY is for development only (LAB_DEV=1)")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise SelftestConfigError(f"LAB_PROBE_HOST_GATEWAY: {value!r} is not an IP") from None
    log.warning("selftest: LAB_DEV=1: probing %s as the host, not the cell gateway", value)
    return value


def _release_tree(lab_root: Path, environ: Mapping[str, str]) -> Path:
    if tree := environ.get("LAB_RELEASE_TREE"):
        return Path(tree)
    current = lab_root / "current"
    if (current / SELFTEST_EXPERIMENT).is_file():
        return current
    return REPO_ROOT  # a development checkout


@contextlib.contextmanager
def _lab_deps(context: LabContext) -> Iterator[SelftestDeps]:
    environ, lab_root = context.environ, context.lab_root
    lab_key = _lab_key(lab_root)
    host_env = _host_env(lab_root, environ)
    lan = _probe_lan(environ, host_env)
    host_gateway = _host_gateway_override(environ)
    tree = _release_tree(lab_root, environ)
    cell_env = dict(environ)
    cell_env.setdefault("LAB_IMAGES_LOCK", str(tree / "deploy" / "images.lock"))
    try:
        settings = CellSettings.from_env(cell_env, host_env=host_env)
        probe_image = settings.image("lab-cell")
    except CellError as exc:
        raise SelftestConfigError(str(exc)) from exc
    docker_env = {k: environ[k] for k in ("DOCKER_HOST",) if k in environ}
    commands = SubprocessRunner(docker_env)
    with httpx.Client(base_url=context.collector_url, timeout=60.0) as http:
        yield SelftestDeps(
            engine=context.engine,
            collector=CollectorClient(http),
            backend=ComposeBackend(commands),
            probe=DockerContainmentProbe(
                commands, image=probe_image, lan=lan, host_gateway=host_gateway
            ),
            leftovers=DockerLeftovers(commands),
            settings=settings,
            lab_key=lab_key,
            runs_dir=lab_root / "artifacts",
            work_dir=lab_root / "cells",
            lock_path=runner_lock_path(lab_root, environ),
            templates_root=tree,
        )


def run_lab_selftest(context: LabContext, *, quick: bool) -> SelftestReport:
    """The self-test on this host (``labctl selftest``); never raises for a failure."""
    started = time.time()
    try:
        with _lab_deps(context) as deps:
            return run_selftest(deps, quick=quick)
    except SelftestConfigError as exc:
        log.error("selftest: %s", exc)
        return failed_report(quick, "configuration", str(exc), started_at=started)
