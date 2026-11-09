"""The instrumentation self-test: ``labctl selftest [--quick]`` (DEVELOPMENT_PLAN 5.3).

It runs ``experiments/selftest.yaml`` (one injected and one matched control DVGA cell,
the scripted agent, the stub LLM; no model is called) through the real
:class:`~control.runner.runner.Runner`, holding the host's runner lock for the whole
self-test, and then checks the result from the database, the evidence on disk and the
container engine. It **passes** only if all of these hold:

* both runs are ``valid`` **and** ended ``completed`` (a crashed agent still gives a
  valid run: crashing is an outcome, so ``valid`` alone is not enough);
* injected run: Access, Visible, Uptake and Outcome are all true; the stored verdict
  (``runs.outcome``, ``runs.decided_at``) is true; the catcher recorded a callback on
  **both** channels (HTTP and DNS) whose token is the one the lab key derives for one
  of the run's own placements;
* control run: Access, Visible and Uptake are false, its verdict is stored, no token
  callback reached it, and no file of its evidence holds any injected run's tag or
  token, base64 fields (``body_b64``) decoded (the labeller's forbidden-tag check
  already made a leaking control ``contaminated``; the scan repeats it independently);
* **containment** (critical): before a cell is trusted, i.e. after the runner's health
  check, pre-flight probe and liveness check and before its agent starts,
  ``cell/probe/containment.py`` runs in a sibling container on the cell's agent network
  (the agent's own network position, the lab-cell image, the run's label, no
  capabilities) with the full flag set: ``--host-gateway`` (the agent network's
  gateway, ``.1``), ``--lan`` (``LAB_PROBE_LAN``), ``--sinkhole`` (the catcher, ``.2``),
  ``--reach`` the injector (``.3``) and the tap (``.4``), and must-fail ``--dest`` s for
  the control plane (the Collector's and the database's container addresses and the
  control network's gateway with the published ports, read from the engine and
  ``deploy/compose/control-plane.yml``) and the host's own LAN address on the host
  ports. IP literals only. Anything reachable, a must-reach that failed, or a probe
  without a complete report fails the self-test as CRITICAL and that cell's agent never
  starts (:class:`ContainmentGate` raises: the run is invalid ``cell_failed``);
* a "blocked" result proves something only about real addresses: the host gateway must
  be one of this host's own addresses (checked with ``bind``) before each probe, and
  each LAN address must answer from the host (TCP on 80/443, else ICMP) before the
  self-test starts. Otherwise the self-test fails (not critical: nothing was reached,
  but nothing was proven);
* after teardown nothing (container, volume, network) is labelled with either run id,
  and the runs' cell work directories are gone.

Before the pair runs, resources left by **earlier self-tests** are swept: those
labelled ``lab.run_id`` with a run of an ``exp_selftest_*`` experiment (none can be
running: the self-test holds the runner lock). Study runs' resources are never touched.

A cell that fails before its agent would start (so before the probe) is reported as a
cell failure, not as a containment failure.

``--quick`` is what ``deploy/remote/release.sh`` runs after every deploy. It keeps the
**first target only** (one matched pair: two cells, the smallest unit the matched-pair
schedule can run, and the control's zero-tag check is a core claim) and runs the
containment probe in the **first cell only** (the cells differ only by subnet; the
host firewall covers the whole cell range). Every other check is the same. With
M0's single target, full mode differs from quick mode only by probing every cell.

Each invocation registers a **fresh experiment** (``exp_selftest_<ULID>``; the file's
text with that id and a provenance comment), so self-tests can be repeated and a new
release's image builds are never refused as "registered with other builds". Study
metrics leave these experiments out (:data:`SELFTEST_EXPERIMENT_PREFIX`).

The lab wiring (:func:`run_lab_selftest`) reads, on the host (``LAB_ROOT=/srv/lab``):

* ``secrets/hmac.key`` (the lab key; read by root only);
* the host profile through :meth:`CellSettings.from_env` (``LAB_CELL_NETWORKS``,
  ``LAB_LLM_GATEWAY``) and, in production only from the profile, ``LAB_PROBE_LAN``;
* the release tree ``current/`` (``$LAB_RELEASE_TREE`` overrides), resolved once: the
  experiment, the cell templates, ``deploy/compose/control-plane.yml`` and, in
  production always, ``deploy/images.lock`` (labctl is installed non-editable, so the
  package's own directory holds none of them; ``LAB_IMAGES_LOCK`` and
  ``LAB_IMAGE_OVERRIDES`` count only in development);
* runs' evidence under ``artifacts/``, cell work files under ``cells/``, the runner's
  host lock from :func:`~control.runner.runner.runner_lock_path`.

Development (``settings.dev``, which :meth:`CellSettings.from_env` refuses on a host
with a profile): ``LAB_PROBE_LAN`` comes from the environment, a missing control plane
is tolerated, and, on Podman only, ``LAB_PROBE_HOST_GATEWAY`` replaces the probed host
address (under rootless Podman the network's gateway is the rootless network
namespace, not the host, and answers with a reset). It must still be an address of
this host.
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import ipaddress
import json
import logging
import re
import shutil
import socket
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Protocol

import httpx
import yaml
from sqlalchemy import Engine, func, select

from cell.probe.containment import HOST_PORTS, LAN_PORTS
from control.core.ids import new_id
from control.core.models import Arm, CallbackChannel, EndStatus, FunnelStage, RunStatus
from control.core.selftest_status import MAX_SUMMARY_CHARS, SELFTEST_EXPERIMENT_PREFIX
from control.core.tokens import derive_token
from control.db import tables as t
from control.db.engine import session_scope
from control.runner.cell_spec import (
    CELL_NAME_PREFIX,
    HOST_ENV_FILE,
    REPO_ROOT,
    RUN_LABEL,
    CellError,
    CellSettings,
    read_host_env,
)
from control.runner.cell_spec import (
    Engine as CellEngine,
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
from control.runner.runner import (
    CellLeftBehindError,
    HostLockError,
    Runner,
    RunResult,
    host_lock,
    runner_lock_path,
)
from control.runner.ship import CollectorClient
from control.runner.store import RunStore

__all__ = [
    "CONTROL_PLANE_FILE",
    "CONTROL_PLANE_PROJECT",
    "SELFTEST_EXPERIMENT",
    "CellLayout",
    "CellResources",
    "Check",
    "ContainmentGate",
    "ContainmentProbe",
    "DockerContainmentProbe",
    "DockerLeftovers",
    "LabContext",
    "ProbeRecord",
    "SelftestConfigError",
    "SelftestDeps",
    "SelftestReport",
    "cell_layout",
    "control_plane_destinations",
    "derive_experiment",
    "failed_report",
    "is_local_address",
    "lan_answers",
    "run_lab_selftest",
    "run_selftest",
]

log = logging.getLogger(__name__)

#: The self-test experiment, relative to the release tree.
SELFTEST_EXPERIMENT: Final = Path("experiments") / "selftest.yaml"
#: The control-plane compose file (relative to the release tree) and its project.
CONTROL_PLANE_FILE: Final = Path("deploy") / "compose" / "control-plane.yml"
CONTROL_PLANE_PROJECT: Final = "lab"
#: Seconds per probed destination (the probe allows 1-60).
PROBE_TIMEOUT_S: Final = 2.0
#: Most seconds the probe container may take (about 30 destinations at 2 s each).
PROBE_RUN_TIMEOUT_S: Final = 300.0
#: Port the tap listens on (deploy/compose/cell.<target>.yml).
_TAP_PORT_DEFAULT: Final = 8080
_EXPERIMENT_ID_LINE = re.compile(r"^experiment_id:[ \t]*\S+[ \t]*$", re.MULTILINE)
#: Evidence files larger than this are scanned as raw bytes only (no JSON decoding).
_MAX_JSON_SCAN_BYTES: Final = 64 * 1024 * 1024


class SelftestConfigError(RuntimeError):
    """The self-test cannot be set up on this host (no secret in the message)."""


# --------------------------------------------------------------------------- results


@dataclass(frozen=True, slots=True)
class Check:
    """One assertion of the self-test. ``critical``: a containment breach."""

    name: str
    ok: bool
    detail: str = ""
    critical: bool = False

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "ok": self.ok, "detail": self.detail, "critical": self.critical}


@dataclass(frozen=True, slots=True)
class ProbeRecord:
    """The containment probe's verdict on one cell (``report``: the probe's JSON).

    ``breach``: the probe ran and the cell is not proven contained (something reached,
    a must-reach failed, or no complete report): critical. Not contained without a
    breach means the probe could not prove anything (e.g. the host gateway is not this
    host's address): a failure, not critical.
    """

    run_id: str
    contained: bool
    report: Mapping[str, Any] | None
    problems: tuple[str, ...] = ()
    breach: bool = False

    def to_json(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "contained": self.contained,
            "breach": self.breach,
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
            outcome = run.get("outcome")
            lines.append(
                f"  run {run['run_id']} {run['arm']}: {run['status']}"
                + (f" ({run['reason']})" if run.get("reason") else "")
                + f", end {run.get('end_status') or '-'}, outcome "
                + f"{'-' if outcome is None else str(outcome).lower()}, {shown}"
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
        checks=(Check(name, False, detail[:MAX_SUMMARY_CHARS]),),
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
    if not new.startswith(SELFTEST_EXPERIMENT_PREFIX):
        raise ValueError(f"a self-test experiment id must start with {SELFTEST_EXPERIMENT_PREFIX}")
    if len(_EXPERIMENT_ID_LINE.findall(text)) != 1:
        raise ValueError(f"{path}: expected exactly one top-level experiment_id line")
    body = _EXPERIMENT_ID_LINE.sub(f"experiment_id: {new}", text)
    if quick and len(parse_experiment(body, selftest=True).targets) > 1:
        doc = yaml.safe_load(body)
        doc["targets"] = doc["targets"][:1]
        body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    header = (
        f"# labctl selftest ({'quick' if quick else 'full'}): derived from "
        f"{SELFTEST_EXPERIMENT.as_posix()} sha256 {source_sha}\n"
    )
    final = header + body
    return ExperimentFile(
        experiment=parse_experiment(final, selftest=True),
        definition_yaml=final,
        definition_sha256=hashlib.sha256(final.encode("utf-8")).hexdigest(),
    )


# --------------------------------------------------------------------------- addresses


def is_local_address(addr: str) -> bool:
    """True if ``addr`` is one of this host's own addresses (it can be bound here)."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.bind((str(ip), 0))
    except OSError:
        return False
    return True


def lan_answers(addr: str, *, timeout_s: float = 2.0) -> bool:
    """True if ``addr`` answers from this host: TCP on a probed LAN port (a connection or
    a refusal both answer), else one ICMP echo (``ping``)."""
    for port in LAN_PORTS:
        try:
            with socket.create_connection((addr, port), timeout=timeout_s):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    ping = shutil.which("ping")
    if ping is None:
        return False
    try:
        done = subprocess.run(  # noqa: S603 - fixed argv, an IP literal
            [ping, "-c", "1", "-W", str(int(timeout_s)), addr],
            capture_output=True,
            timeout=timeout_s + 3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return done.returncode == 0


def own_address_towards(addr: str) -> str | None:
    """This host's source address towards ``addr`` (a UDP connect sends nothing)."""
    family = socket.AF_INET6 if ipaddress.ip_address(addr).version == 6 else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.connect((addr, 9))
            return str(sock.getsockname()[0])
    except OSError:
        return None


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
        for value in (layout.gateway, layout.catcher, layout.injector, layout.tap):
            ipaddress.IPv4Address(value)  # IP literals only
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise CellError(f"{project.name}: cannot read the agent network layout: {exc!r}") from exc
    return layout


class ContainmentProbe(Protocol):
    def __call__(self, cell: CellHandle) -> ProbeRecord: ...


class DockerContainmentProbe:
    """Run ``cell.probe.containment`` in a sibling container on the cell's agent network.

    The container uses the cell's own image (``lab-cell``), the agent's resolver (the
    catcher), no capabilities, a read-only root and the run's label, so teardown removes
    it whatever happens. Before it runs, the host gateway must be an address of this
    host (``is_local``), or the probe proves nothing. A report counts as contained only
    if the probe exited 0, said so, covered every category, every result is ok and both
    the injector and the tap were reached.
    """

    def __init__(
        self,
        run: CommandRunner,
        *,
        image: str,
        lan: Sequence[str],
        docker: str = "docker",
        host_gateway: str | None = None,
        extra_destinations: Sequence[str] = (),
        is_local: Callable[[str], bool] = is_local_address,
        timeout_s: float = PROBE_TIMEOUT_S,
    ) -> None:
        if not lan:
            raise SelftestConfigError("the containment probe needs a LAN address")
        self._run = run
        self._image = image
        self._lan = tuple(lan)
        self._docker = docker
        self._host_gateway = host_gateway
        self._extra = tuple(dict.fromkeys(extra_destinations))
        self._is_local = is_local
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
        for dest in self._extra:
            probe += ["--dest", dest]
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
            layout = cell_layout(cell.project)
            argv = self.argv(cell)
        except CellError as exc:
            return ProbeRecord(run_id, False, None, (f"probe not run: {exc}",))
        gateway = self._host_gateway or layout.gateway
        if not self._is_local(gateway):
            return ProbeRecord(
                run_id,
                False,
                None,
                (
                    f"probe not run: the host gateway {gateway} is not an address of this "
                    "host, so a blocked result there would prove nothing",
                ),
            )
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
                breach=True,
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
                run_id,
                False,
                None,
                (f"the probe gave no report: {result.text[-300:]!r}",),
                breach=True,
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
        tried = {
            f"{item.get('target')}:{item.get('port')}" for item in results if isinstance(item, dict)
        }
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
        for dest in self._extra:
            where = dest.split(":", 2)[2]
            if where not in tried:
                problems.append(f"{dest} was not probed")
        if doc.get("contained") is not True or result.returncode != 0:
            problems.append(f"probe verdict: contained={doc.get('contained')!r}")
        problems = list(dict.fromkeys(problems))
        return ProbeRecord(run_id, not problems, doc, tuple(problems), breach=bool(problems))


class ContainmentGate:
    """A :class:`CellBackend` that probes a cell's containment before its agent starts.

    Everything is delegated to ``inner``; :meth:`start_agent` first runs ``probe`` (for
    the first ``limit`` cells, all if ``None``) and raises :class:`CellError` if the cell
    is not proven contained, so the agent never starts there and the runner tears it
    down.
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
                    "selftest: cell of run %s is NOT proven contained: %s",
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


# --------------------------------------------------------------------------- control plane


def control_plane_destinations(
    run: CommandRunner,
    compose_file: Path,
    *,
    docker: str = "docker",
    project: str = CONTROL_PLANE_PROJECT,
) -> list[str]:
    """Must-fail probe destinations for the running control plane.

    From ``compose_file``: the control network's subnet and each service's published
    ports (``host:host_port:container_port``). From the engine: the address of each
    published service's container on that network. Gives ``host:tcp:<container>:<port>``
    for every container port and ``host:tcp:<network gateway>:<host port>`` for every
    published port. Raises :class:`SelftestConfigError` if a published service has no
    running container there.
    """
    try:
        doc = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
        nets = doc["networks"]
        subnets = [
            ipaddress.ip_network(cfg["subnet"])
            for net in nets.values()
            for cfg in (net.get("ipam") or {}).get("config") or []
        ]
        published: dict[str, list[tuple[int, int]]] = {}
        for name, service in doc["services"].items():
            for spec in service.get("ports") or []:
                parts = str(spec).split(":")
                published.setdefault(name, []).append((int(parts[-2]), int(parts[-1])))
    except (OSError, yaml.YAMLError, KeyError, TypeError, ValueError, IndexError) as exc:
        raise SelftestConfigError(f"cannot read {compose_file}: {exc!r}") from exc
    if not subnets:
        raise SelftestConfigError(f"{compose_file}: the control network has no subnet")
    dests: list[str] = []
    for net in subnets:
        dests += [
            f"host:tcp:{next(net.hosts())}:{host_port}"
            for ports in published.values()
            for host_port, _ in ports
        ]
    for service, ports in sorted(published.items()):
        listing = run(
            [
                docker,
                "ps",
                "-q",
                "--filter",
                f"label=com.docker.compose.project={project}",
                "--filter",
                f"label=com.docker.compose.service={service}",
            ]
        )
        ids = listing.text.split()
        if listing.returncode != 0 or not ids:
            raise SelftestConfigError(
                f"the control plane's {service} is not running (compose project {project})"
            )
        inspected = run([docker, "inspect", *ids])
        try:
            containers = json.loads(inspected.stdout or b"[]")
        except ValueError:
            containers = []
        addresses = sorted(
            {
                str(ep.get("IPAddress"))
                for c in containers
                for ep in ((c.get("NetworkSettings") or {}).get("Networks") or {}).values()
                if ep.get("IPAddress")
                and any(ipaddress.ip_address(ep["IPAddress"]) in net for net in subnets)
            }
        )
        if inspected.returncode != 0 or not addresses:
            raise SelftestConfigError(f"no address of the control plane's {service} found")
        dests += [f"host:tcp:{addr}:{port}" for addr in addresses for _, port in ports]
    return list(dict.fromkeys(dests))


# --------------------------------------------------------------------------- cell resources


class CellResources(Protocol):
    """What is still on the engine for a run, and removing it (the sweep)."""

    def leftovers(self, run_id: str) -> dict[str, list[str]]: ...
    def labelled_run_ids(self) -> set[str]: ...
    def remove(self, run_id: str) -> dict[str, list[str]]: ...


class DockerLeftovers:
    """Containers, volumes and networks labelled with a run (a failed listing is
    reported as a leftover, never as "none")."""

    _KINDS: Final = (
        ("containers", ["ps", "-a"], '{{.Label "lab.run_id"}}'),
        ("volumes", ["volume", "ls"], '{{.Label "lab.run_id"}}'),
        ("networks", ["network", "ls"], '{{.Label "lab.run_id"}}'),
    )

    def __init__(self, run: CommandRunner, *, docker: str = "docker") -> None:
        self._run = run
        self._docker = docker

    def leftovers(self, run_id: str) -> dict[str, list[str]]:
        label = f"label={RUN_LABEL}={run_id}"
        left: dict[str, list[str]] = {}
        for kind, argv, _ in self._KINDS:
            result = self._run([self._docker, *argv, "-q", "--filter", label])
            if result.returncode != 0:
                left[kind] = [f"listing failed (exit {result.returncode})"]
            elif words := result.text.split():
                left[kind] = words
        return left

    def labelled_run_ids(self) -> set[str]:
        ids: set[str] = set()
        for kind, argv, fmt in self._KINDS:
            result = self._run(
                [self._docker, *argv, "--filter", f"label={RUN_LABEL}", "--format", fmt]
            )
            if result.returncode != 0:
                raise SelftestConfigError(f"cannot list labelled {kind} (exit {result.returncode})")
            ids.update(word for word in result.text.split() if word)
        return ids

    def remove(self, run_id: str) -> dict[str, list[str]]:
        left = self.leftovers(run_id)
        if containers := left.get("containers"):
            self._run([self._docker, "rm", "-f", "-v", *containers])
        if volumes := self.leftovers(run_id).get("volumes"):
            self._run([self._docker, "volume", "rm", "-f", *volumes])
        if networks := self.leftovers(run_id).get("networks"):
            self._run([self._docker, "network", "rm", *networks])
        return self.leftovers(run_id)


# --------------------------------------------------------------------------- the self-test


@dataclass(slots=True)
class SelftestDeps:
    """Everything the self-test talks to (fakes in tests, the lab's on the host)."""

    engine: Engine
    collector: CollectorClient
    backend: CellBackend
    probe: ContainmentProbe
    resources: CellResources
    settings: CellSettings
    lab_key: bytes = field(repr=False)
    runs_dir: Path
    work_dir: Path
    lock_path: Path
    templates_root: Path = REPO_ROOT
    #: extra Runner keyword arguments (tests: no sleeping)
    runner_options: Mapping[str, Any] = field(default_factory=dict)


def _cell_dir(work_dir: Path, run_id: str) -> Path:
    return work_dir / f"{CELL_NAME_PREFIX}{run_id.lower()}"


def run_selftest(
    deps: SelftestDeps, *, quick: bool, clock: Callable[[], float] = time.time
) -> SelftestReport:
    """Run the self-test pair under the host lock and check it; never raises."""
    started = clock()
    try:
        ef = derive_experiment(deps.templates_root / SELFTEST_EXPERIMENT, quick=quick)
    except (OSError, ValueError) as exc:
        return failed_report(quick, "experiment", str(exc)[:300], started_at=started)
    experiment_id = ef.experiment.experiment_id
    gate = ContainmentGate(deps.backend, deps.probe, limit=1 if quick else None)
    checks: list[Check] = []
    results: list[RunResult] = []
    try:
        with host_lock(deps.lock_path):
            checks.append(_sweep_earlier(deps))
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
            try:
                results = runner.run_experiment(ef)
            except CellLeftBehindError as exc:
                results = list(exc.results)
                checks.append(Check("run the pair", False, f"stopped: {exc}"[:500]))
            checks += _check_results(deps, ef, results, gate.records, quick=quick)
    except HostLockError as exc:
        checks.append(Check("run the pair", False, f"another runner is active: {exc}"))
    except Exception as exc:
        log.exception("selftest: failed")
        checks.append(Check("run the pair", False, f"{type(exc).__name__}: {str(exc)[:300]}"))
    try:
        runs = tuple(_run_summary(deps.engine, r) for r in results)
    except Exception as exc:
        log.exception("selftest: cannot summarise the runs")
        runs = tuple(
            {"run_id": r.run_id, "arm": r.arm.value, "status": r.status.value} for r in results
        )
        checks.append(Check("summarise runs", False, f"{type(exc).__name__}: {exc}"[:300]))
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


def _sweep_earlier(deps: SelftestDeps) -> Check:
    """Remove what earlier self-tests left (never a study run's resources)."""
    try:
        labelled = deps.resources.labelled_run_ids()
    except Exception as exc:
        return Check("earlier self-tests swept", False, f"cannot list: {exc}"[:300])
    with session_scope(deps.engine) as s:
        selftest_runs = set(
            s.scalars(
                select(t.Run.run_id).where(
                    t.Run.experiment_id.startswith(SELFTEST_EXPERIMENT_PREFIX, autoescape=True)
                )
            ).all()
        )
        stale_dirs = (
            [
                d
                for d in deps.work_dir.iterdir()
                if d.is_dir() and d.name.startswith(CELL_NAME_PREFIX)
            ]
            if deps.work_dir.is_dir()
            else []
        )
        by_dir = {
            _cell_dir(deps.work_dir, run_id).name: run_id
            for run_id in s.scalars(
                select(t.Run.run_id).where(
                    t.Run.experiment_id.startswith(SELFTEST_EXPERIMENT_PREFIX, autoescape=True),
                    func.lower(t.Run.run_id).in_(
                        [d.name.removeprefix(CELL_NAME_PREFIX) for d in stale_dirs]
                    ),
                )
            ).all()
        }
    removed: list[str] = []
    left: dict[str, Any] = {}
    for run_id in sorted(labelled & selftest_runs):
        remaining = deps.resources.remove(run_id)
        removed.append(run_id)
        if remaining:
            left[run_id] = remaining
    for directory in stale_dirs:
        if directory.name in by_dir:
            shutil.rmtree(directory, ignore_errors=True)
            if directory.exists():
                left[str(directory)] = "not removed"
            elif by_dir[directory.name] not in removed:
                removed.append(by_dir[directory.name])
    if removed:
        log.warning("selftest: swept what earlier self-tests left: %s", removed)
    detail = f"removed resources of {len(removed)} earlier self-test runs" if removed else ""
    if left:
        return Check("earlier self-tests swept", False, f"still there: {json.dumps(left)[:300]}")
    return Check("earlier self-tests swept", True, detail)


def _labels(engine: Engine, run_id: str) -> dict[FunnelStage, bool]:
    with session_scope(engine) as s:
        rows = s.scalars(select(t.Label).where(t.Label.run_id == run_id)).all()
        return {row.stage: row.value for row in rows}


def _stored_verdict(engine: Engine, run_id: str) -> tuple[bool | None, Any]:
    with session_scope(engine) as s:
        row = s.get(t.Run, run_id)
        return (None, None) if row is None else (row.outcome, row.decided_at)


def _run_summary(engine: Engine, result: RunResult) -> dict[str, Any]:
    outcome, decided_at = _stored_verdict(engine, result.run_id)
    return {
        "run_id": result.run_id,
        "arm": result.arm.value,
        "status": result.status.value,
        "reason": result.reason.value if result.reason else None,
        "end_status": result.end_status.value if result.end_status else None,
        "outcome": outcome,
        "decided_at": None if decided_at is None else str(decided_at),
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
        rows = s.scalars(
            select(t.Run).where(t.Run.experiment_id == ef.experiment.experiment_id)
        ).all()
        injected_ids = [row.run_id for row in rows if row.arm is Arm.INJECTED]
        needles = {row.tag for row in rows if row.tag}
        needles |= set(
            s.scalars(select(t.Placement.token).where(t.Placement.run_id.in_(injected_ids))).all()
        )
    probed = {p.run_id: p for p in probes}
    for result in results:
        name = result.arm.value
        valid = result.status is RunStatus.VALID
        detail = "" if valid else f"{result.status.value} ({result.reason}): {result.detail[:300]}"
        checks.append(Check(f"{name}: valid", valid, detail))
        completed = result.end_status is EndStatus.COMPLETED
        checks.append(
            Check(
                f"{name}: completed",
                completed,
                "" if completed else f"agent end status {result.end_status or 'none'}",
            )
        )
        labels = _labels(deps.engine, result.run_id)
        outcome, decided_at = _stored_verdict(deps.engine, result.run_id)
        if result.arm is Arm.INJECTED:
            checks.append(_funnel_check(name, labels, want_true=tuple(FunnelStage)))
            ok = outcome is True and decided_at is not None
            checks.append(
                Check(
                    f"{name}: oracle", ok, "" if ok else f"stored verdict {outcome}, {decided_at}"
                )
            )
            checks.append(_callback_check(deps, result.run_id))
        else:
            checks.append(
                _funnel_check(
                    name,
                    labels,
                    want_false=(FunnelStage.ACCESS, FunnelStage.VISIBLE, FunnelStage.UPTAKE),
                )
            )
            ok = outcome is not None and decided_at is not None
            checks.append(Check(f"{name}: oracle", ok, "" if ok else "no stored verdict"))
            checks.append(_control_clean(deps, result.run_id, needles))
        record = probed.get(result.run_id)
        if record is not None:
            checks.append(
                Check(
                    f"{name}: contained",
                    record.contained,
                    "; ".join(record.problems)[:500],
                    critical=record.breach,
                )
            )
        elif not quick:
            checks.append(
                Check(
                    f"{name}: contained",
                    False,
                    "not probed: the cell failed before its agent would start",
                )
            )
        left: dict[str, Any] = dict(deps.resources.leftovers(result.run_id))
        cell_dir = _cell_dir(deps.work_dir, result.run_id)
        if cell_dir.exists():
            left["work_dir"] = [str(cell_dir)]
        checks.append(
            Check(f"{name}: nothing left", not left, "" if not left else json.dumps(left)[:300])
        )
    if quick and not probes:
        checks.append(
            Check("contained", False, "not probed: the first cell failed before its agent")
        )
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


def _b64_values(node: Any) -> Iterator[str]:
    """Every string under a key ending in ``_b64`` (any depth)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and key.endswith("_b64") and isinstance(value, str):
                yield value
            else:
                yield from _b64_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from _b64_values(item)


def _holds(data: bytes, needles: Iterable[bytes]) -> bool:
    """True if ``data`` (case-folded) or a decoded base64 field in it holds a needle."""
    needles = list(needles)
    if any(n in data.lower() for n in needles):
        return True
    if len(data) > _MAX_JSON_SCAN_BYTES:
        return False
    for line in data.splitlines():
        if b"_b64" not in line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        for value in _b64_values(doc):
            try:
                decoded = base64.b64decode(value, validate=True).lower()
            except (binascii.Error, ValueError):
                continue
            if any(n in decoded for n in needles):
                return True
    return False


def _control_clean(deps: SelftestDeps, run_id: str, needles: set[str]) -> Check:
    problems: list[str] = []
    with session_scope(deps.engine) as s:
        tokened = [
            c.channel.value
            for c in s.scalars(select(t.Callback).where(t.Callback.run_id == run_id)).all()
            if c.token
        ]
    if tokened:
        problems.append(f"token callbacks reached the control: {sorted(set(tokened))}")
    wanted = [n.lower().encode() for n in needles]
    evidence = deps.runs_dir / run_id
    if not evidence.is_dir():
        problems.append("no evidence directory")
    leaked = sorted(
        str(path.relative_to(evidence))
        for path in _files(evidence)
        if _holds(path.read_bytes(), wanted)
    )
    if leaked:
        problems.append(
            f"an injected tag or token is in {len(leaked)} evidence files: {leaked[:5]}"
        )
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
    #: is an address one of this host's own (tests replace it)
    is_local: Callable[[str], bool] = is_local_address
    #: does a LAN address answer from this host (tests replace it)
    lan_answers: Callable[[str], bool] = lan_answers


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


def _release_tree(lab_root: Path, environ: Mapping[str, str]) -> Path:
    """The release tree, resolved once (``current`` is a symlink a deploy may swap)."""
    if tree := environ.get("LAB_RELEASE_TREE"):
        return Path(tree).resolve(strict=False)
    current = lab_root / "current"
    if (current / SELFTEST_EXPERIMENT).is_file():
        return current.resolve(strict=True)
    return REPO_ROOT.resolve()  # a development checkout


def _probe_lan(environ: Mapping[str, str], settings: CellSettings) -> list[str]:
    """``LAB_PROBE_LAN``: from the host profile in production, the environment in dev."""
    if settings.dev:
        raw = environ.get("LAB_PROBE_LAN", "")
        where = "the environment (LAB_DEV=1)"
    else:
        path = Path(environ.get("LAB_HOST_ENV") or HOST_ENV_FILE)
        try:
            raw = read_host_env(path).get("LAB_PROBE_LAN", "")
        except (OSError, CellError) as exc:
            raise SelftestConfigError(f"cannot read the host profile {path}: {exc}") from exc
        where = str(path)
        if environ.get("LAB_PROBE_LAN") not in (None, raw):
            log.warning("selftest: LAB_PROBE_LAN in the environment is ignored (production)")
    lan = [part.strip() for part in raw.split(",") if part.strip()]
    if not lan:
        raise SelftestConfigError(
            f"no home-LAN address for the containment probe: set LAB_PROBE_LAN in {where}"
        )
    for addr in lan:
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            raise SelftestConfigError(f"LAB_PROBE_LAN: {addr!r} is not an IP address") from None
    return lan


def _host_gateway_override(
    environ: Mapping[str, str], settings: CellSettings, is_local: Callable[[str], bool]
) -> str | None:
    value = environ.get("LAB_PROBE_HOST_GATEWAY", "").strip()
    if not value:
        return None
    if not (settings.dev and settings.engine is CellEngine.PODMAN):
        raise SelftestConfigError(
            "LAB_PROBE_HOST_GATEWAY is for development on Podman only (LAB_DEV=1, "
            "LAB_ENGINE=podman)"
        )
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise SelftestConfigError(f"LAB_PROBE_HOST_GATEWAY: {value!r} is not an IP") from None
    if not is_local(value):
        raise SelftestConfigError(f"LAB_PROBE_HOST_GATEWAY {value} is not an address of this host")
    log.warning("selftest: development: probing %s as the host, not the cell gateway", value)
    return value


def _cell_env(environ: Mapping[str, str], tree: Path) -> dict[str, str]:
    """The runner's environment: in production the tree's images.lock, no overrides."""
    env = dict(environ)
    lock = str(tree / "deploy" / "images.lock")
    if env.get("LAB_DEV") == "1":
        env.setdefault("LAB_IMAGES_LOCK", lock)
        return env
    for key in ("LAB_IMAGES_LOCK", "LAB_IMAGE_OVERRIDES"):
        if env.get(key):
            log.warning("selftest: %s is ignored outside development", key)
    env.pop("LAB_IMAGE_OVERRIDES", None)
    env["LAB_IMAGES_LOCK"] = lock
    return env


@contextlib.contextmanager
def _lab_deps(context: LabContext) -> Iterator[SelftestDeps]:
    environ, lab_root = context.environ, context.lab_root
    lab_key = _lab_key(lab_root)
    tree = _release_tree(lab_root, environ)
    try:
        settings = CellSettings.from_env(_cell_env(environ, tree))
        probe_image = settings.image("lab-cell")
    except CellError as exc:
        raise SelftestConfigError(str(exc)) from exc
    lan = _probe_lan(environ, settings)
    silent = [addr for addr in lan if not context.lan_answers(addr)]
    if silent:
        raise SelftestConfigError(
            f"LAB_PROBE_LAN {silent} does not answer from this host, so a blocked result "
            "from a cell would prove nothing"
        )
    host_gateway = _host_gateway_override(environ, settings, context.is_local)
    docker_env = {k: environ[k] for k in ("DOCKER_HOST",) if k in environ}
    commands = SubprocessRunner(docker_env)
    extra: list[str] = []
    try:
        extra += control_plane_destinations(commands, tree / CONTROL_PLANE_FILE)
    except SelftestConfigError as exc:
        if not settings.dev:
            raise
        log.warning("selftest: development: no control-plane destinations (%s)", exc)
    own = own_address_towards(lan[0])
    if own is None or not context.is_local(own):
        raise SelftestConfigError(f"cannot find this host's own address towards {lan[0]}")
    extra += [f"host:tcp:{own}:{port}" for port in HOST_PORTS]
    work_dir = lab_root / "cells"
    with httpx.Client(base_url=context.collector_url, timeout=60.0) as http:
        yield SelftestDeps(
            engine=context.engine,
            collector=CollectorClient(http),
            backend=ComposeBackend(commands),
            probe=DockerContainmentProbe(
                commands,
                image=probe_image,
                lan=lan,
                host_gateway=host_gateway,
                extra_destinations=extra,
                is_local=context.is_local,
            ),
            resources=DockerLeftovers(commands),
            settings=settings,
            lab_key=lab_key,
            runs_dir=lab_root / "artifacts",
            work_dir=work_dir,
            lock_path=runner_lock_path(environ, dev=settings.dev, work_dir=work_dir),
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
    except Exception as exc:
        log.exception("selftest: internal error")
        return failed_report(
            quick, "internal", f"{type(exc).__name__}: {str(exc)[:300]}", started_at=started
        )
