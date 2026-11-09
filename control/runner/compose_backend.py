"""Run cells with ``docker compose`` (the :class:`CellBackend` of the LXC profile).

The runner talks to cells only through this interface, and this backend only through
the Docker CLI (Docker, or Podman's Docker-compatible socket via ``DOCKER_HOST``): it
never opens a network connection into a cell. Per-run inputs go in through the archive
API (``docker cp`` into the created, never started ``secrets-writer``); probes and
oracle polls run with ``docker compose exec``; evidence comes out with ``docker cp``
from the stopped containers, as a tar stream unpacked by :func:`extract_evidence`,
which keeps only regular files below each producer's own directory.

Lifecycle (:class:`ComposeBackend`):

1. :meth:`~ComposeBackend.prepare` writes the project file (0600) and returns the
   handle the runner keeps; :meth:`~ComposeBackend.up` creates the scratch volume (if
   any, labelled), creates the writer, copies the per-run files into its volumes
   (canaries root-only 0400), removes it and starts every infrastructure service (not
   the agent). Any failure in ``up`` tears the cell down before it is re-raised;
2. :meth:`~ComposeBackend.health` / :meth:`~ComposeBackend.exec`: the target's
   ``/opt/support/health.sh`` and ``/opt/support/done.sh`` and the injector's
   pre-flight probe, by exec only;
3. :meth:`~ComposeBackend.start_agent`, :meth:`~ComposeBackend.state`,
   :meth:`~ComposeBackend.kill_agent`;
4. :meth:`~ComposeBackend.stop` then :meth:`~ComposeBackend.collect` (the tap drains
   on its own SIGTERM before its evidence is read);
5. :meth:`~ComposeBackend.teardown`: containers Compose does not manage (cell-guard's)
   first, then ``compose down -v``, then every container, volume and network labelled
   ``lab.run_id=<run>`` and the scratch volume; judged by listing them again; the
   project file is deleted.
"""

from __future__ import annotations

import io
import ipaddress
import json
import logging
import os
import re
import subprocess
import tarfile
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Final, Protocol

from control.core.models import ARTIFACT_PATH_PATTERN
from control.runner.cell_spec import (
    DEFAULT_EVIDENCE_PATH,
    RUN_LABEL,
    CellError,
    CellFile,
    ComposeProject,
)

log = logging.getLogger(__name__)

__all__ = [
    "MAX_EVIDENCE_BYTES",
    "CellBackend",
    "CellHandle",
    "CollectReport",
    "CommandResult",
    "CommandRunner",
    "ComposeBackend",
    "ContainerState",
    "SubprocessRunner",
    "extract_evidence",
    "files_tar",
]

#: Most bytes the runner unpacks from one service's evidence (the rest is refused).
MAX_EVIDENCE_BYTES: Final = 2 * 1024**3
_ARTIFACT_RE = re.compile(ARTIFACT_PATH_PATTERN)
_DEFAULT_TIMEOUT_S: Final = 300.0
#: Where the writer mounts each per-run volume: ``/w/<volume>`` (cell file).
WRITER_ROOT: Final = "w"


# --------------------------------------------------------------------------- commands


@dataclass(frozen=True, slots=True)
class CommandResult:
    argv: tuple[str, ...]
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""

    @property
    def text(self) -> str:
        return self.stdout.decode("utf-8", "replace")


class CommandRunner(Protocol):
    def __call__(
        self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult: ...


class SubprocessRunner:
    """Runs commands with :mod:`subprocess` (no shell), with an optional extra env."""

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self._env = {**os.environ, **(env or {})}

    def __call__(
        self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell
                list(argv),
                input=stdin,
                capture_output=True,
                timeout=timeout or _DEFAULT_TIMEOUT_S,
                env=self._env,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            return CommandResult(tuple(argv), 124, exc.stdout or b"", exc.stderr or b"timeout")
        return CommandResult(tuple(argv), proc.returncode, proc.stdout, proc.stderr)


# --------------------------------------------------------------------------- files in, evidence out


def files_tar(files: Iterable[CellFile]) -> bytes:
    """A tar of regular files named by ``name`` with each file's mode and owner.

    Unpacked into one volume's mount point in the writer (``/w/<volume>``): a copy
    to the mount point itself lands in the volume on Docker and Podman alike, while
    one through ``/`` would land in the container's own filesystem on Podman.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for f in files:
            info = tarfile.TarInfo(f.name)
            info.size, info.mode, info.uid, info.gid = len(f.content), f.mode, f.uid, f.gid
            info.mtime = int(time.time())
            tar.addfile(info, io.BytesIO(f.content))
    return buf.getvalue()


@dataclass(slots=True)
class CollectReport:
    """What :func:`extract_evidence` kept and what it refused (never silently dropped)."""

    files: list[str] = field(default_factory=list)
    refused: list[str] = field(default_factory=list)


def extract_evidence(
    data: bytes, dest: Path, prefix: str, report: CollectReport, *, root: str = "evidence"
) -> None:
    """Unpack a ``docker cp <ctr>:/evidence -`` stream into ``dest``, defensively.

    Kept: regular files and directories under ``<prefix>/`` whose every path segment
    is a valid artifact segment, within :data:`MAX_EVIDENCE_BYTES`. Refused (and
    listed in ``report.refused``): links, devices, FIFOs, names outside ``prefix``,
    hidden or odd names, ``..``, and anything after the size cap. Never overwrites.
    """
    total = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as tar:
        for member in tar:
            # Docker names members evidence/..., Podman /...; both mean the same tree
            parts = [p for p in PurePosixPath(member.name).parts if p not in ("/", ".")]
            if parts and parts[0] == root:
                parts = parts[1:]
            rel = "/".join(parts)
            if not rel:
                continue
            if member.isdir():
                own = rel == prefix or rel.startswith(prefix + "/")
                if own and _ARTIFACT_RE.fullmatch(rel):
                    (dest / rel).mkdir(parents=True, exist_ok=True)
                else:
                    report.refused.append(f"{rel} (directory)")
                continue
            ok = (
                member.isreg()
                and rel.startswith(prefix + "/")
                and _ARTIFACT_RE.fullmatch(rel) is not None
                and total + member.size <= MAX_EVIDENCE_BYTES
            )
            if not ok:
                kind = "file" if member.isreg() else "special"
                report.refused.append(f"{rel} ({kind}, {member.size} bytes)")
                continue
            source = tar.extractfile(member)
            if source is None:  # pragma: no cover - isreg() members always have data
                report.refused.append(f"{rel} (unreadable)")
                continue
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with source, target.open("xb") as out:
                while chunk := source.read(1024 * 1024):
                    out.write(chunk)
            total += member.size
            report.files.append(rel)


# --------------------------------------------------------------------------- backend


@dataclass(frozen=True, slots=True)
class ContainerState:
    """One container's state from its inspect document (``missing`` if it does not exist).

    ``created`` is *pending*, not running: a container that never leaves it never
    started, which is a cell failure, not an agent that ran out of time.
    """

    status: str
    exit_code: int | None = None
    #: times the engine restarted it (cell services use ``restart: "no"``: always 0)
    restart_count: int = 0

    @property
    def running(self) -> bool:
        return self.status in ("running", "restarting", "paused")

    @property
    def alive(self) -> bool:
        """Exactly ``running`` and never restarted: the liveness infrastructure needs."""
        return self.status == "running" and self.restart_count == 0

    @property
    def pending(self) -> bool:
        return self.status in ("created", "starting")

    @property
    def ended(self) -> bool:
        return self.status in ("exited", "dead")


@dataclass(frozen=True, slots=True)
class CellHandle:
    """A cell: its project and the Compose file :meth:`CellBackend.prepare` wrote."""

    project: ComposeProject
    compose_file: Path


class CellBackend(Protocol):
    """How the runner provisions, inspects and destroys a cell.

    :meth:`prepare` only writes the project file; the runner holds the handle from then
    on, so :meth:`teardown` runs whatever happens in :meth:`up` (which also tears down
    by itself before re-raising any failure).
    """

    def subnets_in_use(self) -> list[ipaddress.IPv4Network]: ...
    def prepare(self, project: ComposeProject, workdir: Path) -> CellHandle: ...
    def up(self, cell: CellHandle) -> None: ...
    def health(self, cell: CellHandle, *, timeout_s: float) -> bool: ...
    def exec(
        self, cell: CellHandle, service: str, argv: Sequence[str], *, timeout_s: float
    ) -> CommandResult: ...
    def start_agent(self, cell: CellHandle) -> None: ...
    def state(self, cell: CellHandle, service: str) -> ContainerState: ...
    def kill_agent(self, cell: CellHandle) -> None: ...
    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None: ...
    def logs(self, cell: CellHandle, service: str) -> str: ...
    def collect(
        self, cell: CellHandle, dest: Path, services: Sequence[str] | None = None
    ) -> CollectReport: ...
    def teardown(self, cell: CellHandle) -> None: ...


HEALTH_COMMAND: Final = ("/opt/support/health.sh",)


class ComposeBackend:
    """:class:`CellBackend` on ``docker compose`` through a :class:`CommandRunner`."""

    def __init__(
        self,
        runner: CommandRunner | None = None,
        *,
        docker: str = "docker",
        health_interval_s: float = 2.0,
    ) -> None:
        self._run = runner or SubprocessRunner()
        self._docker = docker
        self._health_interval_s = health_interval_s
        #: scratch volumes this backend created (only those are removed by name)
        self._scratch_created: set[str] = set()

    # helpers

    def _compose(self, cell: CellHandle, *args: str) -> list[str]:
        return [
            self._docker,
            "compose",
            "-p",
            cell.project.name,
            "-f",
            str(cell.compose_file),
            "--profile",
            "setup",
            *args,
        ]

    def _must(
        self, argv: Sequence[str], *, stdin: bytes | None = None, timeout: float | None = None
    ) -> CommandResult:
        result = self._run(argv, stdin=stdin, timeout=timeout)
        if result.returncode != 0:
            err = result.stderr.decode("utf-8", "replace").strip()[-2000:]
            raise CellError(f"{' '.join(argv[:6])}...: exit {result.returncode}: {err}")
        return result

    def _container(self, cell: CellHandle, service: str) -> str | None:
        out = self._must(self._compose(cell, "ps", "-a", "-q", service)).text.split()
        return out[0] if out else None

    # CellBackend

    def subnets_in_use(self) -> list[ipaddress.IPv4Network]:
        ids = self._must([self._docker, "network", "ls", "-q"]).text.split()
        if not ids:
            return []
        doc = json.loads(self._must([self._docker, "network", "inspect", *ids]).stdout or b"[]")
        nets: list[ipaddress.IPv4Network] = []
        for net in doc:
            for cfg in (net.get("IPAM") or {}).get("Config") or []:
                try:
                    subnet = ipaddress.ip_network(cfg.get("Subnet", ""), strict=False)
                except ValueError:
                    continue
                if isinstance(subnet, ipaddress.IPv4Network):
                    nets.append(subnet)
        return nets

    def prepare(self, project: ComposeProject, workdir: Path) -> CellHandle:
        """Write the project file (0600; it holds the probe secret). Nothing else."""
        cell_dir = workdir / project.name
        cell_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        compose_file = cell_dir / "compose.yml"
        fd = os.open(compose_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(project.to_yaml())
        return CellHandle(project, compose_file)

    def up(self, cell: CellHandle) -> None:
        """Create the cell and start its infrastructure; on any failure tear it down.

        A scratch volume of the same name that already exists is refused before anything
        is created (``volume create`` would silently reuse it, unlabelled, with someone
        else's contents), and is then not this cell's to remove.
        """
        scratch = cell.project.scratch_volume
        if scratch is not None and self._volume_exists(scratch):
            raise CellError(f"{cell.project.name}: scratch volume {scratch} already exists")
        try:
            self._up(cell)
        except BaseException:
            try:
                self.teardown(cell)
            except Exception:  # the original failure is the one to report
                log.exception("%s: teardown after a failed up also failed", cell.project.name)
            raise

    def _up(self, cell: CellHandle) -> None:
        project = cell.project
        if project.scratch_volume is not None:
            # Created here, labelled, so teardown always finds it: Compose would never
            # create it (no service mounts it) and cell-guard would create it unlabelled.
            label = f"{RUN_LABEL}={project.run_id}"
            self._must([self._docker, "volume", "create", "--label", label, project.scratch_volume])
            self._scratch_created.add(project.scratch_volume)
        self._must(self._compose(cell, "create", project.writer_service))
        writer = self._container(cell, project.writer_service)
        if writer is None:
            raise CellError(f"{project.name}: the secrets writer was not created")
        by_volume: dict[str, list[CellFile]] = {}
        for f in project.files:
            by_volume.setdefault(f.volume, []).append(f)
        for volume, files in by_volume.items():
            self._must(
                [self._docker, "cp", "-", f"{writer}:/{WRITER_ROOT}/{volume}"],
                stdin=files_tar(files),
            )
        self._must(self._compose(cell, "rm", "-f", "-s", project.writer_service))
        self._must(self._compose(cell, "up", "-d", "--no-build", *project.infra_services))

    def health(self, cell: CellHandle, *, timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        while True:
            result = self.exec(cell, cell.project.target_service, HEALTH_COMMAND, timeout_s=30)
            if result.returncode == 0:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(self._health_interval_s)

    def exec(
        self, cell: CellHandle, service: str, argv: Sequence[str], *, timeout_s: float
    ) -> CommandResult:
        return self._run(self._compose(cell, "exec", "-T", service, *argv), timeout=timeout_s)

    def start_agent(self, cell: CellHandle) -> None:
        self._must(
            self._compose(cell, "up", "-d", "--no-build", "--no-deps", cell.project.agent_service)
        )

    def state(self, cell: CellHandle, service: str) -> ContainerState:
        """The service's container state, exit code and restart count (``docker inspect``)."""
        container = self._container(cell, service)
        if container is None:
            return ContainerState("missing")
        docs = json.loads(self._must([self._docker, "container", "inspect", container]).stdout)
        doc = docs[0] if isinstance(docs, list) and docs else {}
        state = doc.get("State") or {}
        code = state.get("ExitCode")
        restarts = doc.get("RestartCount", 0)
        return ContainerState(
            str(state.get("Status", "")).lower() or "unknown",
            int(code) if isinstance(code, int) else None,
            int(restarts) if isinstance(restarts, int) else 0,
        )

    def kill_agent(self, cell: CellHandle) -> None:
        self._run(self._compose(cell, "kill", cell.project.agent_service))

    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None:
        self._must(self._compose(cell, "stop", "-t", str(timeout_s), *services))

    def logs(self, cell: CellHandle, service: str) -> str:
        """A service's logs; a failed read raises (it must never read as "no failure")."""
        return self._must(self._compose(cell, "logs", "--no-color", service)).text

    def collect(
        self, cell: CellHandle, dest: Path, services: Sequence[str] | None = None
    ) -> CollectReport:
        """Copy each evidence producer's files out (``services``: only these, e.g. not an
        agent that never started)."""
        report = CollectReport()
        dest.mkdir(parents=True, exist_ok=True)
        for service, prefix in cell.project.evidence.items():
            if services is not None and service not in services:
                continue
            source = cell.project.evidence_paths.get(service, DEFAULT_EVIDENCE_PATH)
            container = self._container(cell, service)
            if container is None:
                report.refused.append(f"{service}: no container")
                continue
            result = self._run([self._docker, "cp", f"{container}:{source}", "-"], timeout=600)
            if result.returncode != 0:
                report.refused.append(f"{service}: docker cp failed ({result.returncode})")
                continue
            extract_evidence(result.stdout, dest, prefix, report, root=PurePosixPath(source).name)
        return report

    def _volume_exists(self, name: str) -> bool:
        result = self._run([self._docker, "volume", "inspect", name])
        if result.returncode == 0:
            return True
        err = result.stderr.decode("utf-8", "replace").lower()
        if "no such volume" in err or "not found" in err or "no such object" in err:
            return False
        raise CellError(f"volume inspect {name}: exit {result.returncode}: {err[-300:]}")

    def _listed(self, argv: Sequence[str]) -> list[str]:
        """Output words of a listing; a failed listing is an error, never "empty"."""
        return self._must(argv).text.split()

    def teardown(self, cell: CellHandle) -> None:
        """Remove the cell and everything labelled with its run; verify by re-listing.

        Order: containers that Compose does not manage (cell-guard's, which would keep
        the agent network busy) first, with their anonymous volumes; then
        ``compose down -v``; then a sweep of every container, volume and network
        labelled ``lab.run_id=<run>`` and the scratch volume by name. Success is judged
        only by listing them again. The project file (it holds the probe secret) is
        deleted in every case.
        """
        project = cell.project
        label = f"label={RUN_LABEL}={project.run_id}"
        notes: list[str] = []
        try:
            listing = self._must(
                [
                    self._docker,
                    "ps",
                    "-a",
                    "--filter",
                    label,
                    "--format",
                    '{{.ID}} {{.Label "com.docker.compose.project"}}',
                ]
            ).text
            foreign = [
                parts[0]
                for parts in (line.split() for line in listing.splitlines())
                if parts and (len(parts) == 1 or parts[1] != project.name)
            ]
            if foreign:
                self._run([self._docker, "rm", "-f", "-v", *foreign])
            down = self._run(
                self._compose(cell, "down", "-v", "--remove-orphans", "-t", "10"), timeout=600
            )
            if down.returncode != 0:
                notes.append(f"down: {down.stderr.decode('utf-8', 'replace')[-300:]}")
            containers = self._listed([self._docker, "ps", "-a", "-q", "--filter", label])
            if containers:
                self._run([self._docker, "rm", "-f", "-v", *containers])
            volumes = self._listed([self._docker, "volume", "ls", "-q", "--filter", label])
            scratch = project.scratch_volume
            ours = scratch is not None and scratch in self._scratch_created
            if ours and scratch is not None:
                volumes.append(scratch)
            if volumes:
                self._run([self._docker, "volume", "rm", "-f", *sorted(set(volumes))])
            networks = self._listed([self._docker, "network", "ls", "-q", "--filter", label])
            if networks:
                self._run([self._docker, "network", "rm", *networks])
            left = {
                "containers": self._listed([self._docker, "ps", "-a", "-q", "--filter", label]),
                "volumes": self._listed([self._docker, "volume", "ls", "-q", "--filter", label]),
                "networks": self._listed([self._docker, "network", "ls", "-q", "--filter", label]),
            }
            if ours and scratch is not None:
                if self._volume_exists(scratch):
                    left["volumes"].append(scratch)
                else:
                    self._scratch_created.discard(scratch)
            remaining = {k: v for k, v in left.items() if v}
            if remaining:
                raise CellError(
                    f"{project.name}: teardown incomplete: {remaining} {'; '.join(notes)}"
                )
        finally:
            cell.compose_file.unlink(missing_ok=True)
