"""Run cells with ``docker compose`` (the :class:`CellBackend` of the LXC profile).

The runner talks to cells only through this interface, and this backend only through
the Docker CLI (Docker, or Podman's Docker-compatible socket via ``DOCKER_HOST``): it
never opens a network connection into a cell. Per-run inputs go in through the archive
API (``docker cp`` into the created, never started ``secrets-writer``); probes and
oracle polls run with ``docker compose exec``; evidence comes out with ``docker cp``
from the stopped containers, as a tar stream unpacked by :func:`extract_evidence`,
which keeps only regular files below each producer's own directory.

Lifecycle (:class:`ComposeBackend`):

1. :meth:`~ComposeBackend.up`: write the project file (0600), create the writer,
   copy the per-run files into its volumes (canaries root-only 0400), remove it, and
   start every infrastructure service (not the agent);
2. :meth:`~ComposeBackend.health` / :meth:`~ComposeBackend.exec`: the target's
   ``/opt/support/health.sh`` and ``/opt/support/done.sh`` and the injector's
   pre-flight probe, by exec only;
3. :meth:`~ComposeBackend.start_agent`, :meth:`~ComposeBackend.agent_state`,
   :meth:`~ComposeBackend.kill_agent`;
4. :meth:`~ComposeBackend.stop` then :meth:`~ComposeBackend.collect` (the tap drains
   on its own SIGTERM before its evidence is read);
5. :meth:`~ComposeBackend.teardown`: ``compose down -v``, then every container, volume
   and network labelled ``lab.run_id=<run>`` (cell-guard-created ones included), with
   the anonymous volumes of those containers.
"""

from __future__ import annotations

import io
import ipaddress
import json
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
from control.runner.cell_spec import RUN_LABEL, CellError, CellFile, ComposeProject

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


def extract_evidence(data: bytes, dest: Path, prefix: str, report: CollectReport) -> None:
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
            if parts and parts[0] == "evidence":
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
    """One container's state as Compose reports it (``missing`` if it does not exist)."""

    status: str
    exit_code: int | None = None

    @property
    def running(self) -> bool:
        return self.status in ("running", "restarting", "created", "starting")


@dataclass(frozen=True, slots=True)
class CellHandle:
    """A cell that :meth:`CellBackend.up` created."""

    project: ComposeProject
    compose_file: Path


class CellBackend(Protocol):
    """How the runner provisions, inspects and destroys a cell."""

    def subnets_in_use(self) -> list[ipaddress.IPv4Network]: ...
    def up(self, project: ComposeProject, workdir: Path) -> CellHandle: ...
    def health(self, cell: CellHandle, *, timeout_s: float) -> bool: ...
    def exec(
        self, cell: CellHandle, service: str, argv: Sequence[str], *, timeout_s: float
    ) -> CommandResult: ...
    def start_agent(self, cell: CellHandle) -> None: ...
    def agent_state(self, cell: CellHandle) -> ContainerState: ...
    def kill_agent(self, cell: CellHandle) -> None: ...
    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None: ...
    def logs(self, cell: CellHandle, service: str) -> str: ...
    def collect(self, cell: CellHandle, dest: Path) -> CollectReport: ...
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

    def up(self, project: ComposeProject, workdir: Path) -> CellHandle:
        cell_dir = workdir / project.name
        cell_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        compose_file = cell_dir / "compose.yml"
        fd = os.open(compose_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(project.to_yaml())
        cell = CellHandle(project, compose_file)
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
        return cell

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

    def agent_state(self, cell: CellHandle) -> ContainerState:
        result = self._must(
            self._compose(cell, "ps", "-a", "--format", "json", cell.project.agent_service)
        )
        for line in result.text.splitlines():
            line = line.strip()
            if not line:
                continue
            doc = json.loads(line)
            entries = doc if isinstance(doc, list) else [doc]
            for entry in entries:
                state = str(entry.get("State", "")).lower() or "unknown"
                code = entry.get("ExitCode")
                return ContainerState(state, int(code) if isinstance(code, int) else None)
        return ContainerState("missing")

    def kill_agent(self, cell: CellHandle) -> None:
        self._run(self._compose(cell, "kill", cell.project.agent_service))

    def stop(self, cell: CellHandle, services: Sequence[str], *, timeout_s: int) -> None:
        self._must(self._compose(cell, "stop", "-t", str(timeout_s), *services))

    def logs(self, cell: CellHandle, service: str) -> str:
        return self._run(self._compose(cell, "logs", "--no-color", service)).text

    def collect(self, cell: CellHandle, dest: Path) -> CollectReport:
        report = CollectReport()
        dest.mkdir(parents=True, exist_ok=True)
        for service, prefix in cell.project.evidence.items():
            container = self._container(cell, service)
            if container is None:
                report.refused.append(f"{service}: no container")
                continue
            result = self._run([self._docker, "cp", f"{container}:/evidence", "-"], timeout=600)
            if result.returncode != 0:
                report.refused.append(f"{service}: docker cp failed ({result.returncode})")
                continue
            extract_evidence(result.stdout, dest, prefix, report)
        return report

    def teardown(self, cell: CellHandle) -> None:
        errors: list[str] = []
        down = self._run(
            self._compose(cell, "down", "-v", "--remove-orphans", "-t", "10"), timeout=600
        )
        if down.returncode != 0:
            errors.append(down.stderr.decode("utf-8", "replace")[-500:])
        label = f"label={RUN_LABEL}={cell.project.run_id}"
        containers = self._run([self._docker, "ps", "-a", "-q", "--filter", label]).text.split()
        if containers:
            # -v: the anonymous volumes image VOLUMEs created for these containers too
            self._run([self._docker, "rm", "-f", "-v", *containers])
        for kind in ("volume", "network"):
            ids = self._run([self._docker, kind, "ls", "-q", "--filter", label]).text.split()
            if ids:
                removed = self._run(
                    [self._docker, kind, "rm", *([("-f")] if kind == "volume" else []), *ids]
                )
                if removed.returncode != 0:
                    errors.append(removed.stderr.decode("utf-8", "replace")[-500:])
        left = self._run([self._docker, "ps", "-a", "-q", "--filter", label]).text.split()
        if left:
            errors.append(f"containers left: {left}")
        if errors:
            raise CellError(f"{cell.project.name}: teardown incomplete: {'; '.join(errors)}")
