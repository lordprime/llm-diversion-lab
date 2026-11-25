"""Ollama on the lab host, reached only through the control plane.

Ollama runs as the ``ollama`` service of ``deploy/compose/models.yml`` on an internal
network with no published port, so nothing outside the stack can talk to it. This
module is how the lab host's own tools look at it and manage it:

* :class:`OllamaService` reads: which container, the GPU inside it, the pulled models
  with their full digests, and whether the container is exposed anywhere it should
  not be. ``labctl doctor`` uses it; it changes nothing.
* :class:`OllamaAdmin` adds ``pull`` and ``remove`` and gates every action: it refuses
  inside a container (so a run cell can never use it), without root, and for a pull
  while any run cell is in flight. Pulling is never part of a run.

Everything goes through ``docker`` on the host (``docker exec`` into the running
container); no Ollama port is ever opened for this. The registry is on the internet
and the ``models`` network is internal, so a pull attaches the container to a
throwaway uplink network for the duration of the pull and detaches it again, whatever
happens. If it cannot detach, the error says exactly what to run by hand.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import signal
import subprocess
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network
from pathlib import Path
from typing import Any, Final

from control.runner.compose_backend import CommandResult, CommandRunner

__all__ = [
    "CONTAINER_MARKERS",
    "DEFAULT_LOCK_PATH",
    "MODEL_ID_PATTERN",
    "OLLAMA_PORT",
    "OLLAMA_SERVICE",
    "UPLINK_LABEL",
    "UPLINK_NETWORK",
    "ModelsError",
    "OllamaAdmin",
    "OllamaService",
    "PulledModel",
]

COMPOSE_PROJECT: Final = "lab"
OLLAMA_SERVICE: Final = "ollama"
OLLAMA_PORT: Final = 11434
#: The only services that may share the models network with Ollama.
NETWORK_MEMBERS: Final = frozenset({"ollama", "gateway"})
#: The throwaway network a pull attaches Ollama to, so it can reach the registry.
UPLINK_NETWORK: Final = "lab-ollama-uplink"
UPLINK_LABEL: Final = "lab.role=ollama-uplink"
#: Held (exclusive, non-blocking) for the whole of a pull or removal.
DEFAULT_LOCK_PATH: Final = Path("/run/lab/ollama-models.lock")
#: Files that exist only inside a container (Docker, Podman).
CONTAINER_MARKERS: Final = (Path("/.dockerenv"), Path("/run/.containerenv"))
#: ``name[:tag]`` as the Ollama registry writes it; ``/`` and ``.`` allow namespaces
#: and hosts (``library/gemma3:27b``, ``hf.co/user/model:Q4_K_M``). Never starts with
#: ``-`` and never holds spaces, shell characters or ``..``.
MODEL_ID_PATTERN: Final = re.compile(
    r"(?!.*\.\.)(?!.*//)[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?"
)
_MAX_ID: Final = 200
_DIGEST: Final = re.compile(r"(?:sha256:)?([0-9a-f]{64})")
#: One HTTP/1.0 GET over bash's /dev/tcp: the Ollama image has bash but no curl.
_TAGS_SCRIPT: Final = (
    f"exec 3<>/dev/tcp/127.0.0.1/{OLLAMA_PORT} && "
    "printf 'GET /api/tags HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' >&3 && cat <&3"
)
_QUICK_TIMEOUT_S: Final = 60.0


class ModelsError(RuntimeError):
    """A models command cannot or must not run (the message is for the operator)."""


class UplinkInUse(ModelsError):
    """The uplink network is there and is not ours to touch (a crashed pull's, another
    operation's, or not the Ollama uplink at all): nothing is cleaned up for it."""


@dataclass(frozen=True, slots=True)
class PulledModel:
    name: str
    #: ``sha256:<64 hex>``: the manifest digest an experiment file pins
    digest: str
    size_bytes: int

    def to_json(self) -> dict[str, Any]:
        return {"name": self.name, "digest": self.digest, "size_bytes": self.size_bytes}


def _text(result: CommandResult) -> str:
    err = result.stderr.decode("utf-8", "replace").strip()
    return (err or result.text.strip())[-300:] or f"exit {result.returncode}"


class OllamaService:
    """Read-only view of the running Ollama container."""

    def __init__(
        self, run: CommandRunner, *, docker: str = "docker", project: str = COMPOSE_PROJECT
    ) -> None:
        self._run = run
        self._docker = docker
        self._project = project

    def _docker_run(self, *argv: str, timeout: float = _QUICK_TIMEOUT_S) -> CommandResult:
        return self._run([self._docker, *argv], timeout=timeout)

    def _containers(self, *filters: str, include_stopped: bool = False) -> list[str]:
        argv = ["ps", "-a", "-q"] if include_stopped else ["ps", "-q"]
        for item in filters:
            argv += ["--filter", item]
        result = self._docker_run(*argv)
        if result.returncode != 0:
            raise ModelsError(f"docker ps failed: {_text(result)}")
        return result.text.split()

    def container(self) -> str:
        """The id of the one running Ollama container of this lab."""
        ids = self._containers(
            f"label=com.docker.compose.project={self._project}",
            f"label=com.docker.compose.service={OLLAMA_SERVICE}",
        )
        if not ids:
            raise ModelsError(
                f"Ollama is not running (compose project {self._project}, "
                f"service {OLLAMA_SERVICE}): is this a GPU host (gpu: true) with "
                "deploy/compose/models.yml deployed?"
            )
        if len(ids) > 1:
            raise ModelsError(f"more than one Ollama container is running: {' '.join(ids)}")
        return ids[0]

    def _exec(self, *argv: str, timeout: float = _QUICK_TIMEOUT_S) -> CommandResult:
        return self._docker_run("exec", self.container(), *argv, timeout=timeout)

    def gpu(self) -> str:
        """``nvidia-smi -L`` inside the container: one line per GPU it can see."""
        result = self._exec("nvidia-smi", "-L")
        gpus = [line for line in result.text.splitlines() if re.match(r"GPU \d+:", line)]
        if result.returncode != 0 or not gpus:
            raise ModelsError(f"no GPU is visible in the Ollama container: {_text(result)}")
        return "; ".join(line.split(" (UUID")[0] for line in gpus)

    def models(self) -> list[PulledModel]:
        """The pulled models, by name, with their full manifest digests."""
        result = self._exec("bash", "-c", _TAGS_SCRIPT)
        if result.returncode != 0:
            raise ModelsError(f"could not ask Ollama for its models: {_text(result)}")
        head, _, body = result.text.partition("\r\n\r\n")
        if not head.startswith("HTTP/") or " 200 " not in head.splitlines()[0] + " ":
            raise ModelsError(f"Ollama did not answer /api/tags: {result.text[:120]!r}")
        try:
            entries = json.loads(body)["models"]
            found = [
                PulledModel(
                    str(m["name"]),
                    "sha256:" + _digest(m["digest"]),
                    int(m["size"]),
                )
                for m in entries
            ]
        except (ValueError, KeyError, TypeError) as exc:
            raise ModelsError(
                f"Ollama's model list is not readable ({type(exc).__name__})"
            ) from None
        return sorted(found, key=lambda m: m.name)

    def exposure(self, cell_networks: Sequence[IPv4Network]) -> list[str]:
        """Every way the container is reachable that it must not be (empty: none)."""
        cid = self.container()
        problems: list[str] = []
        inspected = self._json("inspect", cid)
        settings = inspected.get("NetworkSettings") or {}
        published = [port for port, bound in (settings.get("Ports") or {}).items() if bound]
        if published:
            problems.append(f"has a published port ({', '.join(sorted(published))}) on the host")
        networks = sorted(settings.get("Networks") or {})
        models_network = f"{self._project}_models"
        if networks != [models_network]:
            problems.append(
                f"is on more than the models network {models_network} "
                f"({', '.join(networks) or 'none'})"
            )
        for name in networks:
            info = self._json("network", "inspect", name)
            if info.get("Internal") is not True:
                problems.append(f"network {name} is not internal (it has a route out)")
            for config in (info.get("IPAM") or {}).get("Config") or []:
                subnet = ip_network(config["Subnet"], strict=False)
                for cell in cell_networks:
                    if isinstance(subnet, IPv4Network) and subnet.overlaps(cell):
                        problems.append(f"network {name} ({subnet}) overlaps cell network {cell}")
            strangers = sorted(self._services_on(name) - NETWORK_MEMBERS)
            if strangers:
                problems.append(f"network {name} is shared with {', '.join(strangers)}")
        return problems

    def _services_on(self, network: str) -> set[str]:
        result = self._docker_run(
            "ps",
            "--filter",
            f"network={network}",
            "--format",
            '{{.Label "com.docker.compose.service"}}',
        )
        if result.returncode != 0:
            raise ModelsError(f"docker ps failed: {_text(result)}")
        return {line.strip() or "(not a compose service)" for line in result.text.splitlines()}

    def _json(self, *argv: str) -> dict[str, Any]:
        result = self._docker_run(*argv)
        try:
            doc = json.loads(result.stdout or b"[]")
            item = doc[0]
        except (ValueError, IndexError, KeyError):
            item = None
        if result.returncode != 0 or not isinstance(item, dict):
            raise ModelsError(f"docker {' '.join(argv[:2])} gave nothing usable: {_text(result)}")
        return item


def _stream_to_terminal(argv: Sequence[str]) -> int:
    """Run a command with the terminal as its output and no time limit."""
    return subprocess.run(list(argv), check=False).returncode  # noqa: S603 -- fixed argv


def _digest(value: Any) -> str:
    match = _DIGEST.fullmatch(str(value))
    if match is None:
        raise ValueError("not a sha256 digest")
    return match.group(1)


class OllamaAdmin(OllamaService):
    """Model management: every action is refused unless the caller is the host admin."""

    def __init__(
        self,
        run: CommandRunner,
        *,
        docker: str = "docker",
        project: str = COMPOSE_PROJECT,
        environ: Mapping[str, str] | None = None,
        geteuid: Callable[[], int] = os.geteuid,
        container_markers: Sequence[Path] = CONTAINER_MARKERS,
        stream: Callable[[Sequence[str]], int] | None = None,
        lock_path: Path | None = None,
    ) -> None:
        super().__init__(run, docker=docker, project=project)
        # runs a command with its output on the terminal (a pull shows its progress)
        self._stream = stream or _stream_to_terminal
        self._lock_path = lock_path or DEFAULT_LOCK_PATH
        self._environ = os.environ if environ is None else environ
        self._geteuid = geteuid
        self._markers = tuple(container_markers)

    def require_admin(self) -> None:
        """Raise unless this is root on the lab host itself, outside any container."""
        if self._environ.get("LAB_RUN_ID"):
            raise ModelsError("refused: this is inside a cell (LAB_RUN_ID is set)")
        if any(marker.exists() for marker in self._markers):
            raise ModelsError("refused: this is inside a container; run labctl on the lab host")
        if self._geteuid() != 0:
            raise ModelsError("refused: managing models needs root (run it with sudo)")

    @staticmethod
    def _check_id(model: str) -> str:
        if len(model) > _MAX_ID or not MODEL_ID_PATTERN.fullmatch(model):
            raise ModelsError(
                f"{model[:60]!r} is not a valid model id (name or name:tag, as in qwen3:32b)"
            )
        return model

    def models(self) -> list[PulledModel]:
        self.require_admin()
        return super().models()

    def _require_no_cells(self, what: str) -> None:
        """Refuse while any cell exists: a running, created or exited container, or a
        cell network left behind. A run could otherwise start while Ollama is changed."""
        if self._containers("label=lab.run_id", include_stopped=True) or self._run_text(
            "network", "ls", "-q", "--filter", "label=lab.run_id"
        ):
            raise ModelsError(
                f"refused: run cell(s) exist (containers or networks labelled lab.run_id); "
                f"{what} is never part of a run"
            )

    def _run_text(self, *argv: str) -> str:
        result = self._docker_run(*argv)
        if result.returncode != 0:
            raise ModelsError(f"docker {' '.join(argv[:2])} failed: {_text(result)}")
        return result.text.strip()

    @contextlib.contextmanager
    def _exclusive(self) -> Iterator[None]:
        """One pull or removal at a time (an exclusive, non-blocking file lock)."""
        try:
            self._lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self._lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        except OSError as exc:
            raise ModelsError(f"cannot open the lock {self._lock_path}: {exc.strerror}") from None
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ModelsError(
                    "another model operation is running (a pull or removal holds "
                    f"{self._lock_path}); wait for it to finish"
                ) from None
            yield
        finally:
            os.close(fd)  # closing the descriptor drops the lock

    def pull(self, model: str) -> None:
        """Pull ``model`` into the models volume; never while a run cell exists.

        One operation at a time. The uplink is always closed again: on a failure, on
        Ctrl-C and when the process is ended (labctl turns SIGTERM and SIGHUP into
        ``SystemExit``). An uplink that is already there is never touched.
        """
        self.require_admin()
        self._check_id(model)
        with self._exclusive():
            self._require_no_cells("a pull")
            cid = self.container()
            failure: str | None = None
            cleanup = True
            try:
                self._open_uplink(cid)
                code = self._stream([self._docker, "exec", cid, "ollama", "pull", model])
                if code != 0:
                    failure = f"ollama pull {model} failed (exit {code}, see its output above)"
            except UplinkInUse:
                cleanup = False
                raise
            finally:
                leftover = self._close_uplink(cid) if cleanup else None
            if leftover:
                raise ModelsError("; ".join(filter(None, [failure, leftover])))
            if failure:
                raise ModelsError(failure)

    def remove(self, model: str) -> None:
        self.require_admin()
        self._check_id(model)
        with self._exclusive():
            self._require_no_cells("removing a model")
            result = self._docker_run("exec", self.container(), "ollama", "rm", model)
            if result.returncode != 0:
                raise ModelsError(f"ollama rm {model} failed: {_text(result)}")

    def _open_uplink(self, cid: str) -> None:
        """Create the uplink (no container-to-container traffic on it) and attach Ollama.

        A network left by a crashed pull is reused only if it carries our label and
        holds nothing but Ollama.
        """
        created = self._docker_run(
            "network",
            "create",
            "--label",
            f"{UPLINK_LABEL}",
            "-o",
            "com.docker.network.bridge.enable_icc=false",
            UPLINK_NETWORK,
        )
        if created.returncode != 0:
            if "already exists" not in created.stderr.decode("utf-8", "replace"):
                raise ModelsError(f"could not create the uplink network: {_text(created)}")
            info = self._json("network", "inspect", UPLINK_NETWORK)
            by_hand = (
                f"`docker network disconnect --force {UPLINK_NETWORK} {cid}` (for each "
                f"attached container) and `docker network rm {UPLINK_NETWORK}`"
            )
            if (info.get("Labels") or {}).get("lab.role") != "ollama-uplink":
                raise UplinkInUse(
                    f"refused: a network called {UPLINK_NETWORK} exists but is not the Ollama "
                    f"uplink (wrong label); check it, then remove it by hand with {by_hand}"
                )
            if info.get("Containers"):
                raise UplinkInUse(
                    f"refused: the uplink {UPLINK_NETWORK} already has containers attached "
                    "(a crashed pull, or another operation). If none is running, clear it "
                    f"with {by_hand}"
                )
        connected = self._docker_run("network", "connect", UPLINK_NETWORK, cid)
        if connected.returncode != 0:
            raise ModelsError(f"could not attach Ollama to the uplink: {_text(connected)}")

    def _close_uplink(self, cid: str) -> str | None:
        """Detach Ollama and drop the uplink; the problem as text, or ``None``.

        SIGINT, SIGTERM and SIGHUP are blocked meanwhile: one that arrives is held and
        delivered afterwards, so it can neither cut a docker command short nor land
        between the disconnect and the removal.
        """
        signals = {signal.SIGINT, signal.SIGTERM, signal.SIGHUP}
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            return self._detach(cid)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def _detach(self, cid: str) -> str | None:
        left = self._docker_run("network", "disconnect", "--force", UPLINK_NETWORK, cid)
        said = _text(left).lower()
        if left.returncode != 0 and ("no such network" in said or "not found" in said):
            return None  # the network was never created (or is gone): nothing to remove
        if left.returncode != 0 and "is not connected" not in said:
            return (
                f"Ollama may still be attached to the internet: run `docker network disconnect "
                f"--force {UPLINK_NETWORK} {cid}` and `docker network rm {UPLINK_NETWORK}` "
                f"({_text(left)})"
            )
        removed = self._docker_run("network", "rm", UPLINK_NETWORK)
        if removed.returncode != 0 and "No such network" not in _text(removed):
            return f"the uplink network {UPLINK_NETWORK} is left behind: {_text(removed)}"
        return None
