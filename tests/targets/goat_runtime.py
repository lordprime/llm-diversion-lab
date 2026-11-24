"""Shared plumbing for the GOAT image tests: find a container API, start a GOAT the
way its ``compose.cell.yml`` runs it, and run commands inside it.

Each image test module passes its own image reference, compose file and secret file
list; nothing here knows about a particular GOAT.
"""

from __future__ import annotations

import contextlib
import io
import os
import tarfile
import time
from collections.abc import Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

import pytest
import yaml

try:
    import docker
except ImportError:  # pragma: no cover - the dev group always installs it
    docker = None

#: Every container and volume a GOAT test creates carries this label, so a crashed run
#: can be cleaned up by hand.
LABEL_KEY = "llm-diversion-lab.purpose"


def docker_hosts() -> list[str]:
    """Container API sockets to try: ``DOCKER_HOST``, else rootless Podman, else Docker."""
    if host := os.environ.get("DOCKER_HOST"):
        return [host]
    candidates = [
        Path(f"/run/user/{os.getuid()}/podman/podman.sock"),
        Path("/var/run/docker.sock"),
    ]
    return [f"unix://{p}" for p in candidates if p.exists()]


def unavailable(reason: str, require_env: str) -> NoReturn:
    """Skip, or fail when ``require_env`` is set to 1 (as the image build job does)."""
    if os.environ.get(require_env) == "1":
        pytest.fail(reason)
    pytest.skip(reason)


def open_client(image: str, require_env: str, recipe: str) -> Iterator[Any]:
    """Yield a client of the first container API that has ``image`` built."""
    if docker is None:  # pragma: no cover - the dev group always installs it
        unavailable("needs the `docker` SDK (dev dependency)", require_env)
    errors: list[str] = []
    for host in docker_hosts():
        try:
            candidate = docker.DockerClient(base_url=host, timeout=120)
            candidate.ping()
        except Exception as exc:  # any failure means: try the next socket
            errors.append(f"{host}: {exc}")
            continue
        try:
            candidate.images.get(image)
        except docker.errors.ImageNotFound:
            errors.append(f"{host}: image {image} is not built there")
            candidate.close()
            continue
        yield candidate
        candidate.close()
        return
    unavailable(f"no reachable container API with {image} (build {recipe}): {errors}", require_env)


def file_tar(name: str, value: str) -> bytes:
    """A tar holding one root:root 0400 file ``name`` containing ``value``."""
    buf = io.BytesIO()
    data = (value + "\n").encode()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name)
        info.mode = 0o400
        info.size = len(data)
        info.mtime = int(time.time())
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def cell_service(compose_file: Path) -> dict[str, Any]:
    """The `target` service of a GOAT's compose.cell.yml."""
    compose = yaml.safe_load(compose_file.read_text(encoding="utf-8"))
    service = compose["services"]["target"]
    assert isinstance(service, dict)
    return service


class RunningGoat:
    """One running GOAT container, started like the cell's `target` service.

    Applies the compose service's capabilities, security options, sysctls and pids
    limit, and mounts one fresh volume per secret mount it declares (read-only),
    filled by a root writer -- a created, never started container of the same image
    -- through the archive API, as root:root 0400 files. ``secrets`` maps
    ``<directory>/<file>`` under /run/secrets to its value.
    """

    def __init__(
        self,
        client: Any,
        image: str,
        compose_file: Path,
        secrets: Mapping[str, str],
        labels: Mapping[str, str],
        **run_options: Any,
    ) -> None:
        self.client = client
        self.image = image
        self.secrets = dict(secrets)
        service = cell_service(compose_file)
        mounts = [str(v).split(":") for v in service["volumes"]]
        assert all(len(m) == 3 and m[2] == "ro" for m in mounts), mounts
        targets = sorted(m[1] for m in mounts)
        assert targets == sorted({f"/run/secrets/{p.split('/')[0]}" for p in self.secrets})

        self.volumes: list[Any] = []
        self.container: Any = None
        try:
            by_target = {}
            for target in targets:
                volume = client.volumes.create(labels=dict(labels))
                self.volumes.append(volume)
                by_target[target] = volume.name
            writer = client.containers.create(
                image,
                entrypoint=["/bin/true"],
                volumes={
                    name: {"bind": "/s/" + target.rsplit("/", 1)[1], "mode": "rw"}
                    for target, name in by_target.items()
                },
                labels=dict(labels),
            )
            try:
                for path, value in self.secrets.items():
                    directory, name = path.split("/")
                    assert writer.put_archive(f"/s/{directory}", file_tar(name, value))
            finally:
                writer.remove(force=True)
            self.container = client.containers.run(
                image,
                detach=True,
                volumes={
                    name: {"bind": target, "mode": "ro"} for target, name in by_target.items()
                },
                cap_drop=service["cap_drop"],
                cap_add=service["cap_add"],
                security_opt=service["security_opt"],
                pids_limit=service["pids_limit"],
                sysctls=service["sysctls"],
                labels=dict(labels),
                **run_options,
            )
        except BaseException:
            self.remove()
            raise

    def sh(self, script: str, user: str = "root") -> tuple[int, str]:
        """Run ``script`` with bash inside the container; (exit code, combined output)."""
        code, out = self.container.exec_run(["/bin/bash", "-c", script], user=user)
        return code, out.decode(errors="replace")

    def wait_healthy(self, health_cmd: str, timeout_s: float) -> None:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            self.container.reload()
            if self.container.status != "running":
                break
            if self.sh(health_cmd)[0] == 0:
                return
            time.sleep(2)
        logs = self.container.logs(tail=60).decode(errors="replace")
        raise TimeoutError(f"GOAT not healthy (status {self.container.status})\n{logs}")

    def remove(self) -> None:
        for resource in (self.container, *self.volumes):
            if resource is None:
                continue
            with contextlib.suppress(Exception):  # already gone
                resource.remove(force=True)


def scan(client: Any, image: str, script: str, labels: Mapping[str, str]) -> set[str]:
    """Paths ``script`` prints in a throwaway, offline container of ``image``.

    Runs as root with the runtime's default capabilities (unlike the cell's target,
    which drops DAC_READ_SEARCH), so the scan sees every directory.
    """
    out = client.containers.run(
        image,
        ["-c", script],
        entrypoint=["/bin/sh"],
        remove=True,
        network_disabled=True,
        labels=dict(labels),
    )
    return set(out.decode().split())


def words_pattern(words: Sequence[str]) -> str:
    """An extended-grep pattern matching any of ``words`` as a whole word."""
    return "\\b(" + "|".join(words) + ")\\b"
