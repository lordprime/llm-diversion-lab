"""Shared plumbing for the GOAT image tests: find a container API, start a GOAT the
way its ``compose.cell.yml`` runs it, and run commands inside it.

Each image test module passes its own image reference, compose file and secret file
list; nothing here knows about a particular GOAT.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import tarfile
import time
import urllib.parse
import urllib.robotparser
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

import pytest
import yaml

from control.core.ids import new_id
from control.core.models import Arm, Surface
from control.runner.cell_spec import project_name
from control.runner.experiment import PlacementMapFile, TargetSpec
from control.runner.schedule import ScheduledRun

REPO_ROOT = Path(__file__).resolve().parents[2]

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


class PlacementPaths:
    """A target's frozen placement map (``targets/<target>/placements.yaml``) against
    what its built image serves natively: straight from the app, no injector.

    P1 is the app's own robots.txt (200, text/plain); P2 a 200 HTML page with a body
    that this robots.txt disallows for every user agent (the page and the rule exist in
    every arm); P3-P6 and P8 200 HTML pages with a body; P7 the 4xx its locator names,
    answered by the app itself. :meth:`check` returns one evidence line per path.
    """

    def __init__(self, target: str, sh: Callable[[str], tuple[int, str]], base_url: str):
        found = PlacementMapFile.read(REPO_ROOT, f"targets/{target}/placements.yaml")
        self.spec = TargetSpec.model_validate(
            {"name": target, "objective": "probe", "placements": found.placements(target)}
        )
        self._sh = sh
        self._base_url = base_url

    def fetch(self, path: str) -> tuple[int, str, str]:
        """``(status, media type, body)`` of an anonymous GET of ``path``."""
        code, out = self._sh(
            f"curl -s --max-time 60 -w '\\n%{{http_code}} %{{content_type}}' "
            f"{shlex.quote(self._base_url + path)}"
        )
        assert code == 0, out
        body, _, tail = out.rpartition("\n")
        status, _, content_type = tail.partition(" ")
        return int(status), content_type.partition(";")[0].strip().lower(), body

    def check(self) -> list[str]:
        evidence: list[str] = []
        robots: urllib.robotparser.RobotFileParser | None = None
        for surface, placement in sorted(self.spec.placements.items()):
            status, media, body = self.fetch(placement.url)
            evidence.append(f"{surface.value} GET {placement.url} -> {status} {media}")
            where = f"{surface.value} {placement.url}: {status} {media}"
            if surface is Surface.P1:
                assert (status, media) == (200, "text/plain"), where
                robots = urllib.robotparser.RobotFileParser()
                robots.parse(body.splitlines())
            elif surface is Surface.P7:
                expected = int(placement.locator.rpartition(":")[2])
                assert status == expected, where
            else:
                assert (status, media) == (200, "text/html"), where
                assert "<body" in body.lower() and "</body>" in body.lower(), where
        p2 = self.spec.placements.get(Surface.P2)
        if p2 is not None:
            assert robots is not None, "P2 needs the app's own robots.txt (P1)"
            assert not robots.can_fetch("*", p2.url), f"robots.txt does not disallow {p2.url}"
            evidence.append(f"P2 robots.txt disallows {p2.url} for User-agent: *")
        return evidence


class CellSteps:
    """What a target's cell file (``deploy/compose/cell.<target>.yml``, ``x-lab``) has
    the self-test do there: the scripted agent's objective step and the reset."""

    def __init__(self, target: str) -> None:
        cell = yaml.safe_load((REPO_ROOT / "deploy" / "compose" / f"cell.{target}.yml").read_text())
        self.objective: dict[str, Any] = cell["x-lab"]["objective"]
        self.reset: dict[str, Any] = cell["x-lab"]["reset"]

    def objective_curl(self, base_url: str) -> str:
        """A curl command sending the objective step's request exactly as the scripted
        agent builds it (``agents/scripted/agent.py``, ``post``)."""
        step = self.objective
        assert step["action"] == "post"
        if "form" in step:
            body = urllib.parse.urlencode([tuple(pair) for pair in step["form"]])
            kind = "application/x-www-form-urlencoded"
        else:
            body = json.dumps(step["body"])
            kind = "application/json"
        return (
            f"curl -s --max-time 120 -H {shlex.quote('Content-Type: ' + kind)} "
            f"--data-binary {shlex.quote(body)} {shlex.quote(base_url + step['path'])}"
        )


def cell_project(target: str) -> str:
    """A Compose project name as the runner gives a cell (control/runner/cell_spec.py).

    Test containers name their volumes ``<this>_<volume>``, exactly as a cell's are
    named, because those names show in the target's /proc/self/mountinfo.
    """
    run = ScheduledRun(
        run_id=new_id("run"),
        experiment_id=new_id("exp"),
        pair_id=new_id("pair"),
        arm=Arm.CONTROL,
        target=target,
        agent="scripted",
        model="stub",
        rep=0,
        schedule_index=0,
        tag=None,
    )
    return project_name(run)


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
    ``<directory>/<file>`` under /run/secrets to its value. A writable mount (the
    GOAT's latch volume) gets a fresh, empty volume.

    Every volume is named as Compose names a project's (``<project>_<volume>``),
    since the names show in the target's /proc/self/mountinfo, which its app user
    can read.
    """

    SUPPORT = "/opt/support"

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
        # every secret read-only under /run/secrets; anything else writable
        secret_mounts = [m for m in mounts if len(m) == 3]
        writable = [m for m in mounts if len(m) == 2]
        assert len(secret_mounts) + len(writable) == len(mounts), mounts
        assert all(m[2] == "ro" and m[1].startswith("/run/secrets/") for m in secret_mounts)
        assert not any(m[1].startswith("/run/secrets") for m in writable), mounts
        targets = sorted(m[1] for m in secret_mounts)
        assert targets == sorted({f"/run/secrets/{p.split('/')[0]}" for p in self.secrets})
        self.project = cell_project(compose_file.parent.name)
        names = {m[1]: f"{self.project}_{m[0]}" for m in mounts}

        self.volumes: list[Any] = []
        self.container: Any = None
        try:
            by_target = {}
            for target in targets:
                volume = client.volumes.create(name=names[target], labels=dict(labels))
                self.volumes.append(volume)
                by_target[target] = volume.name
            writable_volumes = {}
            for _, target in writable:
                volume = client.volumes.create(name=names[target], labels=dict(labels))
                self.volumes.append(volume)
                writable_volumes[volume.name] = {"bind": target, "mode": "rw"}
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
                    **{name: {"bind": target, "mode": "ro"} for target, name in by_target.items()},
                    **writable_volumes,
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

    def done(self) -> dict[str, Any]:
        """The done v2 verdict, as the runner reads it (``done.sh``, stdout only)."""
        code, out = self.sh(f"{self.SUPPORT}/done.sh 2>/dev/null")
        assert code == 0, out
        verdict = json.loads(out.strip().splitlines()[-1])
        assert isinstance(verdict, dict)
        return verdict

    def diagnostics(self) -> list[str]:
        """The lines done.sh relays from the evaluator's error log (rejected peers among
        them). The log keeps only its latest records, so compare lines, never counts."""
        code, out = self.sh(f"{self.SUPPORT}/done.sh 2>&1 >/dev/null")
        assert code == 0, out
        return out.splitlines()

    def latch(self) -> list[dict[str, Any]]:
        """The latch's events, through latch-dump.sh (as the runner collects them)."""
        code, out = self.sh(f"{self.SUPPORT}/latch-dump.sh 2>/dev/null")
        assert code == 0, out
        return [json.loads(line) for line in out.splitlines()]

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
