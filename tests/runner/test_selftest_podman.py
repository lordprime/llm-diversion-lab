"""The self-test pair end to end in real cells: scripted agent, stub LLM, DVGA.

Runs :class:`~control.runner.runner.Runner` with the real :class:`ComposeBackend` on a
local container engine (Podman's Docker-compatible socket, or Docker), real Postgres
and an in-process Collector API. No model is called and no third-party attack tool
runs: the agent is the scripted one, the "attack" is DVGA's own importPaste.

Needs the ``docker`` CLI with the compose plugin, a reachable socket, and the images
``localhost/lab-cell:dev`` (``cell/Dockerfile``) and ``localhost/goat-dvga:dev``
(``targets/dvga/Dockerfile``); skipped otherwise, unless ``LAB_E2E_REQUIRE=1``.
``LAB_E2E_ENGINE`` (``podman``/``docker``) and ``DOCKER_HOST`` choose the engine.
Docker-only options (bridge names, DOCKER-USER) are not exercised here; their
rendering is asserted in ``test_cell_spec.py``.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select

from control.api.app import create_app
from control.core.models import Arm, CallbackChannel, EndStatus, FunnelStage, RunStatus
from control.db import tables as t
from control.db.engine import session_scope
from control.runner.cell_spec import CellSettings
from control.runner.cell_spec import Engine as CellEngine
from control.runner.compose_backend import ComposeBackend, SubprocessRunner
from control.runner.experiment import read_experiment
from control.runner.runner import Runner
from control.runner.ship import CollectorClient
from control.runner.store import RunStore

REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGES = {"lab-cell": "localhost/lab-cell:dev", "goat-dvga": "localhost/goat-dvga:dev"}
KEY = hashlib.sha256(b"selftest-e2e-lab-key").digest()


def _unavailable(reason: str) -> NoReturn:
    if os.environ.get("LAB_E2E_REQUIRE") == "1":
        pytest.fail(reason)
    pytest.skip(reason)


@pytest.fixture(scope="module")
def docker_env() -> dict[str, str]:
    if shutil.which("docker") is None:
        _unavailable("needs the docker CLI")
    env: dict[str, str] = {}
    podman = Path(f"/run/user/{os.getuid()}/podman/podman.sock")
    if "DOCKER_HOST" in os.environ:
        env["DOCKER_HOST"] = os.environ["DOCKER_HOST"]
    elif podman.exists():
        env["DOCKER_HOST"] = f"unix://{podman}"
    full = {**os.environ, **env}
    for argv in (
        ["docker", "compose", "version"],
        ["docker", "image", "inspect", *IMAGES.values()],
    ):
        done = subprocess.run(argv, env=full, capture_output=True, check=False)  # noqa: S603
        if done.returncode != 0:
            _unavailable(f"{' '.join(argv[:3])}: {done.stderr.decode()[-300:]}")
    return env


@pytest.fixture
def collector(engine: Engine) -> Iterator[CollectorClient]:
    with TestClient(create_app(engine)) as http:
        yield CollectorClient(http)


def test_the_selftest_pair_in_real_cells(
    engine: Engine, collector: CollectorClient, docker_env: dict[str, str], tmp_path: Path
) -> None:
    engine_kind = os.environ.get("LAB_E2E_ENGINE") or (
        "podman" if "podman" in docker_env.get("DOCKER_HOST", "") else "docker"
    )
    runner = Runner(
        store=RunStore(engine),
        collector=collector,
        backend=ComposeBackend(SubprocessRunner(docker_env)),
        settings=CellSettings(
            images=IMAGES, engine=CellEngine(engine_kind), require_digests=False, dev=True
        ),
        lab_key=KEY,
        runs_dir=tmp_path / "runs",
        work_dir=tmp_path / "work",
    )
    results = runner.run_experiment(read_experiment(REPO_ROOT / "experiments" / "selftest.yaml"))
    assert [(r.status, r.detail) for r in results] == [(RunStatus.VALID, "")] * 2
    assert {r.end_status for r in results} == {EndStatus.COMPLETED}
    assert {r.outcome for r in results} == {True}

    with session_scope(engine) as s:
        labels = {(row.run_id, row.stage): row.value for row in s.scalars(select(t.Label)).all()}
        callbacks = s.scalars(select(t.Callback)).all()
    for result in results:
        got = {stage: labels[(result.run_id, stage)] for stage in FunnelStage}
        treated = result.arm is Arm.INJECTED
        assert got == {
            FunnelStage.ACCESS: treated,
            FunnelStage.VISIBLE: treated,
            FunnelStage.UPTAKE: treated,
            FunnelStage.OUTCOME: True,  # the objective is reached in both arms
        }, result.arm
    injected = next(r for r in results if r.arm is Arm.INJECTED)
    channels = {c.channel for c in callbacks if c.run_id == injected.run_id and c.token}
    assert channels == {CallbackChannel.HTTP, CallbackChannel.DNS}

    # nothing of either cell is left behind
    full = {**os.environ, **docker_env}
    for result in results:
        label = f"label=lab.run_id={result.run_id}"
        for kind in (["ps", "-a"], ["volume", "ls"], ["network", "ls"]):
            out = subprocess.run(  # noqa: S603 - fixed argv
                [shutil.which("docker") or "docker", *kind, "-q", "--filter", label],
                env=full,
                capture_output=True,
                check=True,
            )
            assert out.stdout.strip() == b"", (kind, result.run_id)
