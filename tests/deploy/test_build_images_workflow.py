"""Shape of ``.github/workflows/build-images.yml``: the jobs that push the lab's images.

Every job must pin its actions by full commit SHA, check out without persisting the
token, hold only ``contents: read`` and ``packages: write``, read the pushed digest from
``docker image inspect`` RepoDigests and check it, and hand over a ready
``deploy/images.lock`` entry with the image's ``role``.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "build-images.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"

#: job -> (images.lock role, Dockerfile it builds)
JOBS = {
    "goat-dvga": ("target", "targets/dvga/Dockerfile"),
    "lab-cell": ("infra", "cell/Dockerfile"),
    "control": ("control", "deploy/compose/control.Dockerfile"),
}
ROLES = {"agent", "target", "infra", "control"}
USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
ALLOWED_PERMISSIONS = {"contents": "read", "packages": "write"}


def _workflow() -> dict[str, Any]:
    doc = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), f"{WORKFLOW} is not a mapping"
    return doc


def _jobs() -> dict[str, dict[str, Any]]:
    jobs = _workflow().get("jobs")
    assert isinstance(jobs, dict) and jobs, "build-images.yml has no jobs"
    return jobs


def _steps(job: str) -> list[dict[str, Any]]:
    steps = _jobs()[job].get("steps")
    assert isinstance(steps, list) and steps, f"{job}: no steps"
    return steps


def _run_text(job: str) -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps(job))


def test_the_expected_jobs_exist() -> None:
    assert set(_jobs()) == set(JOBS)


def test_no_permissions_at_the_top() -> None:
    assert _workflow().get("permissions") == {}, "grant permissions per job, none at the top"


def test_ci_holds_a_read_only_token() -> None:
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert ci.get("permissions") == {"contents": "read"}
    for name, job in ci["jobs"].items():
        assert "permissions" not in job, f"ci.yml job {name} widens the token"


@pytest.mark.parametrize("job", sorted(JOBS))
def test_job_permissions_are_minimal(job: str) -> None:
    assert _jobs()[job].get("permissions") == ALLOWED_PERMISSIONS


@pytest.mark.parametrize("job", sorted(JOBS))
def test_every_action_is_sha_pinned(job: str) -> None:
    uses = [s["uses"] for s in _steps(job) if "uses" in s]
    assert uses, f"{job}: uses no actions"
    for ref in uses:
        assert USES_RE.match(ref), f"{job}: {ref!r} is not pinned to a full commit SHA"


@pytest.mark.parametrize("job", sorted(JOBS))
def test_checkout_does_not_persist_credentials(job: str) -> None:
    checkouts = [s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkouts, f"{job}: no checkout step"
    for step in checkouts:
        assert (step.get("with") or {}).get("persist-credentials") is False, (
            f"{job}: checkout must set persist-credentials: false"
        )


@pytest.mark.parametrize("job", sorted(JOBS))
def test_job_pushes_to_its_ghcr_name_and_checks_the_digest(job: str) -> None:
    assert _jobs()[job].get("env", {}).get("IMAGE") == f"ghcr.io/lordprime/{job}"
    run = _run_text(job)
    assert "{{index .RepoDigests 0}}" in run, f"{job}: digest not read from RepoDigests"
    assert "^sha256:[0-9a-f]{64}$" in run, f"{job}: digest format not checked"
    uploads = [s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/upload-")]
    assert [u["with"]["name"] for u in uploads] == [f"{job}-digest"]


@pytest.mark.parametrize("job", sorted(JOBS))
def test_job_builds_its_dockerfile_and_emits_its_role(job: str) -> None:
    role, dockerfile = JOBS[job]
    assert role in ROLES
    run = _run_text(job)
    assert f"-f {dockerfile}" in run, f"{job}: does not build {dockerfile}"
    assert f"- name: {job}\n" in run, f"{job}: the images.lock entry names another image"
    assert f"role: {role}\n" in run, f"{job}: the images.lock entry must carry role: {role}"


@pytest.mark.parametrize("job", ["lab-cell", "control"])
def test_root_context_images_build_from_the_repository_root(job: str) -> None:
    build = next(s["run"] for s in _steps(job) if s.get("name") == "Build")
    last = build.strip().splitlines()[-1].strip()
    assert last == ".", f"{job}: the build context must be the repository root"


def test_root_dockerignore_admits_what_the_cell_image_copies() -> None:
    dockerfile = ROOT / "cell" / "Dockerfile"
    if not dockerfile.is_file():
        pytest.skip("cell/Dockerfile is not on this branch yet")
    admitted = {
        line[1:].strip().rstrip("/")
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.startswith("!")
    }
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts or parts[0] != "COPY" or any(p.startswith("--from") for p in parts):
            continue
        for src in (p for p in parts[1:-1] if not p.startswith("--")):
            top = src.split("/", 1)[0]
            assert src in admitted or top in admitted, f".dockerignore does not admit {src}"
