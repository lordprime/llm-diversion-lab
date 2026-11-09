"""Shape of ``.github/workflows/build-images.yml``: the jobs that push the lab's images.

Every job must pin its actions by full commit SHA, check out without persisting the
token and hold only the permissions it needs (``contents: read``, plus
``packages: write`` where it pushes). The ``plan`` job picks one tag for the run (the
``version`` input, a ``lab-v*`` git tag, or ``sha-<commit>``) and finds every GOAT with
a Dockerfile; the ``goat`` matrix job builds each through its own
``targets/<name>/ci`` scripts. Each image job takes the pushed digest from the push
output, checks the registry serves it at the tag, refuses to move an existing named
tag, and hands over a ready ``deploy/images.lock`` entry with the image's ``role``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.deploy.test_scripts import SHELLCHECK_PY, _require_tool

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "build-images.yml"
CI = ROOT / ".github" / "workflows" / "ci.yml"

#: image job -> (images.lock role, the Dockerfile it builds; None: per-GOAT script)
IMAGE_JOBS = {
    "goat": ("target", None),
    "lab-cell": ("infra", "cell/Dockerfile"),
    "control": ("control", "deploy/compose/control.Dockerfile"),
}
ALL_JOBS = {"plan", *IMAGE_JOBS}
ROLES = {"agent", "target", "infra", "control"}
USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
PUSH_PERMISSIONS = {"contents": "read", "packages": "write"}
GOATS = sorted(p.parent.name for p in (ROOT / "targets").glob("*/Dockerfile"))


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


def _step(job: str, name: str) -> dict[str, Any]:
    return next(s for s in _steps(job) if s.get("name") == name)


def _run_text(job: str) -> str:
    return "\n".join(str(s.get("run", "")) for s in _steps(job))


def _bash(script: str, cwd: Path, tmp_path: Path, **env: str) -> tuple[int, str, str]:
    """Run a workflow step's script with bash, as the runner would; return (rc, outputs, stderr)."""
    out = tmp_path / "github_output"
    out.write_text("")
    full_env = {
        "PATH": os.environ["PATH"],
        "GITHUB_OUTPUT": str(out),
        "GITHUB_STEP_SUMMARY": str(tmp_path / "summary"),
        **env,
    }
    proc = subprocess.run(  # noqa: S603 -- the workflow's own step script
        ["bash", "-e", "-c", script],  # noqa: S607
        cwd=cwd,
        env=full_env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return proc.returncode, out.read_text(), proc.stderr


def test_the_expected_jobs_exist() -> None:
    assert set(_jobs()) == ALL_JOBS


def test_no_permissions_at_the_top() -> None:
    assert _workflow().get("permissions") == {}, "grant permissions per job, none at the top"


def test_ci_holds_a_read_only_token() -> None:
    ci = yaml.safe_load(CI.read_text(encoding="utf-8"))
    assert ci.get("permissions") == {"contents": "read"}
    for name, job in ci["jobs"].items():
        assert "permissions" not in job, f"ci.yml job {name} widens the token"


def test_plan_job_cannot_push() -> None:
    assert _jobs()["plan"].get("permissions") == {"contents": "read"}


@pytest.mark.parametrize("job", sorted(IMAGE_JOBS))
def test_image_job_permissions_are_minimal(job: str) -> None:
    assert _jobs()[job].get("permissions") == PUSH_PERMISSIONS


@pytest.mark.parametrize("job", sorted(ALL_JOBS))
def test_every_action_is_sha_pinned(job: str) -> None:
    uses = [s["uses"] for s in _steps(job) if "uses" in s]
    assert uses, f"{job}: uses no actions"
    for ref in uses:
        assert USES_RE.match(ref), f"{job}: {ref!r} is not pinned to a full commit SHA"


@pytest.mark.parametrize("job", sorted(ALL_JOBS))
def test_checkout_does_not_persist_credentials(job: str) -> None:
    checkouts = [s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/checkout@")]
    assert checkouts, f"{job}: no checkout step"
    for step in checkouts:
        assert (step.get("with") or {}).get("persist-credentials") is False, (
            f"{job}: checkout must set persist-credentials: false"
        )


def test_manual_runs_take_a_version() -> None:
    # PyYAML reads the bare key `on` as True
    doc: dict[Any, Any] = _workflow()
    triggers: dict[str, Any] = doc["on"] if "on" in doc else doc[True]
    version = triggers["workflow_dispatch"]["inputs"]["version"]
    assert version["type"] == "string" and version["required"] is False and version["default"] == ""
    assert triggers["push"] == {"tags": ["lab-v*"]}


@pytest.mark.parametrize("job", sorted(IMAGE_JOBS))
def test_image_jobs_take_the_tag_from_plan(job: str) -> None:
    spec = _jobs()[job]
    assert spec.get("needs") == "plan"
    assert spec["env"]["TAG"] == "${{ needs.plan.outputs.tag }}"
    run = _run_text(job)
    # the tag is chosen once, in plan; the version input is read nowhere else
    assert "GITHUB_SHA::12" not in run and "REF_NAME" not in run
    assert "inputs.version" not in json.dumps(spec)


@pytest.mark.parametrize("job", sorted(IMAGE_JOBS))
def test_job_pushes_and_checks_the_digest(job: str) -> None:
    image = "goat-${{ matrix.goat }}" if job == "goat" else job
    assert _jobs()[job]["env"]["IMAGE"] == f"ghcr.io/lordprime/{image}"
    run = _step(job, "Push")["run"]
    assert ".RepoDigests" not in run, f"{job}: RepoDigests can name the local build first"
    assert "tee push.log" in run, f"{job}: digest not taken from the push output"
    assert "^sha256:[0-9a-f]{64}$" in run, f"{job}: digest format not checked"
    assert '[[ "$served" == "$digest" ]]' in run, f"{job}: pushed and served digests not compared"
    # an existing named version is refused before anything is tagged or pushed
    refuse = run.index("already exists; choose a new version")
    assert refuse < run.index("docker tag "), f"{job}: checks for an existing tag too late"
    assert "!= sha-* ]] && docker buildx imagetools inspect" in run
    uploads = [s for s in _steps(job) if str(s.get("uses", "")).startswith("actions/upload-")]
    name = "goat-${{ matrix.goat }}-digest" if job == "goat" else f"{job}-digest"
    assert [u["with"]["name"] for u in uploads] == [name]


@pytest.mark.parametrize("job", ["lab-cell", "control"])
def test_job_builds_its_dockerfile_and_emits_its_role(job: str) -> None:
    role, dockerfile = IMAGE_JOBS[job]
    assert role in ROLES
    run = _run_text(job)
    assert f"-f {dockerfile}" in run, f"{job}: does not build {dockerfile}"
    assert f"- name: {job}\n" in run, f"{job}: the images.lock entry names another image"
    assert f"role: {role}\n" in run, f"{job}: the images.lock entry must carry role: {role}"


def test_goat_job_runs_each_goats_own_scripts() -> None:
    spec = _jobs()["goat"]
    assert spec["needs"] == "plan"
    assert spec["strategy"]["matrix"]["goat"] == "${{ fromJSON(needs.plan.outputs.goats) }}"
    assert spec["strategy"]["fail-fast"] is False
    assert 'bash "targets/$GOAT/ci/build.sh" "goat-$GOAT:ci"' in _step("goat", "Build")["run"]
    check = next(s for s in _steps("goat") if str(s.get("name", "")).startswith("Check the image"))
    assert check["run"] == 'bash "targets/$GOAT/ci/check.sh" "goat-$GOAT:ci"'
    record = _step("goat", "Record the digest")["run"]
    assert "- name: goat-${GOAT}\n" in record
    assert "role: target\n" in record
    assert 'head -n1 "targets/$GOAT/ci/expect_tools"' in record


def test_there_is_a_goat_to_build() -> None:
    assert "dvga" in GOATS


@pytest.mark.parametrize("goat", GOATS)
def test_every_goat_with_a_dockerfile_has_its_ci_scripts(goat: str) -> None:
    ci = ROOT / "targets" / goat / "ci"
    for name in ("build.sh", "check.sh", "expect_tools"):
        assert (ci / name).is_file(), f"targets/{goat}/ci/{name} is missing"
    assert (ROOT / "targets" / goat / "source.yaml").is_file()
    assert re.fullmatch(r"\[[a-z0-9_.-]+(, [a-z0-9_.-]+)*\]\n", (ci / "expect_tools").read_text())
    build = (ci / "build.sh").read_text()
    assert f"-f targets/{goat}/Dockerfile" in build, f"{goat}: build.sh builds another Dockerfile"
    for var in ("APP_SRC", "APP_COMMIT", "EVAL_SRC", "EVAL_COMMIT", "SOURCE_URL", "REVISION"):
        assert f"${var}" in build, f"{goat}: build.sh ignores {var}"
    for name in ("build.sh", "check.sh"):
        mode = subprocess.run(  # noqa: S603 -- fixed argv
            ["git", "ls-files", "-s", f"targets/{goat}/ci/{name}"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split(" ", 1)[0]
        assert mode == "100755", (
            f"targets/{goat}/ci/{name} is not executable in git ({mode or 'untracked'})"
        )


@pytest.mark.parametrize("goat", GOATS)
def test_goat_ci_scripts_are_shellcheck_clean(goat: str) -> None:
    shellcheck = _require_tool("shellcheck", SHELLCHECK_PY)
    scripts = [str(p) for p in sorted((ROOT / "targets" / goat / "ci").glob("*.sh"))]
    result = subprocess.run(  # noqa: S603 -- fixed argv
        [*shellcheck, "--severity=style", *scripts], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr


SHA = "72c27588f130" + "0" * 28


@pytest.mark.parametrize(
    ("version", "ref_type", "ref_name", "tag"),
    [
        ("", "branch", "main", "sha-72c27588f130"),
        ("", "tag", "lab-v3", "lab-v3"),
        ("v0.2.0", "branch", "main", "v0.2.0"),
        ("v0.2.0", "tag", "lab-v3", "v0.2.0"),
        ("2026.11.09-rc1", "branch", "main", "2026.11.09-rc1"),
    ],
)
def test_plan_chooses_the_tag(
    version: str, ref_type: str, ref_name: str, tag: str, tmp_path: Path
) -> None:
    script = _step("plan", "Choose the image tag")["run"]
    rc, outputs, err = _bash(
        script,
        ROOT,
        tmp_path,
        VERSION=version,
        REF_TYPE=ref_type,
        REF_NAME=ref_name,
        GITHUB_SHA=SHA,
    )
    assert rc == 0, err
    assert outputs == f"tag={tag}\n"


@pytest.mark.parametrize(
    "version", ["latest", "sha-deadbeef", "v1 2", "-v1", "v1/2", "a" * 129, "v1;id"]
)
def test_plan_refuses_a_bad_version(version: str, tmp_path: Path) -> None:
    script = _step("plan", "Choose the image tag")["run"]
    rc, outputs, _ = _bash(
        script, ROOT, tmp_path, VERSION=version, REF_TYPE="branch", REF_NAME="main", GITHUB_SHA=SHA
    )
    assert rc != 0 and outputs == ""


def _fake_targets(root: Path, goats: dict[str, tuple[str, ...]]) -> None:
    for goat, files in goats.items():
        d = root / "targets" / goat
        (d / "ci").mkdir(parents=True)
        for f in files:
            (d / f).write_text("x\n")


ALL_FILES = ("Dockerfile", "source.yaml", "ci/build.sh", "ci/check.sh", "ci/expect_tools")


def test_plan_finds_every_goat_with_a_dockerfile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_targets(
        repo, {"dvga": ALL_FILES, "juice-shop": ALL_FILES, "drupal-7600": ("source.yaml",)}
    )
    rc, outputs, err = _bash(
        _step("plan", "Find the GOATs with an image recipe")["run"], repo, tmp_path
    )
    assert rc == 0, err
    assert outputs == 'goats=["dvga","juice-shop"]\n'
    assert "Not built yet (no Dockerfile): drupal-7600" in (tmp_path / "summary").read_text()


def test_plan_finds_the_real_goats(tmp_path: Path) -> None:
    rc, outputs, err = _bash(
        _step("plan", "Find the GOATs with an image recipe")["run"], ROOT, tmp_path
    )
    assert rc == 0, err
    assert outputs == f"goats={json.dumps(GOATS, separators=(',', ':'))}\n"


@pytest.mark.parametrize(
    "missing", ["source.yaml", "ci/build.sh", "ci/check.sh", "ci/expect_tools"]
)
def test_plan_refuses_a_goat_without_its_ci_files(missing: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_targets(repo, {"dvga": tuple(f for f in ALL_FILES if f != missing)})
    rc, outputs, err = _bash(
        _step("plan", "Find the GOATs with an image recipe")["run"], repo, tmp_path
    )
    assert rc != 0 and outputs == ""
    assert f"has a Dockerfile but no {missing}" in err


def test_plan_refuses_when_no_goat_has_a_dockerfile(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_targets(repo, {"juice-shop": ("source.yaml",)})
    rc, outputs, _ = _bash(
        _step("plan", "Find the GOATs with an image recipe")["run"], repo, tmp_path
    )
    assert rc != 0 and outputs == ""


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
