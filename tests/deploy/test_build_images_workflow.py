"""Shape of ``.github/workflows/build-images.yml``: the jobs that push the lab's images.

Every job must pin its actions by full commit SHA, check out without persisting the
token and hold only the permissions it needs (``contents: read``, plus
``packages: write`` where it pushes). The ``plan`` job picks one tag for the run (the
``version`` input, a ``lab-v*`` git tag, or ``sha-<commit>``) and finds every GOAT and
every agent with a Dockerfile; the ``image`` matrix job builds each through its own
``targets/<name>/ci`` or ``agents/<name>/ci`` scripts (GOATs and agents share it).
Each image job takes the pushed digest from the push output, checks the registry serves
it at the tag, refuses to move an existing named tag, and hands over a ready
``deploy/images.lock`` entry with the image's ``role``.
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

#: image job -> (images.lock role, the Dockerfile it builds; None: per-image script)
IMAGE_JOBS = {
    "image": ("target", None),
    "lab-cell": ("infra", "cell/Dockerfile"),
    "control": ("control", "deploy/compose/control.Dockerfile"),
}
ALL_JOBS = {"plan", *IMAGE_JOBS}
ROLES = {"agent", "target", "infra", "control"}
USES_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}$")
PUSH_PERMISSIONS = {"contents": "read", "packages": "write"}
GOATS = sorted(p.parent.name for p in (ROOT / "targets").glob("*/Dockerfile"))
AGENTS = sorted(p.parent.name for p in (ROOT / "agents").glob("*/Dockerfile"))


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
    for name in ("version", "only"):
        spec = triggers["workflow_dispatch"]["inputs"][name]
        assert spec["type"] == "string" and spec["required"] is False and spec["default"] == ""
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
    image = "${{ matrix.image.image }}" if job == "image" else job
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
    name = "${{ matrix.image.image }}-digest" if job == "image" else f"{job}-digest"
    digest_uploads = [u for u in uploads if u["with"]["name"].endswith("-digest")]
    assert [u["with"]["name"] for u in digest_uploads] == [name]


@pytest.mark.parametrize("job", ["lab-cell", "control"])
def test_job_builds_its_dockerfile_and_emits_its_role(job: str) -> None:
    role, dockerfile = IMAGE_JOBS[job]
    assert role in ROLES
    run = _run_text(job)
    assert f"-f {dockerfile}" in run, f"{job}: does not build {dockerfile}"
    assert f"- name: {job}\n" in run, f"{job}: the images.lock entry names another image"
    assert f"role: {role}\n" in run, f"{job}: the images.lock entry must carry role: {role}"


def test_image_job_runs_each_images_own_scripts() -> None:
    spec = _jobs()["image"]
    assert spec["needs"] == "plan"
    assert spec["if"] == "needs.plan.outputs.images != '[]'"
    assert spec["name"] == "${{ matrix.image.lane }}-${{ matrix.image.name }}"
    assert spec["strategy"]["matrix"]["image"] == "${{ fromJSON(needs.plan.outputs.images) }}"
    assert spec["strategy"]["fail-fast"] is False
    assert spec["timeout-minutes"] == "${{ matrix.image.timeout }}"
    assert spec["env"]["LOCAL"] == "${{ matrix.image.image }}:ci"
    assert 'bash "$DIR/ci/build.sh" "$LOCAL"' in _step("image", "Build")["run"]
    check = next(s for s in _steps("image") if str(s.get("name", "")).startswith("Check the image"))
    assert check["run"] == 'bash "$DIR/ci/check.sh" "$LOCAL"'
    record = _step("image", "Record the digest")["run"]
    assert "- name: ${remote##*/}\n" in record
    assert "role: ${ROLE}\n" in record
    assert 'head -n1 "$DIR/ci/expect_tools"' in record


def test_the_steps_run_in_order_build_check_push_record() -> None:
    names = [str(s.get("name") or s.get("uses")) for s in _steps("image")]
    order = [
        "Build",
        "Build the smoke kit (stub model, egress canary, cell-guard)",
        "Check the image (its own checks; agents also run agents/ci/smoke.sh)",
        "Log in to GHCR",
        "Push",
        "Record the digest",
    ]
    assert [n for n in names if n in order] == order
    assert names[-1].startswith("actions/upload-artifact@")


def test_lane_specific_steps_are_gated() -> None:
    assert (
        _step("image", "Clone forks at the pinned commits")["if"] == "matrix.image.lane == 'goat'"
    )
    kit = _step("image", "Build the smoke kit (stub model, egress canary, cell-guard)")
    assert kit["if"] == "matrix.image.lane == 'agent'"
    assert "-f agents/ci/stub_model/Dockerfile -t lab-smoke-kit:ci ." in kit["run"]
    keep = _step("image", "Keep the smoke outputs")
    assert keep["if"] == "always() && matrix.image.lane == 'agent'"
    # nothing is logged in to, pushed or recorded for an image that is not pushed
    for name in ("Log in to GHCR", "Push", "Record the digest"):
        assert _step("image", name)["if"] == "matrix.image.push"
    uploads = [s for s in _steps("image") if str(s.get("uses", "")).startswith("actions/upload-")]
    assert uploads[-1]["if"] == "matrix.image.push"


@pytest.mark.parametrize("job", ["lab-cell", "control"])
def test_infra_jobs_are_skipped_when_only_some_images_are_wanted(job: str) -> None:
    assert _jobs()[job]["if"] == "inputs.only == ''"


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


# --------------------------------------------------------------------------- the agent lane

AGENT_FILES = ("Dockerfile", "source.yaml", "ci/build.sh", "ci/check.sh")
FIND_AGENTS = "Find the agents with an image recipe"
MATRIX = "Lay out the image matrix"


def _fake_agents(root: Path, agents: dict[str, tuple[str, ...]], sheets: tuple[str, ...]) -> None:
    (root / "agents" / "sheets").mkdir(parents=True, exist_ok=True)
    for sheet in sheets:
        (root / "agents" / "sheets" / f"{sheet}.yaml").write_text("x\n")
    for agent, files in agents.items():
        d = root / "agents" / agent
        (d / "ci").mkdir(parents=True)
        for f in files:
            (d / f).write_text("x\n")


def _plan_agents(repo: Path, tmp_path: Path) -> tuple[int, str, str]:
    return _bash(_step("plan", FIND_AGENTS)["run"], repo, tmp_path)


def test_plan_finds_agents_and_lists_pending_sheets(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_agents(
        repo,
        {"strix": AGENT_FILES, "_selfcheck": AGENT_FILES, "ci": ("x.sh",), "scripted": ()},
        ("strix", "pentagi", "redamon"),
    )
    rc, outputs, err = _plan_agents(repo, tmp_path)
    assert rc == 0, err
    assert outputs == 'agents=["_selfcheck","strix"]\n'
    summary = (tmp_path / "summary").read_text()
    assert "Agent images built: _selfcheck strix" in summary
    assert "Agents not built yet (no Dockerfile): pentagi redamon" in summary


def test_plan_accepts_no_agent_at_all(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_agents(repo, {"scripted": ()}, ("strix",))
    rc, outputs, err = _plan_agents(repo, tmp_path)
    assert rc == 0, err
    assert outputs == "agents=[]\n"
    assert "Agent images built: none" in (tmp_path / "summary").read_text()


@pytest.mark.parametrize("missing", ["source.yaml", "ci/build.sh", "ci/check.sh"])
def test_plan_refuses_an_agent_without_its_ci_files(missing: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_agents(repo, {"strix": tuple(f for f in AGENT_FILES if f != missing)}, ("strix",))
    rc, outputs, err = _plan_agents(repo, tmp_path)
    assert rc != 0 and outputs == ""
    assert f"agents/strix has a Dockerfile but no {missing}" in err


def test_plan_refuses_a_real_agent_without_a_sheet(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_agents(repo, {"strix": AGENT_FILES, "_fixture": AGENT_FILES}, ())
    rc, outputs, err = _plan_agents(repo, tmp_path)
    assert rc != 0 and outputs == ""
    assert "agents/strix has a Dockerfile but no agents/sheets/strix.yaml" in err
    assert "_fixture" not in err  # a lane fixture needs no sheet


@pytest.mark.parametrize("name", ["Strix", "__x", "_", "x_y", "-x"])
def test_plan_refuses_a_bad_agent_name(name: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _fake_agents(repo, {name: AGENT_FILES}, (name,))
    rc, outputs, err = _plan_agents(repo, tmp_path)
    assert rc != 0 and outputs == ""
    assert "bad agent directory name" in err


def test_plan_finds_the_real_agents(tmp_path: Path) -> None:
    rc, outputs, err = _plan_agents(ROOT, tmp_path)
    assert rc == 0, err
    assert outputs == f"agents={json.dumps(AGENTS, separators=(',', ':'))}\n"
    assert "_selfcheck" in AGENTS


def _matrix(tmp_path: Path, goats: str, agents: str, only: str = "") -> tuple[int, Any, str]:
    rc, outputs, err = _bash(
        _step("plan", MATRIX)["run"], ROOT, tmp_path, GOATS=goats, AGENTS=agents, ONLY=only
    )
    if rc != 0:
        return rc, None, err
    assert outputs.startswith("images=")
    return rc, json.loads(outputs.split("=", 1)[1]), err


def test_matrix_lays_out_both_lanes(tmp_path: Path) -> None:
    rc, images, err = _matrix(tmp_path, '["dvga"]', '["_selfcheck","strix"]')
    assert rc == 0, err
    assert images == [
        {
            "lane": "goat",
            "name": "dvga",
            "dir": "targets/dvga",
            "image": "goat-dvga",
            "role": "target",
            "push": True,
            "timeout": 45,
        },
        {
            "lane": "agent",
            "name": "_selfcheck",
            "dir": "agents/_selfcheck",
            "image": "agent-selfcheck",
            "role": "agent",
            "push": False,
            "timeout": 90,
        },
        {
            "lane": "agent",
            "name": "strix",
            "dir": "agents/strix",
            "image": "agent-strix",
            "role": "agent",
            "push": True,
            "timeout": 90,
        },
    ]


@pytest.mark.parametrize(
    ("only", "jobs"),
    [
        ("", ["goat-dvga", "goat-juice-shop", "agent-strix"]),
        ("   ", ["goat-dvga", "goat-juice-shop", "agent-strix"]),
        ("agent-strix", ["agent-strix"]),
        ("goat-dvga  agent-strix", ["goat-dvga", "agent-strix"]),
    ],
)
def test_matrix_only_filters_the_jobs(only: str, jobs: list[str], tmp_path: Path) -> None:
    rc, images, err = _matrix(tmp_path, '["dvga","juice-shop"]', '["strix"]', only)
    assert rc == 0, err
    assert [f"{i['lane']}-{i['name']}" for i in images] == jobs


@pytest.mark.parametrize("only", ["agent-nope", "strix", "goat-dvga agent-", "goat-*"])
def test_matrix_only_refuses_unknown_jobs(only: str, tmp_path: Path) -> None:
    rc, _, err = _matrix(tmp_path, '["dvga"]', '["strix"]', only)
    assert rc != 0
    assert "only: no image job" in err


def test_matrix_with_no_agents_is_just_the_goats(tmp_path: Path) -> None:
    rc, images, err = _matrix(tmp_path, '["dvga"]', "[]")
    assert rc == 0, err
    assert [i["image"] for i in images] == ["goat-dvga"]


def test_an_empty_matrix_is_valid_json(tmp_path: Path) -> None:
    _fake_agents(tmp_path / "r", {}, ())
    rc, outputs, err = _bash(
        _step("plan", MATRIX)["run"], ROOT, tmp_path, GOATS="[]", AGENTS="[]", ONLY=""
    )
    assert rc == 0, err
    assert outputs == "images=[]\n"


def _pins(repo: Path, tmp_path: Path, **env: str) -> tuple[int, str, str]:
    return _bash(_step("image", "Read pinned commits")["run"], repo, tmp_path, **env)


def _source(repo: Path, rel: str, text: str) -> None:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


C1, C2 = "1" * 40, "2" * 40


def test_pins_of_a_goat_name_both_forks(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _source(
        repo, "targets/dvga/source.yaml", f"repo: https://github.com/a/dvga\nbuild_commit: {C1}\n"
    )
    _source(
        repo,
        "cell/oracle/source.yaml",
        f"repo: https://github.com/a/cvebench\nbuild_commit: {C2}\n",
    )
    rc, outputs, err = _pins(repo, tmp_path, LANE="goat", DIR="targets/dvga", PUSH="true")
    assert rc == 0, err
    assert outputs == (
        f"app_repo=https://github.com/a/dvga\napp_commit={C1}\n"
        f"eval_repo=https://github.com/a/cvebench\neval_commit={C2}\n"
    )


def test_pins_of_an_agent_name_its_upstream(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _source(
        repo,
        "agents/strix/source.yaml",
        f"repo: https://github.com/u/strix  # upstream\ncommit: {C1}\n",
    )
    rc, outputs, err = _pins(repo, tmp_path, LANE="agent", DIR="agents/strix", PUSH="true")
    assert rc == 0, err
    assert (
        outputs
        == f"app_repo=https://github.com/u/strix\napp_commit={C1}\neval_repo=\neval_commit=\n"
    )


@pytest.mark.parametrize(
    "text",
    [
        f"repo: http://github.com/u/strix\ncommit: {C1}\n",
        f"repo: https://gitlab.com/u/strix\ncommit: {C1}\n",
        "repo: https://github.com/u/strix\ncommit: main\n",
        "repo: https://github.com/u/strix\ncommit: abc123\n",
        "repo: https://github.com/u/strix\n",
        f"  repo: https://github.com/u/strix\ncommit: {C1}\n",
    ],
)
def test_pins_of_an_agent_must_be_a_github_repo_and_a_full_commit(
    text: str, tmp_path: Path
) -> None:
    repo = tmp_path / "repo"
    _source(repo, "agents/strix/source.yaml", text)
    rc, outputs, _ = _pins(repo, tmp_path, LANE="agent", DIR="agents/strix", PUSH="true")
    assert rc != 0 and outputs == ""


def test_pins_of_a_lane_fixture_are_not_read(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _source(repo, "agents/_selfcheck/source.yaml", "license: none\n")
    rc, outputs, err = _pins(repo, tmp_path, LANE="agent", DIR="agents/_selfcheck", PUSH="false")
    assert rc == 0, err
    assert outputs == ""


D1, D2 = "sha256:" + "ab" * 32, "sha256:" + "cd" * 32

#: The goat entry and summary exactly as the goat job wrote them before the agent lane
#: (checked against the old step at 008d532): sharing the job changed nothing for GOATs.
GOAT_ENTRY = f"""# Paste into deploy/images.lock in a reviewed commit.
  - name: goat-dvga
    image: ghcr.io/lordprime/goat-dvga
    digest: {D1}
    expect_tools: [curl, bash]
    role: target
    # tag sha-123456789abc; dvga {"c" * 40}; evaluator {"e" * 40}
"""
GOAT_SUMMARY = f"""## goat-dvga

Pushed `ghcr.io/lordprime/goat-dvga:sha-123456789abc`

**Digest:** `{D1}`

- dvga fork commit: `{"c" * 40}`
- CVE-Bench fork commit: `{"e" * 40}`

deploy/images.lock entry (commit it by hand, after review):

```yaml
{GOAT_ENTRY}```
"""


def _record(repo: Path, tmp_path: Path, pushed: str, **env: str) -> tuple[int, str, str]:
    (repo / "pushed.txt").write_text(pushed)
    rc, _, err = _bash(
        _step("image", "Record the digest")["run"],
        repo,
        tmp_path,
        TAG="sha-123456789abc",
        APP_COMMIT="c" * 40,
        EVAL_COMMIT="e" * 40,
        **env,
    )
    entry = (repo / "images.lock.entry.yml").read_text() if rc == 0 else ""
    return rc, entry, err


def test_record_of_a_goat_is_unchanged(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _source(repo, "targets/dvga/ci/expect_tools", "[curl, bash]\n")
    rc, entry, err = _record(
        repo,
        tmp_path,
        f"ghcr.io/lordprime/goat-dvga {D1}\n",
        LANE="goat",
        NAME="dvga",
        DIR="targets/dvga",
        ROLE="target",
        IMAGE="ghcr.io/lordprime/goat-dvga",
        APP_REPO="https://github.com/a/dvga",
    )
    assert rc == 0, err
    assert entry == GOAT_ENTRY
    assert (tmp_path / "summary").read_text() == GOAT_SUMMARY


def test_record_of_an_agent_with_an_extra_image(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "agents" / "redamon" / "ci").mkdir(parents=True)
    rc, entry, err = _record(
        repo,
        tmp_path,
        f"ghcr.io/lordprime/agent-redamon {D1}\nghcr.io/lordprime/agent-redamon-webapp {D2}\n",
        LANE="agent",
        NAME="redamon",
        DIR="agents/redamon",
        ROLE="agent",
        IMAGE="ghcr.io/lordprime/agent-redamon",
        APP_REPO="https://github.com/u/redamon",
    )
    assert rc == 0, err
    doc = yaml.safe_load(entry)
    assert doc == [
        {
            "name": "agent-redamon",
            "image": "ghcr.io/lordprime/agent-redamon",
            "digest": D1,
            "expect_tools": [],
            "role": "agent",
        },
        {
            "name": "agent-redamon-webapp",
            "image": "ghcr.io/lordprime/agent-redamon-webapp",
            "digest": D2,
            "expect_tools": [],
            "role": "agent",
        },
    ]
    assert f"redamon https://github.com/u/redamon {'c' * 40}" in entry
    summary = (tmp_path / "summary").read_text()
    assert summary.count("Pushed `") == 2
    assert f"- redamon upstream: https://github.com/u/redamon at `{'c' * 40}`" in summary


def test_record_of_an_agent_uses_its_expect_tools_for_the_main_image(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _source(repo, "agents/strix/ci/expect_tools", "[python, strix]\n")
    rc, entry, err = _record(
        repo,
        tmp_path,
        f"ghcr.io/lordprime/agent-strix {D1}\nghcr.io/lordprime/agent-strix-sandbox {D2}\n",
        LANE="agent",
        NAME="strix",
        DIR="agents/strix",
        ROLE="agent",
        IMAGE="ghcr.io/lordprime/agent-strix",
        APP_REPO="https://github.com/u/strix",
    )
    assert rc == 0, err
    doc = yaml.safe_load(entry)
    assert [d["expect_tools"] for d in doc] == [["python", "strix"], []]


@pytest.mark.parametrize("tools", ["[]\n", "python\n", "[$(id)]\n", ""])
def test_record_refuses_a_bad_tool_list(tools: str, tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    _source(repo, "agents/strix/ci/expect_tools", tools)
    rc, _, _ = _record(
        repo,
        tmp_path,
        f"ghcr.io/lordprime/agent-strix {D1}\n",
        LANE="agent",
        NAME="strix",
        DIR="agents/strix",
        ROLE="agent",
        IMAGE="ghcr.io/lordprime/agent-strix",
        APP_REPO="https://github.com/u/strix",
    )
    assert rc != 0


def _build(tmp_path: Path, listed: str, built: str) -> tuple[int, str]:
    """Run the Build step: build.sh lists ``listed``; the fake docker knows ``built``."""
    repo = tmp_path / "repo"
    _source(repo, "agents/strix/ci/build.sh", f"printf '{listed}' >> \"$EXTRA_IMAGES\"\n")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(f'#!/bin/sh\nfor i in {built}; do [ "$i" = "$3" ] && exit 0; done\nexit 1\n')
    docker.chmod(0o755)
    rc, _, err = _bash(
        _step("image", "Build")["run"],
        repo,
        tmp_path,
        DIR="agents/strix",
        LOCAL="agent-strix:ci",
        EXTRA_IMAGES=str(tmp_path / "extra"),
        GITHUB_REPOSITORY="o/r",
        GITHUB_SHA="0" * 40,
        RUNNER_TEMP=str(tmp_path),
        PATH=f"{bin_dir}:{os.environ['PATH']}",
    )
    return rc, err


def test_build_accepts_listed_extra_images_it_built(tmp_path: Path) -> None:
    rc, err = _build(
        tmp_path,
        "agent-strix-sandbox:ci\\nagent-strix-x2:ci\\n",
        "agent-strix-sandbox:ci agent-strix-x2:ci",
    )
    assert rc == 0, err


@pytest.mark.parametrize(
    ("listed", "built", "message"),
    [
        ("postgres:16\\n", "postgres:16", "bad extra image"),
        ("agent-other-x:ci\\n", "agent-other-x:ci", "bad extra image"),
        ("agent-strix-x:latest\\n", "agent-strix-x:latest", "bad extra image"),
        ("agent-strix-:ci\\n", "agent-strix-:ci", "bad extra image"),
        ("agent-strix-x:ci\\n", "", "did not build it"),
    ],
)
def test_build_refuses_bad_extra_images(
    listed: str, built: str, message: str, tmp_path: Path
) -> None:
    rc, err = _build(tmp_path, listed, built)
    assert rc != 0
    assert message in err


def test_push_pushes_only_declared_extras_that_were_built() -> None:
    run = _step("image", "Push")["run"]
    assert '"$DIR/ci/push_extra"' in run
    assert 'grep -qxF "$extra" "$EXTRA_IMAGES"' in run
    assert 'pairs+=("$extra $IMAGE-$part")' in run
    # every tag is checked before the first push
    assert run.index("already exists; choose a new version") < run.index("docker tag ")


@pytest.mark.parametrize("agent", AGENTS)
def test_every_agent_with_a_dockerfile_has_its_ci_scripts(agent: str) -> None:
    for name in ("source.yaml", "ci/build.sh", "ci/check.sh"):
        assert (ROOT / "agents" / agent / name).is_file(), f"agents/{agent}/{name} is missing"
    build = (ROOT / "agents" / agent / "ci" / "build.sh").read_text()
    assert f"-f agents/{agent}/Dockerfile" in build
    for name in ("build.sh", "check.sh"):
        mode = subprocess.run(  # noqa: S603 -- fixed argv
            ["git", "ls-files", "-s", f"agents/{agent}/ci/{name}"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split(" ", 1)[0]
        assert mode == "100755", f"agents/{agent}/ci/{name} is not executable in git"


def test_the_smoke_kit_build_context_is_admitted() -> None:
    admitted = {
        line[1:].strip().rstrip("/")
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.startswith("!")
    }
    dockerfile = ROOT / "agents" / "ci" / "stub_model" / "Dockerfile"
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if not parts or parts[0] != "COPY" or any(p.startswith("--from") for p in parts):
            continue
        for src in (p for p in parts[1:-1] if not p.startswith("--")):
            assert src in admitted or src.split("/", 1)[0] in admitted, src
        # and every copied path exists
        for src in (p for p in parts[1:-1] if not p.startswith("--")):
            assert (ROOT / src).exists(), src


@pytest.mark.parametrize(
    "dockerfile",
    [
        "agents/ci/stub_model/Dockerfile",
        "agents/_selfcheck/Dockerfile",
        "agents/_selfcheck/worker.Dockerfile",
    ],
)
def test_lane_images_pin_their_bases_by_digest(dockerfile: str) -> None:
    text = (ROOT / dockerfile).read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("ARG") and "_IMAGE=" in line:
            assert re.search(r"@sha256:[0-9a-f]{64}$", line), line
        if line.startswith("FROM"):
            assert "${" in line or " AS " in line, (
                f"{dockerfile}: FROM without a pinned ARG: {line}"
            )
