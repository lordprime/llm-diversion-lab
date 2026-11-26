"""agents/ci/smoke.sh, statically: its flags, its exit codes, its cleanup, and that the agent
never gets this machine's Docker socket.

Docker is never called for real: a fake ``docker`` (tests/agents/ci/fake_docker.py) first
on ``PATH`` logs every call and answers from environment variables. The real thing runs
in CI, where the agent lane's self-check (agents/_selfcheck/ci/check.sh) drives smoke.sh
through every exit code against real containers.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.deploy.test_scripts import SHELLCHECK_PY, SHFMT_PY, _require_tool

ROOT = Path(__file__).resolve().parents[3]
SMOKE = ROOT / "agents" / "ci" / "smoke.sh"
FAKE = Path(__file__).with_name("fake_docker.py")
IMAGE = "agent-strix:ci"
KIT = "lab-smoke-kit:ci"
PINNED = "docker.io/library/postgres:16@sha256:" + "a" * 64
LOCAL = "agent-redamon-webapp:ci"
HELPERS = ("stub", "canary", "holder", "agent")


@dataclass
class Smoke:
    """One smoke.sh invocation against the fake docker."""

    tmp: Path
    env: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE}" "$@"\n', encoding="utf-8")
        docker.chmod(0o755)
        (self.tmp / "state").mkdir()
        self.script = self.tmp / "script.yaml"
        self.script.write_text("turns: [{text: hi}]\n", encoding="utf-8")
        self.out = self.tmp / "out"
        self.log = self.tmp / "docker.log"
        self.log.touch()
        self.env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_DOCKER_LOG": str(self.log),
            "FAKE_DOCKER_STATE": str(self.tmp / "state"),
            "FAKE_IMAGES": f"{IMAGE} {KIT} {LOCAL}",
            "SMOKE_OUT": str(self.out),
            **self.env,
        }

    def run(self, *args: str, bare: bool = False, **env: str) -> subprocess.CompletedProcess[str]:
        """Run smoke.sh with ``args``; with none (and not ``bare``), with a valid minimal set."""
        argv = list(args)
        if not argv and not bare:
            argv = ["--image", IMAGE, "--name", "strix", "--script", str(self.script)]
        return subprocess.run(  # noqa: S603 -- the script under test
            ["bash", str(SMOKE), *argv],  # noqa: S607
            env={**self.env, **env},
            capture_output=True,
            text=True,
            timeout=60,
            cwd=self.tmp,
        )

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]

    def args_of(self, helper: str) -> list[str]:
        (path,) = (self.tmp / "state").glob(f"*-{helper}.json")
        args: list[str] = json.loads(path.read_text(encoding="utf-8"))
        return args

    def index(self, prefix: list[str]) -> int:
        return next(i for i, c in enumerate(self.calls()) if c[: len(prefix)] == prefix)


@pytest.fixture
def smoke(tmp_path: Path) -> Iterator[Smoke]:
    yield Smoke(tmp_path)


def _base(smoke: Smoke, *extra: str) -> list[str]:
    return ["--image", IMAGE, "--name", "strix", "--script", str(smoke.script), *extra]


# --------------------------------------------------------------------------- static


def test_strict_mode_shebang_and_exec_bit() -> None:
    text = SMOKE.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert re.search(r"^set -Eeuo pipefail$", text, re.MULTILINE)
    mode = subprocess.run(
        ["git", "ls-files", "-s", "agents/ci/smoke.sh"],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split(" ", 1)[0]
    assert mode == "100755", f"agents/ci/smoke.sh is not executable in git ({mode or 'untracked'})"


def test_shellcheck_and_shfmt_clean() -> None:
    scripts = [str(SMOKE), *map(str, sorted((ROOT / "agents").glob("*/ci/*.sh")))]
    shellcheck = _require_tool("shellcheck", SHELLCHECK_PY)
    result = subprocess.run(  # noqa: S603 -- fixed argv
        [*shellcheck, "--severity=style", *scripts], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    shfmt = _require_tool("shfmt", SHFMT_PY)
    result = subprocess.run([*shfmt, "-d", *scripts], capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help(smoke: Smoke, flag: str) -> None:
    result = smoke.run(flag)
    assert result.returncode == 0 and result.stderr == ""
    assert result.stdout.startswith("Usage: smoke.sh --image")
    for documented in ("--docker", "--worker-image", "--timeout", "10 egress", "11 timeout"):
        assert documented in result.stdout
    assert smoke.calls() == []


def test_the_header_documents_every_exit_status() -> None:
    header = SMOKE.read_text(encoding="utf-8").split("set -Eeuo pipefail", 1)[0]
    for code in ("0 ", "2 ", "3 ", "10 ", "11 ", "12 "):
        assert re.search(rf"^#\s+{code}", header, re.MULTILINE), f"exit status {code}undocumented"


# --------------------------------------------------------------------------- usage errors


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "--image is required"),
        (["--name", "strix"], "--image is required"),
        (["--image", IMAGE], "--name is required"),
        (["--image", IMAGE, "--name", "Strix"], "not an agent name"),
        (["--image", IMAGE, "--name", "../strix"], "not an agent name"),
        (["--image", IMAGE, "--name", "-strix"], "not an agent name"),
        (["--image", IMAGE, "--name", "__x"], "not an agent name"),
        (["--image", IMAGE, "--name", "a" * 42], "not an agent name"),
        (["--image", IMAGE, "--name", "strix; rm -rf /"], "not an agent name"),
        (["--image", IMAGE, "--name", "strix"], "--script is required"),
        (["--image", IMAGE, "--name", "strix", "--script", "/nonexistent"], "no such file"),
        (["--image", IMAGE, "--name", "strix", "--script", "/"], "no such file"),
        (["--image"], "--image needs a value"),
        (["--image", ""], "--image needs a value"),
        (["--bogus"], "unknown argument: --bogus"),
        (["strix"], "unknown argument: strix"),
    ],
)
def test_bad_arguments_are_refused_before_docker_runs(
    smoke: Smoke, args: list[str], message: str
) -> None:
    result = smoke.run(*args, bare=True)
    assert result.returncode == 2, result.stderr
    assert message in result.stderr
    assert smoke.calls() == []


@pytest.mark.parametrize(
    ("extra", "message"),
    [
        (["--env-file", "/nonexistent.env"], "--env-file: no such file"),
        (["--timeout", "0"], "--timeout"),
        (["--timeout", "-5"], "--timeout"),
        (["--timeout", "1.5"], "--timeout"),
        (["--timeout", "999999"], "--timeout"),
        (["--timeout", "ten"], "--timeout"),
        (["--cap-add", "SYS_ADMIN"], "never granted"),
        (["--cap-add", "NET_ADMIN"], "never granted"),
        (["--cap-add", "ALL"], "never granted"),
        (["--cap-add", "net_raw"], "not a capability"),
        (["--worker-image", PINNED], "--worker-image needs --docker"),
        (["--docker", "--worker-image", "ghcr.io/x/worker:latest"], "must be pinned by digest"),
        (["--docker", "--worker-image", "Upper/Case"], "not an image reference"),
        (["--docker", "--worker-image", "x@sha256:short"], "not an image reference"),
        (["--docker", "--worker-image", "$(id)"], "not an image reference"),
    ],
)
def test_bad_options_are_refused_before_docker_runs(
    smoke: Smoke, extra: list[str], message: str
) -> None:
    result = smoke.run(*_base(smoke, *extra))
    assert result.returncode == 2, result.stderr
    assert message in result.stderr
    assert smoke.calls() == []


@pytest.mark.parametrize("value", ["0", "abc", "-1", "99999", ""])
def test_a_bad_start_timeout_is_refused(smoke: Smoke, value: str) -> None:
    result = smoke.run(SMOKE_START_TIMEOUT=value)
    if value == "":
        assert result.returncode == 0  # empty means the default
        return
    assert result.returncode == 2 and "SMOKE_START_TIMEOUT" in result.stderr
    assert smoke.calls() == []


def test_an_output_directory_is_required(smoke: Smoke) -> None:
    env = dict(smoke.env)
    del env["SMOKE_OUT"]
    smoke.env = env
    result = smoke.run()
    assert result.returncode == 2 and "set SMOKE_OUT or pass --out" in result.stderr
    result = smoke.run(*_base(smoke, "--out", str(smoke.tmp / "elsewhere")))
    assert result.returncode == 0, result.stderr
    assert (smoke.tmp / "elsewhere" / "requests.jsonl").is_file()


def test_an_invalid_stub_script_is_a_usage_error(smoke: Smoke) -> None:
    result = smoke.run(FAKE_SCRIPT_VALID="0")
    assert result.returncode == 2 and "not a valid stub script" in result.stderr
    assert not any(c[:2] == ["network", "create"] for c in smoke.calls())


# --------------------------------------------------------------------------- whole runs


def test_a_clean_run_passes_and_collects_everything(smoke: Smoke) -> None:
    result = smoke.run(
        *_base(smoke, "--timeout", "30", "--cap-add", "NET_RAW", "--", "strix", "--target", "x y"),
        FAKE_REQUESTS='{"seq":0}\n',
    )
    assert result.returncode == 0, result.stderr
    assert "strix passed" in result.stderr
    for name in ("requests.jsonl", "canary.jsonl", "agent.log", "agent.exit", "stub.log"):
        assert (smoke.out / name).is_file(), name
    assert (smoke.out / "agent.exit").read_text() == "0\n"
    agent = smoke.args_of("agent")
    # the image, then the command exactly as given
    assert agent[agent.index(IMAGE) :] == [IMAGE, "strix", "--target", "x y"]
    for expected in (
        ["--read-only"],
        ["--cap-drop", "ALL"],
        ["--cap-add", "NET_RAW"],
        ["--security-opt", "no-new-privileges:true"],
        ["--pids-limit", "512"],
    ):
        assert any(agent[i : i + len(expected)] == expected for i in range(len(agent)))
    network = agent[agent.index("--network") + 1]
    assert network.startswith("container:smoke-strix-") and network.endswith("-holder")
    joined = " ".join(agent)
    assert "--privileged" not in agent
    for variable in ("DOCKER_HOST", "LAB_RUN_ID", "LAB_SCRATCH_VOLUME"):
        assert variable not in joined  # only with --docker


def test_the_network_is_internal_and_tap_is_the_stub(smoke: Smoke) -> None:
    assert smoke.run().returncode == 0
    (create,) = [c for c in smoke.calls() if c[:2] == ["network", "create"]]
    assert "--internal" in create
    stub = smoke.args_of("stub")
    assert stub[stub.index("--network-alias") + 1] == "tap"
    canary = smoke.args_of("canary")
    assert canary[canary.index("--allow") + 1] == "tap=172.30.0.2"
    assert canary[
        canary.index("NET_RAW") - 1 : canary.index("NET_RAW") + 1
    ] == ["--cap-add", "NET_RAW"]
    holder = smoke.args_of("holder")
    assert "ip route replace default via 172.30.0.3" in holder[-1]
    hosts = (smoke.tmp / "state").glob("*-agent.hosts")
    assert "172.30.0.2\ttap" in next(hosts).read_text()
    resolv = next((smoke.tmp / "state").glob("*-agent.resolv.conf")).read_text()
    assert resolv == "nameserver 172.30.0.3\n"


def test_cleanup_removes_everything_after_a_pass(smoke: Smoke) -> None:
    assert smoke.run().returncode == 0
    _assert_cleaned_up(smoke)


def _assert_cleaned_up(smoke: Smoke) -> None:
    calls = smoke.calls()
    removed = [c for c in calls if c[:2] == ["rm", "-f"]]
    assert removed, "no container was removed"
    names = removed[-1][2:]
    assert {n.rsplit("-", 1)[-1] for n in names} >= {"agent", "holder", "guard", "canary", "stub"}
    assert calls[-1][:2] == ["network", "rm"]


@pytest.mark.parametrize(
    ("env", "status", "message"),
    [
        ({"FAKE_CANARY": '{"kind":"dns"}\n'}, 10, "the egress canary saw"),
        ({"FAKE_AGENT_EXIT": "3"}, 12, "the agent failed"),
        ({"FAKE_AGENT_EXIT": "hang"}, 11, "ran longer than 2s"),
        # egress is reported first, whatever else went wrong
        ({"FAKE_AGENT_EXIT": "hang", "FAKE_CANARY": "{}\n"}, 10, "the egress canary saw"),
        ({"FAKE_AGENT_EXIT": "1", "FAKE_CANARY": "{}\n"}, 10, "the egress canary saw"),
        ({"FAKE_AGENT_EXIT": "1"}, 12, "fake log line"),
    ],
)
def test_exit_statuses(smoke: Smoke, env: dict[str, str], status: int, message: str) -> None:
    result = smoke.run(*_base(smoke, "--timeout", "2"), **env)
    assert result.returncode == status, result.stderr
    assert message in result.stderr
    _assert_cleaned_up(smoke)
    if status == 11:
        assert any(c[0] == "kill" for c in smoke.calls())
        assert (smoke.out / "agent.exit").read_text() == "timeout\n"


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({"FAKE_IMAGES": KIT}, "agent image not found"),
        ({"FAKE_IMAGES": IMAGE}, "smoke kit image not found"),
        ({"FAKE_FAIL": "network create"}, "command failed"),
        ({"FAKE_FAIL": "cp"}, "command failed"),
        ({"FAKE_FAIL": "exec"}, "did not come up"),
        ({"FAKE_DEAD": "-canary"}, "stopped during the run"),
        ({"FAKE_DEAD": "-stub"}, "stopped during the run"),
    ],
)
def test_smoke_failures_exit_3_and_still_clean_up(
    smoke: Smoke, env: dict[str, str], message: str
) -> None:
    result = smoke.run(SMOKE_START_TIMEOUT="1", **env)
    assert result.returncode == 3, result.stderr
    assert message in result.stderr
    if not message.endswith("image not found"):
        _assert_cleaned_up(smoke)


def test_stale_outputs_are_cleared(smoke: Smoke) -> None:
    smoke.out.mkdir()
    (smoke.out / "canary.jsonl").write_text("stale\n")
    (smoke.out / "unrelated.txt").write_text("kept\n")
    assert smoke.run().returncode == 0
    assert (smoke.out / "canary.jsonl").read_text() == ""
    assert (smoke.out / "unrelated.txt").read_text() == "kept\n"


def test_the_env_file_reaches_only_the_agent(smoke: Smoke) -> None:
    env_file = smoke.tmp / "agent.env"
    env_file.write_text("OLLAMA_HOST=http://tap:8000\n")
    assert smoke.run(*_base(smoke, "--env-file", str(env_file))).returncode == 0
    agent = smoke.args_of("agent")
    assert agent[agent.index("--env-file") + 1] == str(env_file)
    for helper in ("stub", "canary", "holder"):
        assert "--env-file" not in smoke.args_of(helper)


# --------------------------------------------------------------------------- --docker


def _lock(smoke: Smoke) -> Any:
    (path,) = (smoke.tmp / "state").glob("*-guard.images.lock")
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_docker_mode_puts_cell_guard_in_front(smoke: Smoke) -> None:
    extra = smoke.tmp / "extra-images"
    extra.write_text(f"{LOCAL}\n")
    result = smoke.run(
        *_base(smoke, "--docker", "--worker-image", PINNED, "--worker-image", LOCAL),
        EXTRA_IMAGES=str(extra),
        FAKE_WORKERS="w1 w2",
    )
    assert result.returncode == 0, result.stderr
    guard = smoke.args_of("guard")
    env = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in guard if a.startswith("LAB_")}
    net = smoke.args_of("stub")[smoke.args_of("stub").index("--network") + 1]
    assert env["LAB_CELLGUARD_NETWORK"] == net
    assert env["LAB_CELLGUARD_DNS"] == "172.30.0.3"  # the canary
    assert re.fullmatch(r"run_[0-9A-HJKMNP-TV-Z]{26}", env["LAB_RUN_ID"])
    assert env["LAB_CELLGUARD_LISTEN"] == "/run/cellguard/docker.sock"
    # run as cell_spec runs it
    for flag in ("--read-only", "--init"):
        assert flag in guard
    assert guard[guard.index("--network") + 1] == "none"
    assert guard[guard.index("--cap-drop") + 1] == "ALL"
    assert guard[-3:] == ["python", "-m", "cell.cellguard.proxy"]
    assert "/var/run/docker.sock:/var/run/docker.sock" in guard
    # the agent gets the guard's socket volume, never the real socket
    agent = smoke.args_of("agent")
    guard_volume = next(v for v in guard[1:] if v.endswith(":/run/cellguard"))
    assert guard_volume in agent
    assert "DOCKER_HOST=unix:///run/cellguard/docker.sock" in agent
    assert f"LAB_RUN_ID={env['LAB_RUN_ID']}" in agent
    assert f"LAB_SCRATCH_VOLUME={env['LAB_CELLGUARD_SCRATCH_VOLUME']}" in agent
    assert env["LAB_CELLGUARD_SCRATCH_VOLUME"].endswith("-scratch")
    assert ["volume", "create", env["LAB_CELLGUARD_SCRATCH_VOLUME"]] in smoke.calls()
    assert not any("docker.sock:" in a for a in agent)
    # the allow-list: the pinned worker by its digest, the local one by its image id
    assert _lock(smoke) == {
        "images": [
            {
                "name": "worker-1",
                "image": "docker.io/library/postgres:16",
                "digest": "sha256:" + "a" * 64,
                "role": "agent",
            },
            {
                "name": "worker-2",
                "image": "agent-redamon-webapp",
                "digest": "sha256:" + "1" * 64,
                "role": "agent",
            },
        ]
    }
    assert ["pull", "--quiet", PINNED] in smoke.calls()
    # guard-started workers: logs kept, then removed by their run label
    assert sorted(p.name for p in (smoke.out / "workers").iterdir()) == ["w1.log", "w2.log"]
    label = f"label=lab.run_id={env['LAB_RUN_ID']}"
    assert ["ps", "-aq", "--filter", label] in smoke.calls()
    assert ["volume", "ls", "-q", "--filter", label] in smoke.calls()
    assert ["rm", "-f", "w1", "w2"] in smoke.calls()
    assert (smoke.out / "cellguard.jsonl").read_text() == '{"allowed":false}\n'


def test_the_allow_list_is_valid_for_cell_guard(smoke: Smoke) -> None:
    from cell.cellguard.policy import load_images_lock

    extra = smoke.tmp / "extra-images"
    extra.write_text(f"{LOCAL}\n")
    smoke.run(
        *_base(smoke, "--docker", "--worker-image", PINNED, "--worker-image", LOCAL),
        EXTRA_IMAGES=str(extra),
    )
    images = load_images_lock(_lock(smoke))
    assert [i.pinned for i in images] == [
        "docker.io/library/postgres@sha256:" + "a" * 64,
        "docker.io/library/agent-redamon-webapp@sha256:" + "1" * 64,
    ]
    assert {i.role for i in images} == {"agent"}


def test_docker_mode_without_workers_has_an_empty_allow_list(smoke: Smoke) -> None:
    assert smoke.run(*_base(smoke, "--docker")).returncode == 0
    assert _lock(smoke) == {"images": []}


@pytest.mark.parametrize(
    ("listed", "images", "message"),
    [
        (None, f"{IMAGE} {KIT} {LOCAL}", "not listed in $EXTRA_IMAGES"),
        ("agent-other:ci\n", f"{IMAGE} {KIT} {LOCAL}", "not listed in $EXTRA_IMAGES"),
        (f"{LOCAL}\n", f"{IMAGE} {KIT}", "is listed but was not built"),
    ],
)
def test_a_local_worker_must_be_built_and_listed_by_this_job(
    smoke: Smoke, listed: str | None, images: str, message: str
) -> None:
    env = {"FAKE_IMAGES": images}
    if listed is not None:
        extra = smoke.tmp / "extra-images"
        extra.write_text(listed)
        env["EXTRA_IMAGES"] = str(extra)
    result = smoke.run(*_base(smoke, "--docker", "--worker-image", LOCAL), **env)
    assert result.returncode == 2, result.stderr
    assert message in result.stderr
    assert not any(c[:2] == ["network", "create"] for c in smoke.calls())


def test_an_unpinned_docker_hub_name_is_refused(smoke: Smoke) -> None:
    # it looks local, but nothing in this job built it
    result = smoke.run(*_base(smoke, "--docker", "--worker-image", "postgres:16"))
    assert result.returncode == 2 and "not pinned by digest" in result.stderr


def test_a_pinned_worker_that_cannot_be_pulled_is_a_smoke_failure(smoke: Smoke) -> None:
    result = smoke.run(*_base(smoke, "--docker", "--worker-image", PINNED), FAKE_FAIL="pull")
    assert result.returncode == 3 and "cannot pull worker image" in result.stderr


@pytest.mark.parametrize(
    "mount",
    [
        "bind /var/run/docker.sock /var/run/docker.sock",
        "bind /var/run/docker.sock /tmp/d.sock",
        "bind /home/runner/x /run/cellguard",
        "volume somevol /data",
    ],
)
def test_an_agent_that_would_see_another_mount_is_never_started(smoke: Smoke, mount: str) -> None:
    result = smoke.run(*_base(smoke, "--docker"), FAKE_EXTRA_MOUNT=mount)
    assert result.returncode == 3, result.stderr
    assert "unexpected mount" in result.stderr or "would see the Docker socket" in result.stderr
    assert not any(c[0] == "start" and c[-1].endswith("-agent") for c in smoke.calls())
    _assert_cleaned_up(smoke)


def test_without_docker_mode_the_guard_volume_is_refused_too(smoke: Smoke) -> None:
    result = smoke.run(FAKE_EXTRA_MOUNT="volume x-guard /run/cellguard")
    assert result.returncode == 3 and "unexpected mount" in result.stderr
