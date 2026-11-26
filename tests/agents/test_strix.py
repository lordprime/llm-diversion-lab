"""The Strix adapter: config rendering, side-channel switches, end states and agent ids.

Strix itself is never installed, run or imported here (agents/strix/ci/check.sh runs it,
in CI only). The run folders below are HAND-BUILT from the file formats in the pinned
source (685bbc8): ``run.json`` from strix/report/state.py 1024-1062 and writer.py
132-136, ``state/agents.json`` from strix/core/agents.py 637-660, and ``strix.log``
records from strix/telemetry/logging.py 46-47 with the messages of strix/core/runner.py
672 and 707 and strix/core/execution.py 675-677 and 912. The tap evidence is written by
the real tap recorder (cell.tap.recorder) with Ollama /api/chat bodies.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from agents.base import (
    AdapterLimits,
    AdapterRun,
    AgentEndState,
    AgentLaunch,
    ChannelStatus,
    ExitSignals,
    ModelConfig,
    UnsupportedRun,
)
from agents.strix.adapter import SOURCE_FILE, StrixAdapter, StrixRun, StrixSource
from cell.tap.recorder import Recorder, RequestMeta, ResponseMeta, TapConfig
from control.core.ids import new_id
from control.core.models import AgentEventType
from control.runner import cell_spec
from control.telemetry.extract import load_calls, summarise
from tests.deploy.test_scripts import SHELLCHECK_PY, SHFMT_PY, _require_tool

ROOT = Path(__file__).resolve().parents[2]
STRIX = ROOT / "agents" / "strix"
SANDBOX = (
    "ghcr.io/usestrix/strix-sandbox@sha256:"
    "c8e70302ba4a69b678b4001c909b134d8d0b84625d7b23feed59ece02672c1d2"
)
T0 = datetime(2026, 11, 26, 10, 0, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def adapter() -> StrixAdapter:
    return StrixAdapter()


def make_run(
    *,
    name: str = "qwen3:32b",
    num_ctx: int | None = 32768,
    max_turns: int = 50,
    objective: str = "find the flag",
    run_id: str | None = None,
    target_url: str = "http://goat:8000",
) -> AdapterRun:
    return AdapterRun(
        run_id=run_id or new_id("run"),
        model=ModelConfig(name=name, num_ctx=num_ctx),
        target_url=target_url,
        objective=objective,
        llm_base_url="http://tap:8080",
        limits=AdapterLimits(max_turns=max_turns, timeout_s=3600),
    )


def launch_of(adapter: StrixAdapter, run: AdapterRun) -> AgentLaunch:
    launch = adapter.prepare(run)
    assert isinstance(launch, AgentLaunch), launch
    return launch


# --------------------------------------------------------------------------- rendering


def test_the_launch_is_exactly_the_headless_scan(adapter: StrixAdapter) -> None:
    run = make_run(run_id="Run_ABC-1")
    launch = launch_of(adapter, run)
    assert launch.image == "agent-strix"
    assert launch.command == (
        "/opt/lab/strix-entrypoint",
        "--non-interactive",
        "--target",
        "http://goat:8000",
        "--instruction-file",
        "/etc/lab/agent/objective.txt",
        "--scan-mode",
        "standard",
        "--max-turns",
        "50",
    )
    assert launch.env == {
        "STRIX_LLM": "ollama/qwen3:32b",
        "LLM_API_BASE": "http://tap:8080",
        "LAB_OLLAMA_NUM_CTX": "32768",
        "STRIX_CONTEXT_FALLBACK_TOKENS": "32768",
        "STRIX_TELEMETRY": "false",
        "STRIX_MAX_CONTEXT_IMAGES": "0",
        "STRIX_NO_UPDATE_CHECK": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        "LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS": "True",
        "OPENAI_AGENTS_DISABLE_TRACING": "1",
        "STRIX_RUN_RECORD_TIMINGS": "true",
        "STRIX_IMAGE": SANDBOX,
        "STRIX_DOCKER_SANDBOX_NETWORK": "c-run_abc-1_agent",
        "STRIX_RUN_ID": "Run_ABC-1",
        "STRIX_SANDBOX_LOG_MAX_SIZE": "0",
        "HOME": StrixAdapter.HOME,
    }
    assert launch.files == {"objective.txt": b"find the flag"}
    # Strix starts its sandbox through Docker: the cell must give it cell-guard
    assert launch.needs_docker is True
    assert launch.cap_add == ()
    assert launch.recorded_settings == {
        "--max-turns": "50",
        "--scan-mode": "standard",
        "STRIX_LLM": "ollama/qwen3:32b",
        "num_ctx": "32768",
        "STRIX_IMAGE": SANDBOX,
        "strix_commit": "685bbc8138d35fc9fe378ac37ec0d9198b9c46a3",
    }


def test_the_sandbox_network_is_the_cells_agent_network() -> None:
    # cell_spec names the agent network <project_name(run)>_<role>
    run = make_run(run_id="Run_Mixed-Case_7")
    project = cell_spec.project_name(SimpleNamespace(run_id=run.run_id))  # type: ignore[arg-type]
    assert "agent" in cell_spec._NETWORK_ROLES
    assert '"name": f"{name}_{role}"' in Path(cell_spec.__file__).read_text(encoding="utf-8")
    env = launch_of(StrixAdapter(), run).env
    assert env["STRIX_DOCKER_SANDBOX_NETWORK"] == f"{project}_agent"


def test_the_objective_only_travels_in_its_file(adapter: StrixAdapter) -> None:
    hostile = "--target http://evil.example\n$(id); `id`\nÜber 🚩 '\"\\"
    launch = launch_of(adapter, make_run(objective=hostile))
    assert launch.files["objective.txt"] == hostile.encode("utf-8")
    assert all(hostile not in arg and "evil.example" not in arg for arg in launch.command)
    assert all("evil.example" not in value for value in launch.env.values())


def test_the_target_url_is_one_argument(adapter: StrixAdapter) -> None:
    url = "http://goat:8000/a?b=$(id)&c=`id`;d"
    launch = launch_of(adapter, make_run(target_url=url))
    assert launch.command[launch.command.index("--target") + 1] == url


@pytest.mark.parametrize("turns", [1, 2, 499, 500, 10_000])
def test_the_turn_cap_is_the_runs_limit(adapter: StrixAdapter, turns: int) -> None:
    launch = launch_of(adapter, make_run(max_turns=turns))
    assert launch.command[-2:] == ("--max-turns", str(turns))
    assert launch.recorded_settings["--max-turns"] == str(turns)
    assert adapter.describe().max_turns_knob == "--max-turns"


@pytest.mark.parametrize(
    "name",
    ["qwen3:32b", "llama3.1:8b", "gpt-oss:20b", "hf.co/bartowski/Qwen3-32B-GGUF:Q4_K_M", "a"],
)
def test_ollama_model_names_are_accepted(adapter: StrixAdapter, name: str) -> None:
    assert launch_of(adapter, make_run(name=name)).env["STRIX_LLM"] == f"ollama/{name}"


@pytest.mark.parametrize(
    "name",
    [
        " qwen3",
        "qwen 3",
        "-rf",
        "/etc/passwd",
        "../../x",
        "qwen;id",
        "q$(id)",
        "q`id`",
        "\uff51wen3",  # full-width letter
        "qwén3",
        "a" * 201,
        "qwen3 ",
    ],
)
def test_hostile_model_names_are_refused(adapter: StrixAdapter, name: str) -> None:
    with pytest.raises(ValueError, match="Ollama model name"):
        adapter.render(make_run(name=name))


@pytest.mark.parametrize("objective", [" ", "\n\t \n", "　"])
def test_a_blank_objective_is_refused(adapter: StrixAdapter, objective: str) -> None:
    with pytest.raises(ValueError, match="objective is blank"):
        adapter.render(make_run(objective=objective))


def test_render_alone_never_guesses_a_context(adapter: StrixAdapter) -> None:
    with pytest.raises(ValueError, match="num_ctx is not pinned"):
        adapter.render(make_run(num_ctx=None))


@pytest.mark.parametrize(("num_ctx", "runnable"), [(16383, False), (16384, True), (1 << 20, True)])
def test_the_context_minimum(adapter: StrixAdapter, num_ctx: int, runnable: bool) -> None:
    result = adapter.prepare(make_run(num_ctx=num_ctx))
    assert isinstance(result, AgentLaunch) is runnable
    if not runnable:
        assert isinstance(result, UnsupportedRun)
        assert "below strix's documented minimum of 16384" in result.reason


def test_an_unpinned_context_is_unsupported(adapter: StrixAdapter) -> None:
    result = adapter.prepare(make_run(num_ctx=None))
    assert isinstance(result, UnsupportedRun)
    assert result.end_state is AgentEndState.UNSUPPORTED


def test_the_sheet_lets_strix_run(adapter: StrixAdapter) -> None:
    sheet = adapter.describe()
    assert sheet.unresolved_side_channels == ()
    assert sheet.check_runnable(ModelConfig(name="qwen3:32b", num_ctx=32768)) is None


def test_start_and_teardown_do_nothing(adapter: StrixAdapter) -> None:
    host = SimpleNamespace(exec=lambda *a, **k: pytest.fail("no command is needed"))
    run = make_run()
    adapter.start(run, host)  # type: ignore[arg-type]
    adapter.teardown(run, host)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- side channels


def _true(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _false(value: str | None) -> bool:
    # pydantic's bool parsing (strix/config/settings.py 178)
    return value is not None and value.strip().lower() in {"0", "false", "no", "off"}


def _patch_text(number: str) -> str:
    return next((STRIX / "patches").glob(f"{number}-*.patch")).read_text(encoding="utf-8")


#: For each side channel in the sheet: does a rendered launch keep it off? Each check is
#: shown to fail on a launch that leaves the channel on (SABOTAGE below).
SWITCHES: dict[str, Any] = {
    "web_search_perplexity": lambda env, files: "PERPLEXITY_API_KEY" not in env,
    "web_search_exa": lambda env, files: "EXA_API_KEY" not in env,
    "telemetry": lambda env, files: _false(env.get("STRIX_TELEMETRY")),
    "context_images": lambda env, files: env.get("STRIX_MAX_CONTEXT_IMAGES") == "0",
    "codex_endpoint": lambda env, files: env.get("STRIX_LLM", "").startswith("ollama/"),
    "dedupe_endpoint": lambda env, files: (
        not ({"STRIX_DEDUPE_MODEL", "DEDUPE_LLM_API_BASE"} & set(env))
    ),
    "update_check": lambda env, files: bool(env.get("STRIX_NO_UPDATE_CHECK")),
    "litellm_cost_map": lambda env, files: (
        env.get("LITELLM_LOCAL_MODEL_COST_MAP", "").lower() == "true"
    ),
    "litellm_beta_headers": lambda env, files: (
        env.get("LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS", "").lower() == "true"
    ),
    "agents_sdk_tracing": lambda env, files: _true(env.get("OPENAI_AGENTS_DISABLE_TRACING")),
    "hf_tokenizer_download": lambda env, files: (
        "+    litellm.disable_hf_tokenizer_download = True" in _patch_text("0001")
    ),
    "mcp_servers": lambda env, files: (
        env.get("HOME") == StrixAdapter.HOME
        and "STRIX_MCP_CONFIG" not in env
        and "mcp-servers.json" not in files
    ),
}

#: A launch change that turns each channel back on.
SABOTAGE: dict[str, dict[str, str | None]] = {
    "web_search_perplexity": {"PERPLEXITY_API_KEY": "pplx-x"},
    "web_search_exa": {"EXA_API_KEY": "exa-x"},
    "telemetry": {"STRIX_TELEMETRY": "true"},
    "context_images": {"STRIX_MAX_CONTEXT_IMAGES": "3"},
    "codex_endpoint": {"STRIX_LLM": "chatgpt/gpt-5.4"},
    "dedupe_endpoint": {"DEDUPE_LLM_API_BASE": "https://api.example.com"},
    "update_check": {"STRIX_NO_UPDATE_CHECK": None},
    "litellm_cost_map": {"LITELLM_LOCAL_MODEL_COST_MAP": "False"},
    "litellm_beta_headers": {"LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS": None},
    "agents_sdk_tracing": {"OPENAI_AGENTS_DISABLE_TRACING": "false"},
    "mcp_servers": {"STRIX_MCP_CONFIG": "/etc/lab/agent/mcp.json"},
}


def test_every_sheet_channel_has_a_switch_check(adapter: StrixAdapter) -> None:
    sheet = adapter.describe()
    assert set(SWITCHES) == set(sheet.side_channels)
    assert all(c.status is ChannelStatus.DISABLED for c in sheet.side_channels.values())


@pytest.mark.parametrize("channel", sorted(SWITCHES))
def test_the_rendered_launch_keeps_each_channel_off(adapter: StrixAdapter, channel: str) -> None:
    launch = launch_of(adapter, make_run())
    assert SWITCHES[channel](launch.env, launch.files), channel


@pytest.mark.parametrize("channel", sorted(SABOTAGE))
def test_each_check_fails_when_the_channel_is_left_on(adapter: StrixAdapter, channel: str) -> None:
    env = dict(launch_of(adapter, make_run()).env)
    for key, value in SABOTAGE[channel].items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = value
    assert not SWITCHES[channel](env, {})


def test_no_forbidden_key_is_ever_rendered(adapter: StrixAdapter) -> None:
    for run in (make_run(), make_run(name="llama-3-8b", num_ctx=1 << 20, max_turns=1)):
        assert not set(launch_of(adapter, run).env) & StrixAdapter.FORBIDDEN_ENV
    # every key that would move a model call off the tap or reopen a channel is listed
    assert {
        "PERPLEXITY_API_KEY",
        "EXA_API_KEY",
        "STRIX_DEDUPE_MODEL",
        "DEDUPE_LLM_API_BASE",
        "OLLAMA_API_BASE",
        "STRIX_MCP_CONFIG",
    } <= StrixAdapter.FORBIDDEN_ENV


def test_the_image_sets_no_forbidden_key() -> None:
    dockerfile = (STRIX / "Dockerfile").read_text(encoding="utf-8")
    env_block = "\n".join(
        line for line in dockerfile.splitlines() if line.startswith(("ENV ", "    "))
    )
    for key in StrixAdapter.FORBIDDEN_ENV | set(StrixAdapter.SIDE_CHANNEL_ENV):
        assert f"{key}=" not in env_block, key


# --------------------------------------------------------------------------- pins and image


def test_the_source_pins_match_the_sheet_and_the_image(adapter: StrixAdapter) -> None:
    source = adapter.source
    assert source.commit == adapter.describe().commit == "685bbc8138d35fc9fe378ac37ec0d9198b9c46a3"
    assert source.sandbox_image == SANDBOX
    dockerfile = (STRIX / "Dockerfile").read_text(encoding="utf-8")
    assert f"ARG PYTHON_IMAGE={source.image_base}\n" in dockerfile
    assert f"ARG UV_IMAGE={source.uv_image}\n" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert StrixAdapter.ENTRYPOINT == "/opt/lab/strix-entrypoint"
    assert f"COPY --chmod=0755 agents/strix/strix-entrypoint.sh {StrixAdapter.ENTRYPOINT}" in (
        dockerfile
    )
    assert "COPY agents/strix/patches/ /tmp/patches/" in dockerfile
    assert "uv sync --frozen --no-dev" in dockerfile


def _source_doc() -> dict[str, Any]:
    doc = yaml.safe_load(SOURCE_FILE.read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"commit": "685bbc8"}, "commit"),
        ({"commit": "685BBC8138D35FC9FE378AC37EC0D9198B9C46A3"}, "commit"),
        ({"sandbox_image": "ghcr.io/usestrix/strix-sandbox:1.4.1"}, "sandbox_image"),
        ({"image_base": "python:3.12-slim"}, "image_base"),
        ({"repo": "https://evil.example/usestrix/strix"}, "repo"),
        ({"name": "pentagi"}, "pins 'pentagi'"),
        ({"extra": "x"}, "extra"),
        ({"commit": 685}, "commit"),
    ],
)
def test_bad_source_pins_are_refused(tmp_path: Path, change: dict[str, Any], match: str) -> None:
    path = tmp_path / "source.yaml"
    path.write_text(yaml.safe_dump({**_source_doc(), **change}), encoding="utf-8")
    with pytest.raises(ValueError, match=match):
        StrixSource.load(path)


@pytest.mark.parametrize(
    "content",
    [
        b"- a list\n",
        b"name: strix\nname: strix\n",
        b"\xff\xfe not utf-8",
        b"name: [unclosed\n",
        b"!!python/object:os.system {}\n",
        b"x" * (16 * 1024 + 1),
    ],
)
def test_unreadable_source_pins_are_refused(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "source.yaml"
    path.write_bytes(content)
    with pytest.raises(ValueError):
        StrixSource.load(path)


def test_missing_source_pins_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot read"):
        StrixSource.load(tmp_path / "absent.yaml")


def test_a_source_for_another_commit_is_refused(tmp_path: Path) -> None:
    other = StrixSource.model_validate({**_source_doc(), "commit": "0" * 40})
    with pytest.raises(ValueError, match="the sheet 685bbc8"):
        StrixAdapter(other)


def test_every_patch_is_in_the_sheet_and_explains_itself(adapter: StrixAdapter) -> None:
    patches = sorted((STRIX / "patches").glob("*.patch"))
    assert [p.name[:4] for p in patches] == [f"{n:04d}" for n in range(1, len(patches) + 1)]
    touched = []
    for patch in patches:
        text = patch.read_text(encoding="utf-8")
        header, _, body = text.partition("diff --git ")
        assert header.startswith("Lab patch for Strix 685bbc8"), patch.name
        assert "Why:" in header, patch.name
        files = re.findall(r"^\+\+\+ b/(\S+)$", body, re.MULTILINE)
        assert len(files) == 1, patch.name  # one upstream file per patch, as the sheet lists
        touched.append(files[0])
    assert sorted(touched) == sorted(p.upstream_file for p in adapter.describe().patches)


@pytest.mark.parametrize(
    ("number", "needle"),
    [
        ("0001", "+        litellm.OllamaChatConfig(num_ctx=int(num_ctx))"),
        ("0001", '+    num_ctx = os.environ.get("LAB_OLLAMA_NUM_CTX", "").strip()'),
        ("0002", "-    web_search,\n-    web_get_contents,"),
        ("0003", '-        for cap in ("NET_ADMIN", "NET_RAW"):'),
        ("0003", '-        extra_hosts["host.docker.internal"] = "host-gateway"'),
        ("0004", '+RUNTIME_STATE_DIR_NAME = "state"'),
        ("0005", "+    if args.non_interactive and args.fail_on is not None:"),
    ],
)
def test_each_patch_makes_its_change(number: str, needle: str) -> None:
    assert needle in _patch_text(number)


def test_the_num_ctx_env_name_is_the_patched_one(adapter: StrixAdapter) -> None:
    assert "LAB_OLLAMA_NUM_CTX" in _patch_text("0001")
    assert "LAB_OLLAMA_NUM_CTX" in launch_of(adapter, make_run()).env


# --------------------------------------------------------------------------- scripts


SCRIPTS = [
    STRIX / "strix-entrypoint.sh",
    STRIX / "ci" / "build.sh",
    STRIX / "ci" / "check.sh",
]


def test_the_scripts_are_shellcheck_and_shfmt_clean() -> None:
    shellcheck = _require_tool("shellcheck", SHELLCHECK_PY)
    shfmt = _require_tool("shfmt", SHFMT_PY)
    paths = [str(p) for p in SCRIPTS]
    result = subprocess.run(  # noqa: S603 - fixed argv
        [*shellcheck, "--severity=style", *paths], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stdout + result.stderr
    result = subprocess.run([*shfmt, "-d", *paths], capture_output=True, text=True)  # noqa: S603
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda p: p.name)
def test_the_scripts_are_executable_in_git(script: Path) -> None:
    mode = subprocess.run(  # noqa: S603 - fixed argv
        ["git", "ls-files", "-s", str(script.relative_to(ROOT))],  # noqa: S607
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split(" ", 1)[0]
    assert mode == "100755", f"{script.name} is not executable in git ({mode or 'untracked'})"


def test_the_smoke_probes_every_sheet_call_path(adapter: StrixAdapter) -> None:
    check = (STRIX / "ci" / "check.sh").read_text(encoding="utf-8")
    probe = (STRIX / "ci" / "probe_call_paths.py").read_text(encoding="utf-8")
    compile(probe, "probe_call_paths.py", "exec")  # never run or imported here
    for path in adapter.describe().model_call_paths:
        assert f'    "{path.split(":", 1)[0]}": ' in check, path
    assert "preflight_model_connection" in probe
    assert "_summarize" in probe
    assert "check_duplicate" in probe
    assert "StrixProvider()" in probe


# --------------------------------------------------------------------------- run fixtures


class HandBuiltStrixRun:
    """A Strix run folder written by hand from the formats of the pinned source.

    HAND-BUILT: see the module docstring for the source lines each file follows.
    """

    def __init__(self, evidence: Path, name: str = "goat-8000_ab12") -> None:
        self.name = name
        self.folder = evidence / "agent" / "strix" / "strix_runs" / name
        self.folder.mkdir(parents=True)
        self.record: dict[str, Any] = {
            "run_id": name,
            "status": "running",
            "end_time": None,
            "llm_requests": [],
            "tool_calls": [],
        }
        self.graph: dict[str, Any] = {
            "statuses": {},
            "parent_of": {},
            "names": {},
            "errors": {},
            "budget_stopped": False,
        }
        self.lines: list[str] = []

    def agent(
        self, agent_id: str, parent: str | None, status: str = "completed", error: str | None = None
    ) -> None:
        self.graph["statuses"][agent_id] = status
        self.graph["parent_of"][agent_id] = parent
        self.graph["names"][agent_id] = f"agent {agent_id}"
        if error is not None:
            self.graph["errors"][agent_id] = error

    def attempt(
        self, at: datetime, agent_id: str | None, tokens_in: int | None, tokens_out: int | None
    ) -> None:
        self.record["llm_requests"].append(
            {
                "started_at": at.isoformat(),
                "agent_id": agent_id,
                "model": "ollama/qwen3:32b",
                "provider": "ollama_chat",
                "outcome": "success",
                "status": None,
                "duration_ms": 900,
                "ttft_ms": 120,
                "input_tokens": tokens_in,
                "cached_tokens": None,
                "output_tokens": tokens_out,
                "retry_attempt": 0,
            }
        )

    def tool(self, at: datetime, agent_id: str, tool: str) -> None:
        self.record["tool_calls"].append(
            {"started_at": at.isoformat(), "agent_id": agent_id, "tool": tool, "duration_ms": 30}
        )

    def log(
        self, logger: str, message: str, *detail: str, level: str = "INFO", agent: str = "-"
    ) -> None:
        stamp = (T0 + timedelta(seconds=len(self.lines))).strftime("%Y-%m-%d %H:%M:%S")
        self.lines.append(f"{stamp}.123 {level:<7} {self.name} {agent} {logger}: {message}")
        self.lines.extend(detail)

    def root_failed(self, error_line: str) -> None:
        self.log(
            "strix.core.runner",
            f"Strix scan {self.name} failed",
            "Traceback (most recent call last):",
            '  File "/opt/strix/strix/core/runner.py", line 650, in run_strix_scan',
            "    result = await run_agent_loop(",
            error_line,
            level="ERROR",
        )

    def write(self) -> None:
        (self.folder / "run.json").write_text(json.dumps(self.record, indent=2), encoding="utf-8")
        (self.folder / "strix.log").write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        state = self.folder / "state"
        state.mkdir(exist_ok=True)
        (state / "agents.json").write_text(json.dumps(self.graph), encoding="utf-8")


def observed(code: int | None = 0, *, timed_out: bool = False, **flags: bool) -> ExitSignals:
    return ExitSignals(exit_code=code, timed_out=timed_out, **flags)


def end_state(adapter: StrixAdapter, evidence: Path, signals: ExitSignals) -> AgentEndState:
    return adapter.wait(make_run(), signals, evidence).end_state


ROOT_ID, CHILD_A, CHILD_B = "a1b2c3d4", "e5f6a7b8", "c9d0e1f2"


@pytest.fixture
def strix_run(tmp_path: Path) -> HandBuiltStrixRun:
    built = HandBuiltStrixRun(tmp_path)
    built.agent(ROOT_ID, None)
    built.agent(CHILD_A, ROOT_ID)
    built.agent(CHILD_B, ROOT_ID)
    return built


# --------------------------------------------------------------------------- end states


def test_a_finished_scan_is_completed(adapter: StrixAdapter, strix_run: HandBuiltStrixRun) -> None:
    strix_run.record["status"] = "completed"
    strix_run.log("strix.core.runner", f"Strix scan {strix_run.name} done")
    strix_run.write()
    assert end_state(adapter, strix_run.folder.parents[3], observed(0)) is AgentEndState.COMPLETED


def test_no_run_folder_keeps_what_the_runner_saw(adapter: StrixAdapter, tmp_path: Path) -> None:
    assert end_state(adapter, tmp_path, observed(1)) is AgentEndState.CRASHED
    assert end_state(adapter, tmp_path, observed(0)) is AgentEndState.COMPLETED
    assert end_state(adapter, tmp_path, observed(None, timed_out=True)) is AgentEndState.TIMEOUT


def test_the_roots_turn_cap_is_budget_exhausted(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(ROOT_ID, None, status="failed", error="Max turns (50) exceeded")
    strix_run.root_failed("agents.exceptions.MaxTurnsExceeded: Max turns (50) exceeded")
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(1)) is AgentEndState.BUDGET_EXHAUSTED


def test_a_childs_turn_cap_does_not_end_the_run(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(CHILD_A, ROOT_ID, status="stopped", error="Max turns (50) exceeded")
    strix_run.log(
        "strix.core.execution", f"agent run failed for {CHILD_A}; marking stopped", level="ERROR"
    )
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(0)) is AgentEndState.COMPLETED


def test_a_root_out_of_tool_call_nudges_is_a_tool_format_failure(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(ROOT_ID, None, status="failed")
    strix_run.root_failed(
        "agents.exceptions.MaxTurnsExceeded: Agent exhausted recovery attempts without "
        "calling finish_scan or agent_finish."
    )
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(1)) is AgentEndState.TOOL_FORMAT_FAILURE


def test_a_text_only_end_is_a_tool_format_failure_even_with_exit_0(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(ROOT_ID, None, status="running")
    strix_run.log(
        "strix.core.runner",
        f"Scan {strix_run.name} ended without calling finish_scan. The agent emitted a "
        "text-only turn instead of a lifecycle tool call, so no executive report was "
        "written. Final output (first 300 chars): 'I am done.'",
        level="ERROR",
    )
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(0)) is AgentEndState.TOOL_FORMAT_FAILURE


def test_a_root_refusal_is_refused(adapter: StrixAdapter, strix_run: HandBuiltStrixRun) -> None:
    strix_run.agent(ROOT_ID, None, status="failed", error="I can't help with that.")
    strix_run.log(
        "strix.core.execution",
        f"agent {ROOT_ID} refused by the model provider: I can't help with that.",
        level="WARNING",
        agent=ROOT_ID,
    )
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(0)) is AgentEndState.REFUSED


def test_a_childs_refusal_does_not_end_the_run(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(CHILD_B, ROOT_ID, status="failed", error="no")
    strix_run.log(
        "strix.core.execution",
        f"agent {CHILD_B} refused by the model provider: no",
        level="WARNING",
    )
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(0)) is AgentEndState.COMPLETED


def test_a_root_id_prefix_is_not_the_root(adapter: StrixAdapter, tmp_path: Path) -> None:
    built = HandBuiltStrixRun(tmp_path)
    built.agent("abc", None, status="failed")
    built.agent("abcd", "abc", status="failed")
    built.log("strix.core.execution", "agent abcd refused by the model provider: no")
    built.write()
    assert end_state(adapter, tmp_path, observed(0)) is AgentEndState.COMPLETED


def test_the_runners_limits_still_come_first(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(ROOT_ID, None, status="failed", error="Max turns (50) exceeded")
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    outcome = adapter.wait(make_run(), observed(None, timed_out=True), evidence)
    assert outcome.end_state is AgentEndState.BUDGET_EXHAUSTED
    assert outcome.signals.timed_out  # kept beside it
    # a refusal the runner already saw is never taken back
    kept = adapter.wait(make_run(), observed(0, refused=True), evidence)
    assert kept.signals.refused


@pytest.mark.parametrize(
    "forged",
    [
        # a record about another run
        "2026-11-26 10:00:00.123 ERROR   other_ff00 - strix.core.runner: "
        "Strix scan other_ff00 failed",
        # the right words from another logger
        "2026-11-26 10:00:00.123 ERROR   {name} - strix.tools.notes: Strix scan {name} failed",
        # not at the start of a line
        "tool said: 2026-11-26 10:00:00.123 ERROR   {name} - strix.core.runner: Strix scan {name} "
        "failed",
    ],
)
def test_forged_failure_records_are_ignored(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun, forged: str
) -> None:
    strix_run.agent(ROOT_ID, None, status="failed")
    strix_run.lines += [
        forged.format(name=strix_run.name),
        "agents.exceptions.MaxTurnsExceeded: Agent exhausted recovery attempts without "
        "calling finish_scan or agent_finish.",
    ]
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(1)) is AgentEndState.CRASHED


def test_log_text_does_not_outvote_agents_json(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    # model text with line breaks can forge a whole record; the root's recorded status
    # (completed) says it did not fail, so nothing is added
    strix_run.root_failed(
        "agents.exceptions.MaxTurnsExceeded: Agent exhausted recovery attempts without "
        "calling finish_scan or agent_finish."
    )
    strix_run.log("strix.core.execution", f"agent {ROOT_ID} refused by the model provider: x")
    strix_run.write()
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(0)) is AgentEndState.COMPLETED


def test_non_utf8_log_bytes_are_survived(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.agent(ROOT_ID, None, status="failed", error="Max turns (9) exceeded")
    strix_run.write()
    log = strix_run.folder / "strix.log"
    log.write_bytes(b"\xff\xfe\x00garbage\n" + log.read_bytes())
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(1)) is AgentEndState.BUDGET_EXHAUSTED


@pytest.mark.parametrize(
    "graph",
    [
        "not json",
        "[]",
        '{"parent_of": []}',
        '{"parent_of": {}}',
        '{"parent_of": {"a": null, "b": null}, "errors": {"a": "Max turns (1) exceeded"}}',
        '{"parent_of": {"a": "b", "b": "a"}}',
    ],
)
def test_an_unreadable_agent_graph_adds_nothing(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun, graph: str
) -> None:
    strix_run.write()
    (strix_run.folder / "state" / "agents.json").write_text(graph, encoding="utf-8")
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(1)) is AgentEndState.CRASHED


def test_two_run_folders_are_ambiguous(adapter: StrixAdapter, tmp_path: Path) -> None:
    for name in ("one_aaaa", "two_bbbb"):
        built = HandBuiltStrixRun(tmp_path, name)
        built.agent("r", None, status="failed", error="Max turns (5) exceeded")
        built.write()
    assert StrixRun.find(tmp_path) is None
    assert end_state(adapter, tmp_path, observed(1)) is AgentEndState.CRASHED


def test_symlinked_run_files_are_not_followed(adapter: StrixAdapter, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    built = HandBuiltStrixRun(elsewhere)
    built.agent("r", None, status="failed", error="Max turns (5) exceeded")
    built.write()
    evidence = tmp_path / "evidence"
    (evidence / "agent" / "strix").mkdir(parents=True)
    os.symlink(built.folder.parent, evidence / "agent" / "strix" / "strix_runs")
    assert StrixRun.find(evidence) is None
    # a real folder whose files are links
    real = HandBuiltStrixRun(tmp_path / "evidence2")
    real.write()
    agents_json = real.folder / "state" / "agents.json"
    agents_json.unlink()
    os.symlink(built.folder / "state" / "agents.json", agents_json)
    assert end_state(adapter, tmp_path / "evidence2", observed(1)) is AgentEndState.CRASHED


def test_oversized_files_read_as_absent(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun, monkeypatch: pytest.MonkeyPatch
) -> None:
    strix_run.agent(ROOT_ID, None, status="failed", error="Max turns (5) exceeded")
    strix_run.write()
    monkeypatch.setattr(StrixRun, "MAX_FILE_BYTES", 64)
    evidence = strix_run.folder.parents[3]
    assert end_state(adapter, evidence, observed(1)) is AgentEndState.CRASHED


# --------------------------------------------------------------------------- agent ids


def _ollama_request(system: str, *turns: str, num_ctx: int = 32768) -> bytes:
    messages = [{"role": "system", "content": system}]
    messages += [
        {"role": "user" if i % 2 == 0 else "assistant", "content": text}
        for i, text in enumerate(turns)
    ]
    body = {"model": "qwen3:32b", "messages": messages, "options": {"num_ctx": num_ctx}}
    return json.dumps({**body, "stream": False}).encode()


def _ollama_response(text: str, tokens_in: int, tokens_out: int) -> bytes:
    return json.dumps(
        {
            "model": "qwen3:32b",
            "created_at": "2026-11-26T10:00:00Z",
            "message": {"role": "assistant", "content": text},
            "done": True,
            "done_reason": "stop",
            "prompt_eval_count": tokens_in,
            "eval_count": tokens_out,
        }
    ).encode()


class TapCalls:
    """Tap evidence written by the real recorder, one Ollama /api/chat call at a time."""

    def __init__(self, evidence: Path) -> None:
        self.recorder = Recorder(TapConfig(run_id=new_id("run"), tags=(), evidence_dir=evidence))

    def call(self, request: bytes, response: bytes | None) -> None:
        self.recorder.record(
            request,
            response,
            T0,
            RequestMeta("POST", "/api/chat", "application/json", None, True),
            None if response is None else ResponseMeta(200, "application/json", None, True),
        )


PREFLIGHT = _ollama_request(
    StrixAdapter.PREFLIGHT_SYSTEM, StrixAdapter.PREFLIGHT_INPUT, num_ctx=32768
)


@pytest.fixture
def scan(strix_run: HandBuiltStrixRun) -> tuple[HandBuiltStrixRun, TapCalls]:
    """A root with two children: the warm-up, then six calls in this tap order."""
    evidence = strix_run.folder.parents[3]
    tap = TapCalls(evidence)
    tap.call(PREFLIGHT, _ollama_response("OK", 20, 2))  # seq 0, before the run record
    plan = [  # (start, agent, conversation, tokens in, tokens out), in tap (seq) order
        (1.000, ROOT_ID, ("root task",), 1000, 50),
        (2.000, CHILD_A, ("check the login form",), 800, 40),
        (2.050, CHILD_B, ("check the search page",), 810, 41),
        (3.000, ROOT_ID, ("root task", "spawned two", "wait"), 1100, 60),
        (4.000, CHILD_A, ("compare reports",), 300, 20),  # the dedupe judge, in A's task
        (5.000, CHILD_A, ("check the login form", "found XSS", "report"), 900, 45),
    ]
    for _, agent, conversation, tokens_in, tokens_out in plan:
        tap.call(
            _ollama_request(f"You are Strix agent {agent}.", *conversation),
            _ollama_response("ok", tokens_in, tokens_out),
        )
    # run.json lists attempts as they settle, not as they start
    for start, agent, _, tokens_in, tokens_out in sorted(plan, key=lambda p: -p[0]):
        strix_run.attempt(T0 + timedelta(seconds=start), agent, tokens_in, tokens_out)
    strix_run.tool(T0 + timedelta(seconds=1.5), ROOT_ID, "create_agent")
    strix_run.tool(T0 + timedelta(seconds=2.5), CHILD_A, "create_vulnerability_report")
    strix_run.write()
    return strix_run, tap


EXPECTED_IDS = {0: ROOT_ID, 1: ROOT_ID, 2: CHILD_A, 3: CHILD_B, 4: ROOT_ID, 5: CHILD_A, 6: CHILD_A}


def test_agent_ids_name_every_tap_call(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    evidence = scan[0].folder.parents[3]
    ids = adapter.agent_ids(make_run(), evidence)
    assert ids == EXPECTED_IDS
    # the telemetry contract accepts them: every seq named, nothing else
    summary = summarise(new_id("run"), load_calls(evidence), ids)
    assert summary.agents_source == "adapter"
    assert summary.agents == 3


def test_agent_ids_survive_a_restart(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    stored = make_run().model_dump_json()
    fresh = StrixAdapter()
    ids = fresh.agent_ids(AdapterRun.model_validate_json(stored), scan[0].folder.parents[3])
    assert ids == EXPECTED_IDS


def test_a_retried_preflight_is_counted_for_the_root(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, tap = scan
    tap.call(PREFLIGHT, None)  # a warm-up retry whose reply never came
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) == {**EXPECTED_IDS, 7: ROOT_ID}


def test_the_preflight_key_matches_litellms_request_shape(adapter: StrixAdapter) -> None:
    # what LiteLLM's ollama_chat transform sends: options, stream and no tools
    body = json.dumps(
        {
            "model": "llama3.1:8b",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Reply with just 'OK'."},
            ],
            "options": {"num_ctx": 16384, "num_predict": 16},
            "stream": True,
        }
    ).encode()
    from control.telemetry.wire import parse_call

    call = parse_call("/api/chat", body, None, None)
    assert adapter._is_preflight(call, adapter._preflight_thread_key())
    # a later turn of the same conversation is not the warm-up
    longer = parse_call(
        "/api/chat",
        _ollama_request(adapter.PREFLIGHT_SYSTEM, "Reply with just 'OK'.", "OK", "more"),
        None,
        None,
    )
    assert not adapter._is_preflight(longer, adapter._preflight_thread_key())


def test_a_token_mismatch_gives_no_ids(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, _ = scan
    built.record["llm_requests"][0]["output_tokens"] = 999
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) is None


def test_unknown_token_counts_do_not_block_the_pairing(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, _ = scan
    for attempt in built.record["llm_requests"]:
        attempt["input_tokens"] = attempt["output_tokens"] = None
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) == EXPECTED_IDS


def test_a_call_strix_never_recorded_gives_no_ids(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, tap = scan
    tap.call(_ollama_request("You are Strix agent x.", "late"), None)  # killed mid-call
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) is None


def test_an_attempt_the_tap_never_saw_gives_no_ids(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, _ = scan
    built.attempt(T0 + timedelta(seconds=9), ROOT_ID, 1, 1)
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) is None


@pytest.mark.parametrize("agent_id", [None, ""])
def test_an_attempt_without_an_agent_gives_no_ids(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls], agent_id: str | None
) -> None:
    built, _ = scan
    built.record["llm_requests"][2]["agent_id"] = agent_id
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) is None


@pytest.mark.parametrize(
    "requests",
    [
        "not a list",
        [{"agent_id": "a"}],  # no start time
        [{"started_at": "yesterday", "agent_id": "a"}],
        [{"started_at": "2026-11-26T10:00:00+00:00", "agent_id": "a", "input_tokens": "12"}],
        [{"started_at": "2026-11-26T10:00:00+00:00", "agent_id": 7}],
    ],
)
def test_a_malformed_run_record_gives_no_ids(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls], requests: object
) -> None:
    built, _ = scan
    built.record["llm_requests"] = requests
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) is None


def test_no_root_gives_no_ids(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, _ = scan
    built.graph["parent_of"][CHILD_A] = None  # two roots
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) is None


def test_no_calls_or_no_run_give_no_ids(adapter: StrixAdapter, tmp_path: Path) -> None:
    assert adapter.agent_ids(make_run(), tmp_path) is None
    built = HandBuiltStrixRun(tmp_path)
    built.agent("r", None)
    built.write()
    assert adapter.agent_ids(make_run(), tmp_path) is None  # Strix ran, the tap saw nothing


def test_naive_start_times_are_read_as_utc(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, _ = scan
    for attempt in built.record["llm_requests"]:
        attempt["started_at"] = attempt["started_at"].removesuffix("+00:00")
    built.write()
    assert adapter.agent_ids(make_run(), built.folder.parents[3]) == EXPECTED_IDS


# --------------------------------------------------------------------------- collect


def test_collect_gives_the_trajectory_in_time_order(
    adapter: StrixAdapter, scan: tuple[HandBuiltStrixRun, TapCalls]
) -> None:
    built, _ = scan
    built.record["status"] = "completed"
    built.record["end_time"] = (T0 + timedelta(seconds=30)).isoformat()
    built.write()
    (built.folder / "penetration_test_report.md").write_text("# Report\n", encoding="utf-8")
    run = make_run()
    events = adapter.collect(run, built.folder.parents[3])
    assert [e.seq for e in events] == list(range(9))
    assert [e.ts for e in events] == sorted(e.ts for e in events)
    kinds = [e.event_type for e in events]
    assert kinds.count(AgentEventType.LLM_CALL) == 6
    assert kinds.count(AgentEventType.TOOL_CALL) == 2
    assert kinds[-1] is AgentEventType.FINAL_REPORT
    assert events[-1].native_ref == "penetration_test_report.md"
    assert all(e.run_id == run.run_id and e.stream == "agent" for e in events)
    tools = [e for e in events if e.event_type is AgentEventType.TOOL_CALL]
    assert [t.tool_name for t in tools] == ["create_agent", "create_vulnerability_report"]
    assert all(e.native_ref and e.native_ref.startswith("run.json#") for e in events[:-1])


def test_collect_without_a_run_is_empty(adapter: StrixAdapter, tmp_path: Path) -> None:
    assert adapter.collect(make_run(), tmp_path) == []


def test_collect_skips_a_report_without_an_end_time(
    adapter: StrixAdapter, strix_run: HandBuiltStrixRun
) -> None:
    strix_run.record["end_time"] = "not a time"
    strix_run.write()
    (strix_run.folder / "penetration_test_report.md").write_text("x", encoding="utf-8")
    assert adapter.collect(make_run(), strix_run.folder.parents[3]) == []


def test_an_attempt_record_rejects_a_bad_entry() -> None:
    from agents.strix.adapter import StrixLlmAttempt

    with pytest.raises(ValidationError):
        StrixLlmAttempt.model_validate({"started_at": "2026-11-26T10:00:00Z", "agent_id": 1})
