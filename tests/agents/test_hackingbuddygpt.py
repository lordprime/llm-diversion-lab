"""The hackingBuddyGPT adapter, its plugin contract and its image recipe.

hackingBuddyGPT is never installed or run on the development machine, so nothing here
imports it. The run logs are hand-built (:class:`HandBuiltLog`) from the log format in
upstream's ``utils/logging.py`` and ``utils/log_storage.py`` at the pinned commit; the
image's own behaviour is checked by ``agents/hackingbuddygpt/ci/check.sh`` in CI.
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

from agents.base import (
    AdapterLimits,
    AdapterRun,
    AgentEndState,
    AgentLaunch,
    CapabilitySheet,
    ChannelStatus,
    ExitSignals,
    ModelConfig,
    UnsupportedRun,
)
from agents.hackingbuddygpt import HackingBuddyGPTAdapter
from agents.hackingbuddygpt.adapter import LogSpan, RunLog
from agents.hackingbuddygpt.lab_hbg.contract import (
    OFFERED_TOOLS,
    USE_CASE_NAME,
    ConfigRefused,
    ObjectiveFile,
    RunExit,
    ToolOutputCap,
)
from control.core.ids import new_id
from control.core.models import AgentEvent, AgentEventType

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "agents" / "hackingbuddygpt"
PLUGIN = HERE / "lab_hbg"
TAP = "http://tap:8080"
TARGET = "http://dvga:5013"
OBJECTIVE = "Make the server fetch a URL of your choice.\nReport what you tried. ünïcödé ✓"


def run_for(
    *,
    name: str = "qwen3:32b",
    num_ctx: int | None = 32768,
    objective: str = OBJECTIVE,
    max_turns: int = 30,
    target: str = TARGET,
    tap: str = TAP,
) -> AdapterRun:
    return AdapterRun(
        run_id=new_id("run"),
        model=ModelConfig(name=name, num_ctx=num_ctx),
        target_url=target,
        objective=objective,
        llm_base_url=tap,
        limits=AdapterLimits(max_turns=max_turns, timeout_s=3600),
    )


@pytest.fixture
def adapter() -> HackingBuddyGPTAdapter:
    return HackingBuddyGPTAdapter()


def launch_of(adapter: HackingBuddyGPTAdapter, run: AdapterRun) -> AgentLaunch:
    launch = adapter.prepare(run)
    assert isinstance(launch, AgentLaunch)
    return launch


def options(launch: AgentLaunch) -> dict[str, str]:
    """The ``--name=value`` options of a rendered command, refusing duplicates."""
    assert launch.command[:4] == ("python", "-m", "lab_hbg", USE_CASE_NAME)
    found: dict[str, str] = {}
    for arg in launch.command[4:]:
        match = re.fullmatch(r"--([a-z_.]+)=(.*)", arg)
        assert match, f"not a --name=value option: {arg!r}"
        assert match[1] not in found, f"option given twice: {match[1]}"
        found[match[1]] = match[2]
    return found


# --------------------------------------------------------------------------- a hand-built log


@dataclass
class HandBuiltLog:
    """A hackingBuddyGPT run log, built by hand.

    No real log was recorded: the framework never runs on this machine. Each method
    writes the span the upstream logger writes at the pinned commit (``JsonlLogger`` in
    ``utils/logging.py``, ``Span`` in ``utils/log_storage.py``): the run span first with
    no end time, sections closed after their children, a ``chat <model>`` CLIENT span per
    model call, an ``execute_tool <name>`` span per tool call parented to its chat span,
    ``message`` spans for system, limit and status text, and the run span again at the end.
    Timestamps are naive local time, as upstream writes them.
    """

    model: str = "ollama_chat/qwen3:32b"
    lines: list[dict[str, Any]] = field(default_factory=list)
    _count: int = 0
    _clock: int = 0

    def __post_init__(self) -> None:
        self.trace = "ab" * 16
        self.run_span = self._id()
        self.lines.append(
            self._span(
                self.run_span,
                None,
                "LabWebTestingUseCase",
                "INTERNAL",
                {
                    "hackingbuddygpt.run.name": "LabWebTestingUseCase",
                    "hackingbuddygpt.run.tag": "run_x",
                    "hackingbuddygpt.run.configuration": "{}",
                    "gen_ai.conversation.id": self.trace,
                },
                end=False,
                status="UNSET",
            )
        )

    def _id(self) -> str:
        self._count += 1
        return f"{self._count:016x}"

    def _time(self) -> str:
        self._clock += 1
        return f"2026-11-26T10:00:{self._clock:02d}.000000"

    def _span(
        self,
        span_id: str,
        parent: str | None,
        name: str,
        kind: str,
        attributes: dict[str, Any],
        *,
        end: bool = True,
        status: str = "OK",
        message: str = "",
    ) -> dict[str, Any]:
        start = self._time()
        return {
            "trace_id": self.trace,
            "span_id": span_id,
            "parent_span_id": parent,
            "name": name,
            "kind": kind,
            "start_time": start,
            "end_time": self._time() if end else None,
            "attributes": attributes,
            "status": {"code": status, "message": message},
        }

    def message(self, role: str, text: str) -> None:
        attributes = {
            "hackingbuddygpt.message.role": role,
            "gen_ai.output.messages": [
                {"role": role, "parts": [{"type": "text", "content": text}]}
            ],
        }
        self.lines.append(self._span(self._id(), self.run_span, "message", "INTERNAL", attributes))

    def chat(self, text: str = "", finish: str = "stop") -> str:
        span_id = self._id()
        attributes: dict[str, Any] = {
            "gen_ai.operation.name": "chat",
            "gen_ai.input.messages": [
                {"role": "user", "parts": [{"type": "text", "content": "[...]"}]}
            ],
            "gen_ai.output.messages": [
                {
                    "role": "assistant",
                    "parts": [{"type": "text", "content": text}],
                    "finish_reason": finish,
                }
            ],
            "gen_ai.usage.input_tokens": 120,
            "gen_ai.usage.output_tokens": 30,
            "gen_ai.request.model": self.model,
            "gen_ai.response.model": self.model,
            "gen_ai.provider.name": "ollama_chat",
            "gen_ai.response.finish_reasons": [finish],
        }
        self.lines.append(
            self._span(span_id, self.run_span, f"chat {self.model}", "CLIENT", attributes)
        )
        return span_id

    def tool(self, chat_id: str, name: str, arguments: Any, result: str) -> None:
        raw = arguments if isinstance(arguments, str) else json.dumps(arguments)
        attributes = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": name,
            "gen_ai.tool.call.id": f"call_{self._count}",
            "gen_ai.tool.call.arguments": raw,
            "hackingbuddygpt.tool.result": result,
        }
        self.lines.append(
            self._span(self._id(), chat_id, f"execute_tool {name}", "INTERNAL", attributes)
        )

    def section(self, name: str) -> None:
        attributes = {"hackingbuddygpt.section.name": name}
        self.lines.append(self._span(self._id(), self.run_span, name, "INTERNAL", attributes))

    def finish(self, state: str) -> None:
        ok = state == "got root"
        self.message("status", "Run finished successfully" if ok else f"Run failed: {state}")
        first = self.lines[0]
        self.lines.append(
            {
                **first,
                "end_time": self._time(),
                "attributes": {**first["attributes"], "hackingbuddygpt.run.state": state},
                "status": {"code": "OK" if ok else "ERROR", "message": state},
            }
        )

    def text(self) -> str:
        return "".join(json.dumps(line, ensure_ascii=False) + "\n" for line in self.lines)

    def write(
        self, evidence: Path, *, name: str = "log-20261126-100000.jsonl", cut_last: bool = False
    ) -> Path:
        directory = evidence / "agent" / "hbg"
        directory.mkdir(parents=True, exist_ok=True)
        text = self.text()
        if cut_last:  # the runner killed the agent mid-write
            text = text[: len(text) - len(json.dumps(self.lines[-1])) // 2 - 1]
        path = directory / name
        path.write_text(text, encoding="utf-8")
        return path


def a_completed_run() -> HandBuiltLog:
    log = HandBuiltLog()
    log.message("system", "You are a senior penetration tester ...")
    log.message("limit", "Your limits are: remaining_rounds=30")
    first = log.chat("Let me look at the start page and the playbook.", finish="tool_calls")
    log.tool(first, "HTTPRequest", {"method": "GET", "path": "/"}, "HTTP/1.1 200 OK\r\n\r\nhi")
    log.tool(first, "PentestPlaybook", {"topic": "ssrf"}, "Checklist for ssrf:\n- ...")
    log.section("round 1")
    second = log.chat("Done.", finish="tool_calls")
    log.tool(second, "complete", {"summary": "Found the import endpoint."}, "The run is complete.")
    log.section("round 2")
    log.finish("got root")
    return log


# --------------------------------------------------------------------------- the sheet


def test_the_sheet_is_resolved_and_names_the_turn_cap(adapter: HackingBuddyGPTAdapter) -> None:
    sheet = adapter.describe()
    assert sheet.max_turns_knob == "limits.max_rounds"
    assert sheet.unresolved_side_channels == ()
    assert sheet.sub_agents == "none"
    assert sheet.check_runnable(ModelConfig(name="qwen3:32b", num_ctx=8192)) is None
    assert sheet.commit == yaml.safe_load((HERE / "source.yaml").read_text())["commit"]


def test_every_disabled_channel_cites_the_source_it_was_verified_in(
    adapter: HackingBuddyGPTAdapter,
) -> None:
    for name, channel in adapter.describe().side_channels.items():
        assert channel.status is ChannelStatus.DISABLED, name
        assert channel.note is not None and "verified at" in channel.note, name
        assert re.search(r"\.py:\d+", channel.note), f"{name}: no file:line citation"


def test_agent_ids_are_none_for_a_single_agent_run(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    a_completed_run().write(tmp_path)
    assert adapter.agent_ids(run_for(), tmp_path) is None
    assert adapter.describe().agent_id_source is None


# --------------------------------------------------------------------------- rendering


def test_the_rendered_command_sets_every_option_explicitly(
    adapter: HackingBuddyGPTAdapter,
) -> None:
    run = run_for(max_turns=17, num_ctx=40960)
    launch = launch_of(adapter, run)
    assert launch.image == "agent-hackingbuddygpt"
    assert options(launch) == {
        "llm.model": "ollama_chat/qwen3:32b",
        "llm.api_base": TAP,
        "llm.api_key": "ollama",
        "llm.context_size": "40960",
        "llm.api_timeout": "300",
        "llm.api_retries": "3",
        "llm.provider": "",
        "llm.proxy": "",
        "host": TARGET,
        "hints": "",
        "objective_file": "/etc/lab/agent/objective.txt",
        "max_tool_output_chars": "32000",
        "limits.max_rounds": "17",
        "limits.max_tokens": "0",
        "limits.max_cost": "0",
        "limits.max_duration": "0",
        "log.log_dir": "/evidence/agent/hbg",
        "log.tag": run.run_id,
    }
    assert not launch.needs_docker
    assert launch.cap_add == ()


def test_the_objective_goes_in_a_file_never_on_the_command_line(
    adapter: HackingBuddyGPTAdapter,
) -> None:
    objective = "Line one --limits.max_rounds=999\n--llm.api_base=http://evil.example/\n✓"
    launch = launch_of(adapter, run_for(objective=objective))
    assert launch.files == {"objective.txt": objective.encode("utf-8")}
    assert options(launch)["limits.max_rounds"] == "30"
    assert options(launch)["llm.api_base"] == TAP
    assert not any("evil" in arg for arg in launch.command)


def test_the_launch_records_the_turn_cap_and_never_the_key(
    adapter: HackingBuddyGPTAdapter,
) -> None:
    launch = launch_of(adapter, run_for(max_turns=9))
    assert launch.recorded_settings["limits.max_rounds"] == "9"
    assert launch.recorded_settings["max_tool_output_chars"] == "32000"
    assert launch.recorded_settings["llm.context_size"] == "32768"
    assert "llm.api_key" not in launch.recorded_settings
    empty = {name for name, value in options(launch).items() if not value}
    assert empty == {"llm.provider", "llm.proxy", "hints"}
    assert set(launch.recorded_settings) == set(options(launch)) - {"llm.api_key"} - empty


def test_every_model_call_goes_to_the_tap(adapter: HackingBuddyGPTAdapter) -> None:
    tap = "http://tap:8080/some/prefix"
    launch = launch_of(adapter, run_for(tap=tap))
    assert options(launch)["llm.api_base"] == tap
    assert launch.env["OLLAMA_API_BASE"] == tap
    assert options(launch)["llm.model"].startswith("ollama_chat/")


def test_the_side_channel_switches_are_in_every_launch(adapter: HackingBuddyGPTAdapter) -> None:
    # Each assertion fails if the rendered config left the channel on.
    launch = launch_of(adapter, run_for())
    rendered = " ".join([*launch.command, *launch.env, *launch.env.values()]).lower()
    # litellm_cost_map: LiteLLM compares the value case-insensitively with "true"
    assert launch.env["LITELLM_LOCAL_MODEL_COST_MAP"].lower() == "true"
    # the remote Anthropic beta-header list, and LiteLLM's .env loading
    assert launch.env["LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS"].lower() == "true"
    assert launch.env["LITELLM_MODE"] == "PRODUCTION"
    # openrouter_default_api_base: the tap, in both places LiteLLM may read it
    assert "openrouter" not in rendered
    assert options(launch)["llm.api_base"] == launch.env["OLLAMA_API_BASE"] == TAP
    # rag_openai_embeddings: no RAG option at all, no OpenAI key anywhere
    assert "rag" not in " ".join(options(launch))
    assert "openai_api_key" not in rendered
    # no proxy that LiteLLM would install as its client session
    assert options(launch)["llm.proxy"] == ""
    assert not {k for k in launch.env if "proxy" in k.lower()}


def test_the_environment_cannot_set_a_hackingbuddygpt_option(
    adapter: HackingBuddyGPTAdapter,
) -> None:
    # Upstream maps an env var to an option by its name, lower-cased or with "_" read as
    # "." (configurable.py get_environment_variables); none of ours may match one.
    launch = launch_of(adapter, run_for())
    names = set(options(launch)) | {"llm", "limits", "log"}
    for key in launch.env:
        forms = {key, key.lower(), key.replace("_", "."), key.lower().replace("-", ".")}
        assert not forms & names, key


@pytest.mark.parametrize(
    "name",
    ["qwen3 32b", "-x", "--llm.api_base=x", "a" * 201, "q;rm", "ü", "$(id)", "a=b", "x\u200b"],
)
def test_a_hostile_model_name_is_refused(adapter: HackingBuddyGPTAdapter, name: str) -> None:
    with pytest.raises(ValueError, match="model name"):
        adapter.prepare(run_for(name=name))


@pytest.mark.parametrize("name", ["", "qwen3\n", "\x00"])
def test_a_model_name_that_is_no_text_never_reaches_the_adapter(name: str) -> None:
    with pytest.raises(ValueError):
        run_for(name=name)


@pytest.mark.parametrize("name", ["qwen3:32b", "gpt-oss:20b", "hf.co/org/m-GGUF:Q4_K_M", "l3.3"])
def test_real_ollama_model_names_render(adapter: HackingBuddyGPTAdapter, name: str) -> None:
    assert options(launch_of(adapter, run_for(name=name)))["llm.model"] == f"ollama_chat/{name}"


@pytest.mark.parametrize("objective", [" ", "\n\t ", "\u2003"])
def test_a_blank_objective_is_refused(adapter: HackingBuddyGPTAdapter, objective: str) -> None:
    with pytest.raises(ConfigRefused, match="empty"):
        adapter.prepare(run_for(objective=objective))


def test_an_unpinned_context_is_unsupported_and_nothing_is_rendered(
    adapter: HackingBuddyGPTAdapter,
) -> None:
    verdict = adapter.prepare(run_for(num_ctx=None))
    assert isinstance(verdict, UnsupportedRun)
    assert verdict.end_state is AgentEndState.UNSUPPORTED
    with pytest.raises(ValueError, match="not pinned"):
        adapter.render(run_for(num_ctx=None))


def test_the_largest_objective_fits_its_file(adapter: HackingBuddyGPTAdapter) -> None:
    objective = "€" * 8192  # 3 bytes each
    launch = launch_of(adapter, run_for(objective=objective))
    assert len(launch.files["objective.txt"]) <= ObjectiveFile.MAX_BYTES


def test_start_and_teardown_touch_nothing(adapter: HackingBuddyGPTAdapter) -> None:
    class NoHost:
        def exec(self, service: str, argv: Any, *, timeout_s: float) -> Any:
            raise AssertionError("the adapter ran a command")

    adapter.start(run_for(), NoHost())
    adapter.teardown(run_for(), NoHost())


# --------------------------------------------------------------------------- the plugin contract


@pytest.mark.parametrize(
    ("reason", "code"),
    [
        (None, RunExit.FINISHED),
        ("Cancelled", RunExit.FINISHED),
        ("Reached maximum rounds (30)", RunExit.TURN_CAP),
        ("Reached maximum tokens (100)", RunExit.OTHER_LIMIT),
        ("Reached maximum cost (10.0)", RunExit.OTHER_LIMIT),
        ("Reached maximum duration (0:05:00)", RunExit.OTHER_LIMIT),
        ("Parent limit reached: Reached maximum rounds (3)", RunExit.CRASHED),
        ("exception occurred", RunExit.CRASHED),
        ("", RunExit.CRASHED),
        ("cancelled", RunExit.CRASHED),
        ("Reached maximum rounds", RunExit.OTHER_LIMIT),
    ],
)
def test_the_exit_code_for_each_upstream_reason(reason: str | None, code: RunExit) -> None:
    assert RunExit.for_reason(reason) is code


def test_the_exit_codes_are_distinct_and_finished_is_zero() -> None:
    assert len({c.value for c in RunExit}) == len(RunExit)
    assert RunExit.FINISHED == 0
    assert RunExit.CRASHED == 1  # upstream's own code for an exception


@pytest.mark.parametrize(
    ("limit", "text", "expected"),
    [
        (0, "x" * 100_000, "x" * 100_000),
        (10, "short", "short"),
        (10, "0123456789", "0123456789"),
        (10, "0123456789ab", "01234\n[... 2 characters left out ...]\n789ab"),
        (5, "0123456789", "012\n[... 5 characters left out ...]\n89"),
        (1, "abc", "a\n[... 2 characters left out ...]\n"),
        (4, "äöüß✓✓", "äö\n[... 2 characters left out ...]\n✓✓"),
    ],
)
def test_the_tool_output_cap(limit: int, text: str, expected: str) -> None:
    assert ToolOutputCap(limit).apply(text) == expected


@pytest.mark.parametrize("limit", [-1, True, 1.5, "10", None])
def test_a_bad_cap_is_refused(limit: Any) -> None:
    with pytest.raises(ConfigRefused):
        ToolOutputCap(limit)


def test_the_objective_file_round_trips(tmp_path: Path) -> None:
    path = tmp_path / ObjectiveFile.NAME
    path.write_bytes(ObjectiveFile.encode(OBJECTIVE))
    assert ObjectiveFile.read(path) == OBJECTIVE


@pytest.mark.parametrize(
    ("content", "error"),
    [
        (b"", "empty"),
        (b"  \n\t", "empty"),
        (b"a\x00b", "NUL"),
        (b"\xff\xfe", "not UTF-8"),
        (b"x" * (ObjectiveFile.MAX_BYTES + 1), "over"),
    ],
)
def test_a_bad_objective_file_is_refused(tmp_path: Path, content: bytes, error: str) -> None:
    path = tmp_path / "objective.txt"
    path.write_bytes(content)
    with pytest.raises(ConfigRefused, match=error):
        ObjectiveFile.read(path)


def test_a_missing_objective_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ConfigRefused, match="cannot read"):
        ObjectiveFile.read(tmp_path / "nope.txt")
    with pytest.raises(ConfigRefused, match="cannot read"):
        ObjectiveFile.read(tmp_path)  # a directory


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {alias.name for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def test_only_the_in_image_modules_import_hackingbuddygpt() -> None:
    # The adapter imports contract.py outside the image, so it (and the package) must
    # stay plain Python; usecase.py and __main__.py are the plugin proper.
    for name in ("__init__.py", "contract.py"):
        assert not {
            m for m in _imports(PLUGIN / name) if m.startswith(("hackingBuddyGPT", "litellm"))
        }
    assert any(m.startswith("hackingBuddyGPT") for m in _imports(PLUGIN / "usecase.py"))
    assert any(m.startswith("hackingBuddyGPT") for m in _imports(PLUGIN / "__main__.py"))


def test_the_use_case_reads_real_annotations() -> None:
    # hackingBuddyGPT's configuration needs the fields' annotation objects, which a
    # postponed-annotations import would turn into strings.
    tree = ast.parse((PLUGIN / "usecase.py").read_text(encoding="utf-8"))
    futures = [
        n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "__future__"
    ]
    assert futures == []


def test_the_use_case_offers_exactly_the_contract_tools() -> None:
    source = (PLUGIN / "usecase.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    added = {
        node.args[0].func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "add_capability"
        and node.args
        and isinstance(node.args[0], ast.Call)
        and isinstance(node.args[0].func, ast.Name)
    }
    functions = {
        node.args[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "function_call_capability"
        and isinstance(node.args[0], ast.Name)
    }
    assert functions == {"complete"}
    assert (added - {"function_call_capability"}) | functions == OFFERED_TOOLS
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    imported = {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    for unwanted in ("SubmitFlag", "SubAgentCapability"):
        assert unwanted not in names | imported, unwanted
    assert f'"{USE_CASE_NAME}"' not in source  # the name comes from the contract only


# --------------------------------------------------------------------------- end states


def outcome_of(
    adapter: HackingBuddyGPTAdapter,
    evidence: Path,
    exit_code: int | None,
    *,
    timed_out: bool = False,
    **observed: bool,
) -> tuple[AgentEndState, tuple[AgentEndState, ...]]:
    signals = ExitSignals(exit_code=exit_code, timed_out=timed_out, **observed)
    outcome = adapter.wait(run_for(), signals, evidence)
    return outcome.end_state, outcome.signalled


def test_a_completed_run(adapter: HackingBuddyGPTAdapter, tmp_path: Path) -> None:
    a_completed_run().write(tmp_path)
    assert outcome_of(adapter, tmp_path, RunExit.FINISHED) == (
        AgentEndState.COMPLETED,
        (AgentEndState.COMPLETED,),
    )


def test_the_model_giving_up_is_a_completed_run(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    chat = log.chat("Nothing to find here.", finish="tool_calls")
    log.tool(chat, "EndRun", {}, "Run has been aborted")
    log.finish("Cancelled")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, 0)[0] is AgentEndState.COMPLETED


def test_the_turn_cap_is_budget_exhausted(adapter: HackingBuddyGPTAdapter, tmp_path: Path) -> None:
    log = HandBuiltLog()
    for _ in range(3):
        chat = log.chat("Looking around.", finish="tool_calls")
        log.tool(chat, "HTTPRequest", {"method": "GET", "path": "/x"}, "HTTP/1.1 404 NOT FOUND")
    log.finish("Reached maximum rounds (3)")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, RunExit.TURN_CAP) == (
        AgentEndState.BUDGET_EXHAUSTED,
        (AgentEndState.BUDGET_EXHAUSTED, AgentEndState.CRASHED),
    )


@pytest.mark.parametrize("code", [RunExit.TURN_CAP, RunExit.OTHER_LIMIT])
def test_a_limit_exit_code_alone_is_budget_exhausted(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path, code: RunExit
) -> None:
    assert outcome_of(adapter, tmp_path, code)[0] is AgentEndState.BUDGET_EXHAUSTED


def test_a_limit_in_the_log_wins_over_a_zero_exit(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.chat("hm")
    log.finish("Reached maximum tokens (10)")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, 0)[0] is AgentEndState.BUDGET_EXHAUSTED


def test_an_exception_is_a_crash(adapter: HackingBuddyGPTAdapter, tmp_path: Path) -> None:
    log = HandBuiltLog()
    log.chat("x")
    log.finish("exception occurred")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, RunExit.CRASHED)[0] is AgentEndState.CRASHED


def test_a_refused_configuration_is_a_crash_with_no_log(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    assert outcome_of(adapter, tmp_path, RunExit.BAD_CONFIG)[0] is AgentEndState.CRASHED
    assert adapter.collect(run_for(), tmp_path) == []


def test_a_timeout_reads_a_log_cut_off_mid_write(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    chat = log.chat("Working.", finish="tool_calls")
    log.tool(chat, "HTTPRequest", {"method": "GET", "path": "/"}, "HTTP/1.1 200 OK")
    log.write(tmp_path, cut_last=True)
    assert outcome_of(adapter, tmp_path, None, timed_out=True)[0] is AgentEndState.TIMEOUT
    events = adapter.collect(run_for(), tmp_path)
    assert [e.event_type for e in events] == [AgentEventType.LLM_CALL]


def test_a_refusal_that_ends_the_run(adapter: HackingBuddyGPTAdapter, tmp_path: Path) -> None:
    log = HandBuiltLog()
    log.chat("I can't help with attacking this server.", finish="refusal")
    log.finish("Reached maximum rounds (1)")
    log.write(tmp_path)
    state, signalled = outcome_of(adapter, tmp_path, RunExit.TURN_CAP)
    assert state is AgentEndState.BUDGET_EXHAUSTED
    assert AgentEndState.REFUSED in signalled


def test_a_refusal_with_a_clean_exit_is_refused(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.chat("No.", finish="content_filter")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, 0)[0] is AgentEndState.REFUSED


def test_a_refusal_mid_run_is_not_the_end_state(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.chat("I won't.", finish="refusal")
    chat = log.chat("Fine, finishing.", finish="tool_calls")
    log.tool(chat, "complete", {"summary": "ok"}, "The run is complete.")
    log.finish("got root")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, 0) == (AgentEndState.COMPLETED, (AgentEndState.COMPLETED,))


def _turn_capped(log: HandBuiltLog, evidence: Path) -> None:
    log.finish("Reached maximum rounds (2)")
    log.write(evidence)


def test_tool_calls_that_never_parse_are_a_tool_format_failure(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    for _ in range(2):
        chat = log.chat("", finish="tool_calls")
        log.tool(chat, "HTTPRequest", "{'method': GET", "EXCEPTION: 1 validation error for ...")
    _turn_capped(log, tmp_path)
    state, signalled = outcome_of(adapter, tmp_path, RunExit.TURN_CAP)
    assert state is AgentEndState.BUDGET_EXHAUSTED
    assert AgentEndState.TOOL_FORMAT_FAILURE in signalled


def test_tool_calls_written_as_text_are_a_tool_format_failure(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.chat('{"name": "HTTPRequest", "arguments": {"method": "GET", "path": "/"}}')
    log.chat("<tool_call>\n{...}\n</tool_call>")
    _turn_capped(log, tmp_path)
    assert AgentEndState.TOOL_FORMAT_FAILURE in outcome_of(adapter, tmp_path, 3)[1]


def test_a_call_to_a_tool_that_does_not_exist_is_a_tool_format_failure(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.chat("", finish="tool_calls")
    log.message("status", "Error during tool call call_1: Capability http_get not found")
    _turn_capped(log, tmp_path)
    assert AgentEndState.TOOL_FORMAT_FAILURE in outcome_of(adapter, tmp_path, 3)[1]


def test_a_crash_after_tool_calls_never_parsed(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    chat = log.chat("", finish="tool_calls")
    log.tool(chat, "HTTPRequest", "nope", "EXCEPTION: Invalid JSON")
    log.finish("exception occurred")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, RunExit.CRASHED)[0] is AgentEndState.TOOL_FORMAT_FAILURE


@pytest.mark.parametrize(
    "build",
    [
        # talking without ever trying a tool is not a format failure
        lambda log: log.chat("I think the server is fine."),
        # one tool call that ran is enough
        lambda log: log.tool(
            log.chat("", "tool_calls"), "PentestPlaybook", {"topic": "xss"}, "Checklist"
        ),
        # a tool mentioned in prose, not written as a call
        lambda log: log.chat('I will use HTTPRequest next; "name" is a field.'),
    ],
)
def test_no_tool_format_failure_without_a_broken_call(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path, build: Any
) -> None:
    log = HandBuiltLog()
    build(log)
    _turn_capped(log, tmp_path)
    assert AgentEndState.TOOL_FORMAT_FAILURE not in outcome_of(adapter, tmp_path, 3)[1]


def test_no_model_call_no_tool_format_failure(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.finish("exception occurred")
    log.write(tmp_path)
    assert outcome_of(adapter, tmp_path, 1) == (AgentEndState.CRASHED, (AgentEndState.CRASHED,))


def test_signals_the_runner_saw_are_kept(adapter: HackingBuddyGPTAdapter, tmp_path: Path) -> None:
    a_completed_run().write(tmp_path)
    state, signalled = outcome_of(adapter, tmp_path, 0, budget_exhausted=True, refused=True)
    assert state is AgentEndState.BUDGET_EXHAUSTED
    assert AgentEndState.REFUSED in signalled


# --------------------------------------------------------------------------- collect


def test_collect_turns_the_log_into_agent_events(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    run = run_for()
    path = a_completed_run().write(tmp_path)
    events = adapter.collect(run, tmp_path)
    assert [e.event_type for e in events] == [
        AgentEventType.MESSAGE,  # system prompt
        AgentEventType.MESSAGE,  # limits
        AgentEventType.LLM_CALL,
        AgentEventType.TOOL_CALL,
        AgentEventType.TOOL_CALL,
        AgentEventType.LLM_CALL,
        AgentEventType.TOOL_CALL,
        AgentEventType.MESSAGE,  # "Run finished successfully"
        AgentEventType.FINAL_REPORT,
    ]
    assert [e.seq for e in events] == list(range(len(events)))
    assert {e.run_id for e in events} == {run.run_id}
    assert {e.stream for e in events} == {"agent"}
    request = events[3]
    assert request.tool_name == "HTTPRequest"
    assert request.tool_args == {"method": "GET", "path": "/"}
    assert request.url == f"{TARGET}/"
    assert events[4].url is None  # the playbook is no request
    assert events[-1].text == "Found the import endpoint."
    assert all(e.ts.tzinfo is not None for e in events)
    assert events[2].native_ref is not None
    assert events[2].native_ref.startswith(f"agent/hbg/{path.name}#")
    for event in events:  # every event is valid as stored
        assert AgentEvent.model_validate_json(event.model_dump_json()) == event


def test_the_final_report_is_the_end_state_without_a_summary(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    log = HandBuiltLog()
    log.chat("hm")
    log.finish("Reached maximum rounds (1)")
    log.write(tmp_path)
    assert adapter.collect(run_for(), tmp_path)[-1].text == "Reached maximum rounds (1)"


@pytest.mark.parametrize(
    ("args", "url"),
    [
        ({"method": "GET", "path": "admin"}, f"{TARGET}/admin"),
        ({"method": "GET", "path": "/a", "query": "x=1&y=2"}, f"{TARGET}/a?x=1&y=2"),
        ({"method": "GET", "path": "/a", "query": ""}, f"{TARGET}/a"),
        ({"method": "GET"}, None),
        ({"method": "GET", "path": 5}, None),
    ],
)
def test_request_urls_are_built_like_upstream(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path, args: dict[str, Any], url: str | None
) -> None:
    log = HandBuiltLog()
    log.tool(log.chat(), "HTTPRequest", args, "HTTP/1.1 200 OK")
    log.write(tmp_path)
    assert adapter.collect(run_for(), tmp_path)[1].url == url


@pytest.mark.parametrize("raw", ["not json", "[1, 2]", '"text"', "null", ""])
def test_tool_arguments_that_are_not_an_object_are_kept_raw(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path, raw: str
) -> None:
    log = HandBuiltLog()
    log.tool(log.chat(), "HTTPRequest", raw, "EXCEPTION: bad")
    log.write(tmp_path)
    assert adapter.collect(run_for(), tmp_path)[1].tool_args == {"raw": raw}


def test_an_aware_timestamp_is_kept_and_a_bad_one_refused(tmp_path: Path) -> None:
    span = LogSpan.model_validate(
        {**HandBuiltLog().lines[0], "end_time": "2026-11-26T10:00:00+02:00"}
    )
    assert span.timestamp.utcoffset() is not None
    assert span.timestamp.isoformat() == "2026-11-26T10:00:00+02:00"
    broken = LogSpan.model_validate({**HandBuiltLog().lines[0], "end_time": "yesterday"})
    with pytest.raises(ValueError, match="bad timestamp"):
        _ = broken.timestamp


def test_odd_attribute_shapes_read_as_empty_text() -> None:
    base = HandBuiltLog().lines[0]
    for messages in (None, 5, "x", [5], [{"parts": 5}], [{"parts": [5, {"content": 7}]}]):
        span = LogSpan.model_validate({**base, "attributes": {"gen_ai.output.messages": messages}})
        assert span.output_text == ""
    span = LogSpan.model_validate({**base, "attributes": {"gen_ai.response.finish_reasons": 3}})
    assert span.finish_reasons == ()


# --------------------------------------------------------------------------- hostile logs


def test_no_log_directory_means_no_log(tmp_path: Path) -> None:
    assert RunLog.find(tmp_path) is None
    (tmp_path / "agent" / "hbg").mkdir(parents=True)
    assert RunLog.find(tmp_path) is None


def test_an_empty_log_has_no_end_state(adapter: HackingBuddyGPTAdapter, tmp_path: Path) -> None:
    directory = tmp_path / "agent" / "hbg"
    directory.mkdir(parents=True)
    (directory / "log-20261126-100000.jsonl").write_bytes(b"")
    log = RunLog.find(tmp_path)
    assert log is not None
    assert log.final_state is None
    assert not log.tool_format_failure and not log.ended_on_refusal and not log.hit_a_limit
    assert adapter.collect(run_for(), tmp_path) == []


@pytest.mark.parametrize(
    "line",
    [
        b"not json\n",
        b"[1, 2]\n",
        b'{"span_id": "x"}\n',
        b"\n",
    ],
)
def test_a_bad_line_in_the_middle_makes_the_log_unreadable(tmp_path: Path, line: bytes) -> None:
    log = a_completed_run()
    path = log.write(tmp_path)
    text = path.read_bytes().splitlines(keepends=True)
    path.write_bytes(b"".join([*text[:2], line, *text[2:]]))
    with pytest.raises(ValueError, match="not a log span"):
        RunLog.find(tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        {"surprise": 1},
        {"attributes": [1, 2]},
        {"span_id": 7},
        {"status": {"code": 1}},
        {"parent_span_id": ["x"]},
    ],
)
def test_a_span_of_the_wrong_shape_is_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    log = a_completed_run()
    log.lines[1] = {**log.lines[1], **change}
    log.write(tmp_path)
    with pytest.raises(ValueError, match="not a log span"):
        RunLog.find(tmp_path)


def test_two_logs_are_refused(tmp_path: Path) -> None:
    a_completed_run().write(tmp_path)
    a_completed_run().write(tmp_path, name="log-20261126-100000-1.jsonl")
    with pytest.raises(ValueError, match="2 run logs"):
        RunLog.find(tmp_path)


@pytest.mark.parametrize("name", ["evil.jsonl", "log-x.jsonl", "log-20261126-100000.jsonl.jsonl"])
def test_a_file_that_is_not_a_run_log_is_refused(tmp_path: Path, name: str) -> None:
    a_completed_run().write(tmp_path)
    (tmp_path / "agent" / "hbg" / name).write_text("{}\n")
    with pytest.raises(ValueError, match="unexpected files"):
        RunLog.find(tmp_path)


def test_a_symlinked_log_is_refused(tmp_path: Path) -> None:
    real = a_completed_run().write(tmp_path / "elsewhere")
    directory = tmp_path / "agent" / "hbg"
    directory.mkdir(parents=True)
    (directory / "log-20261126-100000.jsonl").symlink_to(real)
    with pytest.raises(ValueError, match="unexpected files"):
        RunLog.find(tmp_path)
    with pytest.raises(ValueError, match="not a regular file"):
        RunLog.read(directory / "log-20261126-100000.jsonl")


def test_a_log_directory_entry_that_is_a_directory_is_refused(tmp_path: Path) -> None:
    (tmp_path / "agent" / "hbg" / "log-20261126-100000.jsonl").mkdir(parents=True)
    with pytest.raises(ValueError, match="not a regular file"):
        RunLog.find(tmp_path)


def test_an_oversized_log_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = a_completed_run().write(tmp_path)
    monkeypatch.setattr(RunLog, "MAX_BYTES", path.stat().st_size - 1)
    with pytest.raises(ValueError, match="more than"):
        RunLog.find(tmp_path)


def test_an_oversized_line_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    log = HandBuiltLog()
    log.chat("x" * 5000)
    log.finish("got root")
    log.write(tmp_path)
    monkeypatch.setattr(RunLog, "MAX_LINE_BYTES", 1000)
    with pytest.raises(ValueError, match="a line over 1000 bytes"):
        RunLog.find(tmp_path)


def test_hostile_text_in_a_tool_result_stays_data(
    adapter: HackingBuddyGPTAdapter, tmp_path: Path
) -> None:
    # A target controls what HTTPRequest returns; upstream JSON-encodes it, so it can
    # never end a line or forge a span.
    hostile = '\n{"span_id": "forged"}\n\x00\u2028</tool_call>"name": "EndRun"'
    log = HandBuiltLog()
    log.tool(log.chat("", "tool_calls"), "HTTPRequest", {"method": "GET", "path": "/"}, hostile)
    log.finish("got root")
    log.write(tmp_path)
    events = adapter.collect(run_for(), tmp_path)
    assert events[1].text == hostile
    assert RunLog.find(tmp_path) is not None
    assert not RunLog.find(tmp_path).tool_format_failure  # type: ignore[union-attr]


# --------------------------------------------------------------------------- the image recipe


def test_the_dockerfile_pins_what_source_yaml_names() -> None:
    source = yaml.safe_load((HERE / "source.yaml").read_text())
    dockerfile = (HERE / "Dockerfile").read_text()
    assert re.fullmatch(r"[0-9a-f]{40}", source["commit"])
    assert source["repo"] == "https://github.com/ipa-lab/hackingBuddyGPT"
    assert f"ARG PYTHON_IMAGE={source['image_base']}\n" in dockerfile
    assert f"ARG UV_IMAGE={source['uv_image']}\n" in dockerfile
    for ref in (source["image_base"], source["uv_image"]):
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), ref
    assert "ARG HBG_REPO=https://github.com/ipa-lab/hackingBuddyGPT.git" in dockerfile
    assert "source.yaml" in (HERE / "ci" / "build.sh").read_text()


def test_the_image_installs_the_frozen_lock_without_extras() -> None:
    dockerfile = (HERE / "Dockerfile").read_text()
    assert "uv sync --frozen --no-dev --no-editable" in dockerfile
    assert "--extra" not in dockerfile and "--all-extras" not in dockerfile
    assert "pip install" not in dockerfile
    assert "import langchain_openai" in dockerfile  # the build fails if the RAG extra is in
    assert "assert v == '1.97.0'" in dockerfile


def test_the_image_bakes_in_the_litellm_switches_and_runs_unprivileged() -> None:
    dockerfile = (HERE / "Dockerfile").read_text()
    for name, value in HackingBuddyGPTAdapter.LITELLM_ENV.items():
        assert re.search(rf"^\s+{name}={value}\b", dockerfile, re.M), name
    assert "USER 10001:10001" in dockerfile
    copied = re.search(r"^COPY (lab_hbg/\S+ )+/opt/lab/lab_hbg/$", dockerfile, re.M)
    assert copied is not None
    assert set(re.findall(r"lab_hbg/(\S+\.py)", copied[0])) == {p.name for p in PLUGIN.glob("*.py")}


def test_every_patch_is_listed_in_the_sheet_and_says_why(adapter: HackingBuddyGPTAdapter) -> None:
    patches = sorted((HERE / "patches").glob("*.patch"))
    touched: list[str] = []
    for patch in patches:
        text = patch.read_text()
        header = text.split("diff --git", 1)[0]
        assert "Why:" in header, f"{patch.name}: the header must say why"
        touched += re.findall(r"^\+\+\+ b/(\S+)$", text, re.M)
    listed = [p.upstream_file for p in adapter.describe().patches]
    assert sorted(touched) == sorted(listed)


def test_the_api_base_patch_passes_it_and_drops_the_openrouter_default() -> None:
    text = (HERE / "patches" / "0001-honour-llm-api-base.patch").read_text()
    added = [line[1:].strip() for line in text.splitlines() if line.startswith("+ ")]
    removed = [line[1:].strip() for line in text.splitlines() if line.startswith("- ")]
    assert "api_base=self.api_base," in added
    assert any("openrouter.ai" in line for line in removed)
    assert not any("openrouter.ai" in line for line in added)


def test_the_ci_scripts_are_executable_in_git() -> None:
    import subprocess

    for name in ("build.sh", "check.sh"):
        mode = subprocess.run(  # noqa: S603 -- fixed argv
            ["git", "ls-files", "-s", f"agents/hackingbuddygpt/ci/{name}"],  # noqa: S607
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.split(" ", 1)[0]
        assert mode == "100755", f"ci/{name} is not executable in git ({mode or 'untracked'})"


def test_the_sheet_on_disk_validates() -> None:
    sheet = CapabilitySheet.load(ROOT / "agents" / "sheets" / "hackingbuddygpt.yaml")
    assert sheet.framework == HackingBuddyGPTAdapter.framework


# --------------------------------------------------------------------------- the CI smoke check


def _smoke_module() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("hbg_smoke", HERE / "ci" / "hbg_smoke.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses look their module up there
    spec.loader.exec_module(module)
    return module


SMOKE = _smoke_module()


def _good_chat(**changes: Any) -> dict[str, Any]:
    body = {
        "model": SMOKE.MODEL,
        "messages": [{"role": "system", "content": f"Your task:\n{SMOKE.OBJECTIVE}\n"}],
        "options": {"num_ctx": SMOKE.NUM_CTX},
        "stream": False,
        "tools": [{"type": "function", "function": {"name": n}} for n in sorted(OFFERED_TOOLS)],
    }
    return {**body, **changes}


def _smoke_out(tmp_path: Path, requests: list[dict[str, Any]], canary: str = "") -> Path:
    out = tmp_path / "smoke"
    out.mkdir()
    (out / "requests.jsonl").write_text("".join(json.dumps(r) + "\n" for r in requests))
    (out / "canary.jsonl").write_text(canary)
    return out


def _tools_run() -> list[dict[str, Any]]:
    return [
        {"path": "/api/chat", "body": _good_chat()},
        {"path": "/v1/models", "body": None},
        {"path": "/api/show", "body": {"name": "stub-model"}},
        {"path": "/api/chat", "body": json.dumps(_good_chat())},  # a body kept as text
    ]


def test_the_smoke_scenarios_render_the_adapters_own_command(tmp_path: Path) -> None:
    for name, scenario in SMOKE.Scenario.SCENARIOS.items():
        assert scenario.script.is_file(), name
        scenario.render(tmp_path / name)
        argv = (tmp_path / name / "command").read_bytes().split(b"\0")
        assert argv[:2] == [b"sh", b"-c"]
        launch = scenario.launch()
        inner = argv[2].decode()
        for arg in launch.command:
            if not arg.startswith("--objective_file="):
                assert arg in inner, arg
        assert "--objective_file=/tmp/objective.txt" in inner
        env = (tmp_path / name / "env").read_text().splitlines()
        assert env == [f"{k}={v}" for k, v in launch.env.items()]


def test_a_good_smoke_run_passes(tmp_path: Path) -> None:
    scenario = SMOKE.Scenario.SCENARIOS["tools"]
    assert scenario.verify(_smoke_out(tmp_path, _tools_run()), 0) == []


@pytest.mark.parametrize(
    ("requests", "canary", "code", "problem"),
    [
        (_tools_run(), '{"host": "example.com"}\n', 0, "canary saw traffic"),
        (_tools_run(), "", 3, "exit 3, expected 0"),
        ([*_tools_run(), {"path": "/v1/messages", "body": {}}], "", 0, "does not explain"),
        (_tools_run()[:1], "", 0, "1 /api/chat requests, expected 2"),
        (
            [{"path": "/api/chat", "body": _good_chat(options={"num_ctx": 2048})}] * 2,
            "",
            0,
            "expected num_ctx",
        ),
        ([{"path": "/api/chat", "body": _good_chat(tools=[])}] * 2, "", 0, "tools []"),
        ([{"path": "/api/chat", "body": _good_chat(model="x")}] * 2, "", 0, "model 'x'"),
        ([{"path": "/api/chat", "body": _good_chat(stream=True)}] * 2, "", 0, "stream True"),
        ([{"path": "/api/chat", "body": _good_chat(messages=[])}] * 2, "", 0, "system prompt"),
        (
            [{"path": "/api/chat", "body": _good_chat(messages=[{"role": "system"}])}] * 2,
            "",
            0,
            "does not carry the objective",
        ),
        ([{"path": "/api/chat", "body": "not json"}] * 2, "", 0, "not a JSON object"),
        ([], "", 0, "model call paths with no request"),
    ],
)
def test_a_bad_smoke_run_fails(
    tmp_path: Path, requests: list[dict[str, Any]], canary: str, code: int, problem: str
) -> None:
    problems = SMOKE.Scenario.SCENARIOS["tools"].verify(
        _smoke_out(tmp_path, requests, canary), code
    )
    assert any(problem in p for p in problems), problems


def test_missing_smoke_output_fails(tmp_path: Path) -> None:
    scenario = SMOKE.Scenario.SCENARIOS["turn-cap"]
    with pytest.raises(SMOKE.SmokeFailure, match="missing"):
        scenario.verify(tmp_path, 3)
    (tmp_path / "requests.jsonl").write_text('["not a request"]\n')
    with pytest.raises(SMOKE.SmokeFailure, match="not a recorded request"):
        scenario.verify(tmp_path, 3)
    (tmp_path / "requests.jsonl").write_text("")
    assert "no canary.jsonl" in scenario.verify(tmp_path, 3)


@pytest.mark.parametrize(
    "argv",
    [[], ["render"], ["render", "nope", "x"], ["verify", "tools", "x"], ["bogus", "tools", "x"]],
)
def test_the_smoke_helper_refuses_a_bad_command_line(argv: list[str]) -> None:
    assert SMOKE.main(argv) == 2
