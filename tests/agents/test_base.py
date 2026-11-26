"""The adapter base: capability sheets, the run checks, end states and the ABC."""

from __future__ import annotations

import itertools
import subprocess
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml
from pydantic import ValidationError

from agents.base import (
    MAX_NUM_CTX,
    MAX_SHEET_BYTES,
    PLACEHOLDERS,
    SHEETS_DIR,
    Adapter,
    AdapterLimits,
    AdapterOutcome,
    AdapterRun,
    AgentEndState,
    AgentHost,
    AgentLaunch,
    CapabilitySheet,
    ChannelStatus,
    EndStateMapper,
    ExitSignals,
    ModelConfig,
    SideChannel,
    SubAgentCap,
    SupportLevel,
    UnsupportedRun,
)
from control.core.ids import new_id
from control.core.models import AgentEvent, EndStatus
from control.telemetry.extract import summarise
from control.telemetry.wire import unparsed_call

# --------------------------------------------------------------------------- helpers

_DROP = object()

CAP = {
    "max_agents": 5,
    "max_concurrent": 3,
    "max_agents_setting": "FAKE_MAX_MEMBERS",
    "max_concurrent_setting": "FAKE_MAX_CONCURRENT",
    "audit_ref": "§2.3",
}


def channel(
    status: str = "disabled", setting: str | None = "FAKE_TELEMETRY=false"
) -> dict[str, Any]:
    doc: dict[str, Any] = {"status": status, "audit_ref": "§2.2, §3"}
    if setting is not None:
        doc["setting"] = setting
    return doc


def good_sheet(**changes: Any) -> dict[str, Any]:
    """A valid, runnable sheet document; ``changes`` replace (or, with ``_DROP``, remove) keys."""
    doc: dict[str, Any] = {
        "framework": "fake",
        "version": "v1.0.0",
        "commit": "abc1234",
        "image_digest": "unknown",
        "support_level": "native",
        "wire_formats": ["ollama_chat"],
        "model_call_paths": ["main agent (fake/agent.py)"],
        "side_channels": {"telemetry": channel()},
        "min_num_ctx": 16384,
        "sub_agents": "dynamic",
        "agent_id_source": None,
        "agent_id_gap": "unknown: no log of child ids was read",
        "patches": [],
        "max_turns_knob": "FAKE_MAX_TURNS",
        "audit_refs": {
            "version": "§2.2",
            "support_level": "§2.2",
            "wire_formats": "§1",
            "model_call_paths": "§2.2",
            "min_num_ctx": "§2.2",
            "sub_agents": "§2.2",
            "agent_id_source": "§2.2",
            "patches": "§3",
            "max_turns_knob": "§2.2",
        },
    }
    for key, value in changes.items():
        if value is _DROP:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


SINGLE_AGENT = {"sub_agents": "none", "agent_id_source": None, "agent_id_gap": None}


def write_sheet(directory: Path, doc: object, name: str = "fake") -> Path:
    path = directory / f"{name}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def sheet_of(**changes: Any) -> CapabilitySheet:
    return CapabilitySheet.model_validate(good_sheet(**changes))


def model(num_ctx: int | None = 32768) -> ModelConfig:
    return ModelConfig(name="qwen3:32b", num_ctx=num_ctx)


def run_for(cfg: ModelConfig) -> AdapterRun:
    return AdapterRun(
        run_id=new_id("run"),
        model=cfg,
        target_url="http://goat:8000",
        objective="find the flag",
        llm_base_url="http://tap:8080",
        limits=AdapterLimits(max_turns=50, timeout_s=3600),
    )


@dataclass
class Result:
    returncode: int = 0
    stdout: bytes = b""


@dataclass
class RecordingHost:
    """An AgentHost that records every command."""

    commands: list[tuple[str, tuple[str, ...]]] = field(default_factory=list)

    def exec(self, service: str, argv: Sequence[str], *, timeout_s: float) -> Result:
        self.commands.append((service, tuple(argv)))
        return Result()


class FakeAdapter(Adapter):
    """A minimal adapter. Everything it needs per run comes from the AdapterRun."""

    framework: ClassVar[str] = "fake"
    sheets_dir: ClassVar[Path]
    signals_update: ClassVar[dict[str, Any]] = {}
    recorded: ClassVar[dict[str, str]] = {}

    def __init__(self) -> None:
        super().__init__()
        self.rendered: list[AdapterRun] = []

    def render(self, run: AdapterRun) -> AgentLaunch:
        self.rendered.append(run)
        return AgentLaunch(
            image="lab-agent-fake",
            command=("fake", "--headless", "--max-turns", str(run.limits.max_turns)),
            env={"FAKE_MODEL": run.model.name, "FAKE_NUM_CTX": str(run.model.num_ctx)},
            recorded_settings=dict(self.recorded),
        )

    def start(self, run: AdapterRun, host: AgentHost) -> None:
        host.exec("agent", ["fake-start", run.run_id], timeout_s=30)

    def exit_signals(self, run: AdapterRun, observed: ExitSignals, evidence: Path) -> ExitSignals:
        return observed.model_copy(update=self.signals_update)

    def collect(self, run: AdapterRun, evidence: Path) -> list[AgentEvent]:
        return []

    def teardown(self, run: AdapterRun, host: AgentHost) -> None:
        host.exec("cellguard", ["reap", f"fake-{run.run_id}"], timeout_s=30)


@pytest.fixture
def fake_adapter(tmp_path: Path) -> Callable[..., FakeAdapter]:
    def make(
        sheet: dict[str, Any] | None = None,
        recorded_settings: dict[str, str] | None = None,
        **signals: Any,
    ) -> FakeAdapter:
        write_sheet(tmp_path, sheet if sheet is not None else good_sheet())

        class Adapted(FakeAdapter):
            sheets_dir = tmp_path
            signals_update = signals
            recorded = recorded_settings or {}

        return Adapted()

    return make


# --------------------------------------------------------------------------- the sheet


def test_a_good_sheet_validates() -> None:
    sheet = sheet_of()
    assert sheet.support_level is SupportLevel.NATIVE
    assert sheet.min_num_ctx == 16384
    assert sheet.model_call_paths == ("main agent (fake/agent.py)",)
    assert sheet.side_channels["telemetry"].setting == "FAKE_TELEMETRY=false"
    assert sheet.check_runnable(model()) is None


@pytest.mark.parametrize("level", ["native", "openai_compatible", "unofficial"])
def test_a_runnable_sheet_must_list_its_model_call_paths(level: str) -> None:
    with pytest.raises(ValidationError, match="model_call_paths"):
        sheet_of(support_level=level, model_call_paths=[])


@pytest.mark.parametrize("level", ["native", "openai_compatible", "unofficial"])
def test_a_runnable_sheet_must_name_a_wire_format(level: str) -> None:
    with pytest.raises(ValidationError, match="wire_formats"):
        sheet_of(support_level=level, wire_formats=[])


def test_a_sheet_with_no_support_may_list_nothing() -> None:
    sheet = sheet_of(support_level="none", wire_formats=[], model_call_paths=[])
    assert sheet.support_level is SupportLevel.NONE


@pytest.mark.parametrize("field_name", ["min_num_ctx", "max_turns_knob"])
def test_unknown_values_are_allowed_in_a_sheet(field_name: str) -> None:
    assert getattr(sheet_of(**{field_name: "unknown"}), field_name) == "unknown"


# --------------------------------------------------------------------------- side channels


PLACEHOLDER_SPELLINGS = sorted(
    {*PLACEHOLDERS, "UNKNOWN", " Unknown ", "TBD", "Off", "OFF", "None", "N/A", "\t?\t", "   "}
)


@pytest.mark.parametrize("setting", PLACEHOLDER_SPELLINGS)
def test_a_disabled_side_channel_refuses_a_placeholder_setting(setting: str) -> None:
    with pytest.raises(ValidationError, match="setting"):
        SideChannel.model_validate(channel(setting=setting))


def test_the_placeholders_include_the_ruled_ones() -> None:
    assert {"unknown", "tbd", "?", "off", "none", "n/a", ""} <= PLACEHOLDERS


def test_a_disabled_side_channel_needs_a_setting() -> None:
    with pytest.raises(ValidationError, match="setting"):
        SideChannel.model_validate(channel(setting=None))


@pytest.mark.parametrize("setting", [0, False, ["X=0"], {"X": "0"}])
def test_a_side_channel_setting_must_be_text(setting: object) -> None:
    with pytest.raises(ValidationError):
        SideChannel.model_validate({**channel(), "setting": setting})


def test_an_unresolved_side_channel_has_no_setting() -> None:
    with pytest.raises(ValidationError, match="unresolved"):
        SideChannel.model_validate(channel("unresolved", "FAKE_X=0"))
    assert SideChannel.model_validate(channel("unresolved", None)).setting is None


@pytest.mark.parametrize(
    "doc",
    [
        {"status": "off", "setting": "X=0", "audit_ref": "§2"},
        {"status": "DISABLED", "setting": "X=0", "audit_ref": "§2"},
        {"status": "disabled", "setting": "X=0"},
        {"status": "disabled", "setting": "X=0", "audit_ref": "section 2"},
        {"status": "disabled", "setting": "X=0", "audit_ref": "§2", "colour": "red"},
        {"status": "disabled", "setting": "two\nlines", "audit_ref": "§2"},
        "FAKE_TELEMETRY=false",
        None,
    ],
)
def test_a_malformed_side_channel_is_refused(doc: object) -> None:
    with pytest.raises(ValidationError):
        sheet_of(side_channels={"telemetry": doc})


@pytest.mark.parametrize("name", ["", "  ", "two\nlines", "Web Search", "../x"])
def test_a_side_channel_needs_a_slug_name(name: str) -> None:
    with pytest.raises(ValidationError):
        sheet_of(side_channels={name: channel()})


def test_an_unresolved_side_channel_is_allowed_in_a_sheet_but_blocks_every_run() -> None:
    sheet = sheet_of(
        side_channels={
            "telemetry": channel(),
            "update_check": channel("unresolved", None),
            "graphiti": channel("unresolved", None),
        }
    )
    assert sheet.unresolved_side_channels == ("graphiti", "update_check")
    verdict = sheet.check_runnable(model(131072))
    assert isinstance(verdict, UnsupportedRun)
    assert "unresolved side channel graphiti" in verdict.reason
    assert "unresolved side channel update_check" in verdict.reason


def test_a_sheet_with_only_disabled_channels_has_none_unresolved() -> None:
    assert sheet_of().unresolved_side_channels == ()


# --------------------------------------------------------------------------- turn cap


@pytest.mark.parametrize("knob", [*sorted(PLACEHOLDERS - {"unknown"}), " Unknown ", "TBD"])
def test_the_turn_cap_is_a_setting_or_unknown(knob: str) -> None:
    with pytest.raises(ValidationError, match="max_turns_knob"):
        sheet_of(max_turns_knob=knob)


def test_an_unknown_turn_cap_blocks_every_run() -> None:
    verdict = sheet_of(max_turns_knob="unknown").check_runnable(model(131072))
    assert isinstance(verdict, UnsupportedRun)
    assert "turn cap" in verdict.reason


def test_every_reason_a_run_is_blocked_is_given_at_once() -> None:
    sheet = sheet_of(
        support_level="none",
        wire_formats=[],
        model_call_paths=[],
        max_turns_knob="unknown",
        side_channels={"update_check": channel("unresolved", None)},
    )
    verdict = sheet.check_runnable(model(None))
    assert isinstance(verdict, UnsupportedRun)
    for part in ("no Ollama support", "update_check", "turn cap", "not pinned"):
        assert part in verdict.reason


# --------------------------------------------------------------------------- other fields


@pytest.mark.parametrize(
    "value",
    [0, -1, -16384, True, False, 1.5, 16384.0, "16384", "16k", "", None, MAX_NUM_CTX + 1, 10**12],
)
def test_min_num_ctx_is_a_sane_positive_integer_or_unknown(value: object) -> None:
    with pytest.raises(ValidationError, match="min_num_ctx"):
        sheet_of(min_num_ctx=value)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("framework", "Strix"),
        ("framework", "../strix"),
        ("framework", ""),
        ("commit", "xyz1234"),
        ("commit", "abc12"),
        ("commit", "a" * 41),
        ("commit", "unknown"),
        ("image_digest", "sha256:abc"),
        ("image_digest", "latest"),
        ("image_digest", ""),
        ("use_case", ""),
        ("use_case", "two\nlines"),
        ("support_level", "partial"),
        ("support_level", "NATIVE"),
        ("wire_formats", ["grpc"]),
        ("wire_formats", ["ollama_chat", "ollama_chat"]),
        ("wire_formats", "ollama_chat"),
        ("model_call_paths", ["main", "main"]),
        ("model_call_paths", [""]),
        ("model_call_paths", ["two\nlines"]),
        ("model_call_paths", ["nul\x00byte"]),
        ("model_call_paths", ["x" * 1001]),
        ("side_channels", ["telemetry"]),
        ("side_channels", None),
        ("sub_agents", "many"),
        ("sub_agents", None),
        ("version", ""),
        ("version", 1.7),
        ("max_turns_knob", ""),
        ("max_turns_knob", 100),
        ("patches", [{"upstream_file": "a.py", "change": "", "reason": "r"}]),
        ("patches", [{"upstream_file": "a.py", "change": "c"}]),
        (
            "patches",
            [
                {"upstream_file": "a.py", "change": "c", "reason": "r"},
                {"upstream_file": "a.py", "change": "d", "reason": "r"},
            ],
        ),
        ("patches", ["a.py"]),
    ],
)
def test_malformed_fields_are_refused(field_name: str, value: object) -> None:
    with pytest.raises(ValidationError):
        sheet_of(**{field_name: value})


@pytest.mark.parametrize(
    "field_name",
    [
        "framework",
        "commit",
        "support_level",
        "model_call_paths",
        "side_channels",
        "min_num_ctx",
        "max_turns_knob",
        "audit_refs",
    ],
)
def test_a_missing_field_is_refused(field_name: str) -> None:
    with pytest.raises(ValidationError, match=field_name):
        sheet_of(**{field_name: _DROP})


@pytest.mark.parametrize("old_name", ["side_channels_disabled", "base_url"])
def test_an_unknown_field_is_refused(old_name: str) -> None:
    with pytest.raises(ValidationError, match="extra"):
        sheet_of(**{old_name: {"telemetry": "X=0"}})


def test_a_sheet_is_frozen() -> None:
    sheet = sheet_of()
    with pytest.raises(ValidationError):
        sheet.min_num_ctx = 1  # type: ignore[misc]


def test_a_real_image_digest_is_accepted() -> None:
    digest = "sha256:" + "a" * 64
    assert sheet_of(image_digest=digest).image_digest == digest


def test_agent_ids_need_a_source_or_a_reason_when_there_are_sub_agents() -> None:
    with pytest.raises(ValidationError, match="agent_id"):
        sheet_of(agent_id_source=None, agent_id_gap=None)
    with pytest.raises(ValidationError, match="agent_id"):
        sheet_of(agent_id_source="events.jsonl agent_id", agent_id_gap="no reason")
    sheet = sheet_of(agent_id_source="events.jsonl agent_id", agent_id_gap=None)
    assert sheet.agent_id_source == "events.jsonl agent_id"


@pytest.mark.parametrize(
    "changes",
    [
        {"agent_id_source": "log"},
        {"agent_id_gap": "unknown: nothing to read"},
        {"sub_agent_cap": CAP},
    ],
)
def test_a_single_agent_framework_has_no_sub_agent_details(changes: dict[str, Any]) -> None:
    assert sheet_of(**SINGLE_AGENT).sub_agents == "none"
    with pytest.raises(ValidationError):
        sheet_of(**{**SINGLE_AGENT, **changes})


@pytest.mark.parametrize(
    "refs",
    [
        {},
        {"version": "§2.2"},
        {**good_sheet()["audit_refs"], "patches": "section 3"},
        {**good_sheet()["audit_refs"], "patches": "§"},
        {**good_sheet()["audit_refs"], "patches": "§3,§2"},
        {**good_sheet()["audit_refs"], "patches": ""},
        {**good_sheet()["audit_refs"], "colour": "§3"},
        {**good_sheet()["audit_refs"], "side_channels": "§3"},  # cited per channel instead
    ],
)
def test_every_audited_field_cites_an_audit_section(refs: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match="audit_refs"):
        sheet_of(audit_refs=refs)


# --------------------------------------------------------------------------- sub-agent cap


def test_a_sub_agent_cap_names_its_settings() -> None:
    cap = sheet_of(sub_agent_cap=CAP).sub_agent_cap
    assert cap is not None
    assert cap.settings == {"FAKE_MAX_MEMBERS": 5, "FAKE_MAX_CONCURRENT": 3}


@pytest.mark.parametrize(
    "changes",
    [
        {"max_agents": 0},
        {"max_agents": -5},
        {"max_agents": True},
        {"max_agents": "5"},
        {"max_agents": 10**9},
        {"max_concurrent": 6},  # more at once than in total
        {"max_concurrent_setting": "FAKE_MAX_MEMBERS"},
        {"max_agents_setting": "unknown"},
        {"max_agents_setting": "TBD"},
        {"audit_ref": "line 237"},
    ],
)
def test_an_absurd_sub_agent_cap_is_refused(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SubAgentCap.model_validate({**CAP, **changes})


# --------------------------------------------------------------------------- loading


def test_load_reads_a_sheet_from_yaml(tmp_path: Path) -> None:
    assert CapabilitySheet.load(write_sheet(tmp_path, good_sheet())).framework == "fake"


def test_load_refuses_a_sheet_named_after_another_framework(tmp_path: Path) -> None:
    path = write_sheet(tmp_path, good_sheet(), name="strix")
    with pytest.raises(ValueError, match="strix"):
        CapabilitySheet.load(path)


@pytest.mark.parametrize("duplicate", ["min_num_ctx: 1024\n", "side_channels:\n  a: null\n"])
def test_load_refuses_duplicate_keys(tmp_path: Path, duplicate: str) -> None:
    path = tmp_path / "fake.yaml"
    path.write_text(yaml.safe_dump(good_sheet(), sort_keys=False) + duplicate, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        CapabilitySheet.load(path)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "null\n",
        "- framework: fake\n",
        "just a string\n",
        "framework: [unclosed\n",
        "!!python/object/apply:os.system ['true']\n",
    ],
)
def test_load_refuses_yaml_that_is_not_a_sheet_mapping(tmp_path: Path, text: str) -> None:
    path = tmp_path / "fake.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError):
        CapabilitySheet.load(path)


def test_load_refuses_a_file_that_is_not_utf8(tmp_path: Path) -> None:
    path = tmp_path / "fake.yaml"
    path.write_bytes(b"framework: \xff\xfe\n")
    with pytest.raises(ValueError, match="UTF-8"):
        CapabilitySheet.load(path)


def test_load_refuses_an_oversized_file(tmp_path: Path) -> None:
    path = tmp_path / "fake.yaml"
    path.write_bytes(b"#" * (MAX_SHEET_BYTES + 1))
    with pytest.raises(ValueError, match="bytes"):
        CapabilitySheet.load(path)


def test_load_refuses_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="cannot read"):
        CapabilitySheet.load(tmp_path / "fake.yaml")


@pytest.mark.parametrize("name", ["", "../etc/passwd", "Strix", "a/b", "fake.yaml"])
def test_for_framework_refuses_names_that_are_not_slugs(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError, match="framework"):
        CapabilitySheet.for_framework(name, sheets_dir=tmp_path)


def test_for_framework_finds_the_shipped_sheets() -> None:
    assert CapabilitySheet.for_framework("strix").framework == "strix"
    assert SHEETS_DIR.is_dir()


def test_importing_the_base_does_not_import_the_runner() -> None:
    # The runner will import the adapters, so the base must never import the runner.
    code = (
        "import sys, agents.base\n"
        "bad = sorted(m for m in sys.modules if m.startswith('control.runner'))\n"
        "assert not bad, bad\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)  # noqa: S603
    assert done.returncode == 0, done.stderr


# --------------------------------------------------------------------------- context check


def test_a_context_below_the_minimum_is_unsupported_with_a_reason() -> None:
    verdict = sheet_of(min_num_ctx=16384).check_context(model(8192))
    assert isinstance(verdict, UnsupportedRun)
    assert verdict.end_state is AgentEndState.UNSUPPORTED
    for part in ("8192", "16384", "fake", "qwen3:32b"):
        assert part in verdict.reason


@pytest.mark.parametrize("num_ctx", [16384, 16385, 131072, MAX_NUM_CTX])
def test_a_context_at_or_above_the_minimum_is_fine(num_ctx: int) -> None:
    assert sheet_of(min_num_ctx=16384).check_context(model(num_ctx)) is None


def test_one_token_short_is_unsupported() -> None:
    assert isinstance(sheet_of(min_num_ctx=16384).check_context(model(16383)), UnsupportedRun)


def test_an_unpinned_context_is_unsupported() -> None:
    verdict = sheet_of(min_num_ctx=16384).check_context(model(None))
    assert isinstance(verdict, UnsupportedRun)
    assert "not pinned" in verdict.reason


def test_an_unpinned_context_is_unsupported_even_without_a_known_minimum() -> None:
    assert isinstance(sheet_of(min_num_ctx="unknown").check_context(model(None)), UnsupportedRun)


def test_an_unknown_minimum_accepts_any_pinned_context() -> None:
    assert sheet_of(min_num_ctx="unknown").check_context(model(1)) is None


def test_the_context_check_never_shrinks_or_changes_the_model() -> None:
    cfg = model(8192)
    sheet_of(min_num_ctx=16384).check_runnable(cfg)
    assert cfg.num_ctx == 8192
    with pytest.raises(ValidationError):
        cfg.num_ctx = 16384  # type: ignore[misc]


def test_a_framework_without_support_is_never_runnable() -> None:
    sheet = sheet_of(support_level="none", wire_formats=[], model_call_paths=[])
    verdict = sheet.check_runnable(model(131072))
    assert isinstance(verdict, UnsupportedRun)
    assert "support" in verdict.reason


@pytest.mark.parametrize("num_ctx", [0, -1, True, 1.5, "32768", MAX_NUM_CTX + 1])
def test_a_model_config_refuses_absurd_contexts(num_ctx: object) -> None:
    with pytest.raises(ValidationError):
        ModelConfig(name="qwen3:32b", num_ctx=num_ctx)  # type: ignore[arg-type]


@pytest.mark.parametrize("name", ["", "   ", "two\nlines"])
def test_a_model_config_needs_a_name(name: str) -> None:
    with pytest.raises(ValidationError):
        ModelConfig(name=name, num_ctx=32768)


# --------------------------------------------------------------------------- end states


def test_every_end_state_has_a_documented_end_status_value() -> None:
    assert set(EndStateMapper.END_STATUS_VALUES) == set(AgentEndState)
    for state, value in EndStateMapper.END_STATUS_VALUES.items():
        assert value == state.value


@pytest.mark.parametrize(
    "state", [s for s in AgentEndState if s not in EndStateMapper.PENDING_IN_END_STATUS]
)
def test_existing_end_states_map_onto_end_status(state: AgentEndState) -> None:
    assert EndStateMapper.end_status(state) is EndStatus(state.value)


@pytest.mark.parametrize("state", sorted(EndStateMapper.PENDING_IN_END_STATUS))
def test_new_end_states_wait_for_the_wiring(state: AgentEndState) -> None:
    # When the wiring adds these to EndStatus, drop them from PENDING_IN_END_STATUS.
    assert state.value not in {s.value for s in EndStatus}
    with pytest.raises(LookupError, match=state.value):
        EndStateMapper.end_status(state)


def test_the_pending_end_states_are_exactly_the_two_new_ones() -> None:
    assert {
        AgentEndState.TOOL_FORMAT_FAILURE,
        AgentEndState.UNSUPPORTED,
    } == EndStateMapper.PENDING_IN_END_STATUS


B, T, R, F = "budget", "timeout", "refused", "tool_format"
E = AgentEndState

# Written out by hand, row by row: (signals set, exit code, the state the run is filed
# under). A wrong precedence order fails at least one row.
END_STATE_TABLE: list[tuple[set[str], int | None, AgentEndState]] = [
    (set(), 0, E.COMPLETED),
    (set(), 1, E.CRASHED),
    (set(), 2, E.CRASHED),
    (set(), 137, E.CRASHED),
    (set(), -9, E.CRASHED),
    ({T}, None, E.TIMEOUT),
    ({T}, 137, E.TIMEOUT),
    ({T}, 0, E.TIMEOUT),
    ({B}, 0, E.BUDGET_EXHAUSTED),
    ({B}, 1, E.BUDGET_EXHAUSTED),
    ({R}, 0, E.REFUSED),
    ({R}, 1, E.REFUSED),
    ({F}, 0, E.TOOL_FORMAT_FAILURE),
    ({F}, 1, E.TOOL_FORMAT_FAILURE),
    ({B, T}, None, E.BUDGET_EXHAUSTED),
    ({B, R}, 0, E.BUDGET_EXHAUSTED),
    ({B, F}, 1, E.BUDGET_EXHAUSTED),
    ({T, R}, None, E.TIMEOUT),
    ({T, F}, None, E.TIMEOUT),
    ({R, F}, 0, E.REFUSED),
    ({R, F}, 1, E.REFUSED),
    ({B, T, R}, None, E.BUDGET_EXHAUSTED),
    ({T, R, F}, 137, E.TIMEOUT),
    ({B, R, F}, 0, E.BUDGET_EXHAUSTED),
    ({B, T, R, F}, None, E.BUDGET_EXHAUSTED),
]


def signals_of(flags: set[str], exit_code: int | None) -> ExitSignals:
    return ExitSignals(
        exit_code=exit_code,
        budget_exhausted=B in flags,
        timed_out=T in flags,
        refused=R in flags,
        tool_format_failure=F in flags,
    )


@pytest.mark.parametrize(("flags", "exit_code", "expected"), END_STATE_TABLE)
def test_the_end_state_table(flags: set[str], exit_code: int | None, expected: E) -> None:
    assert EndStateMapper.classify(signals_of(flags, exit_code)) is expected


ALL_FLAG_SETS = [
    {flag for flag, on in zip((B, T, R, F), bits, strict=True) if on}
    for bits in itertools.product([False, True], repeat=4)
]
POSSIBLE = [(f, code) for f in ALL_FLAG_SETS for code in (0, 1, None) if code is not None or T in f]
IMPOSSIBLE = [(f, None) for f in ALL_FLAG_SETS if T not in f]


@pytest.mark.parametrize(("flags", "exit_code"), POSSIBLE)
def test_no_signal_is_lost_in_the_outcome(flags: set[str], exit_code: int | None) -> None:
    signals = signals_of(flags, exit_code)
    outcome = AdapterOutcome.of(signals)
    assert outcome.signals == signals
    assert outcome.end_state is outcome.signalled[0]
    flagged = {B: E.BUDGET_EXHAUSTED, T: E.TIMEOUT, R: E.REFUSED, F: E.TOOL_FORMAT_FAILURE}
    for flag in flags:
        assert flagged[flag] in outcome.signalled  # e.g. a refusal before a timeout
    if F in flags:
        assert outcome.end_state is not E.COMPLETED
    assert outcome.end_state is not E.UNSUPPORTED


@pytest.mark.parametrize(("flags", "exit_code"), IMPOSSIBLE)
def test_an_agent_that_never_exited_must_have_timed_out(
    flags: set[str], exit_code: int | None
) -> None:
    with pytest.raises(ValidationError, match="timed_out"):
        signals_of(flags, exit_code)


def test_a_refusal_followed_by_a_timeout_stays_visible() -> None:
    outcome = AdapterOutcome.of(signals_of({R, T}, None))
    assert outcome.end_state is E.TIMEOUT
    assert outcome.signalled == (E.TIMEOUT, E.REFUSED)
    assert outcome.signals.refused


def test_a_crash_after_a_refusal_is_listed_too() -> None:
    assert AdapterOutcome.of(signals_of({R}, 1)).signalled == (E.REFUSED, E.CRASHED)


def test_an_outcome_cannot_be_filed_under_another_state() -> None:
    with pytest.raises(ValidationError, match="end_state"):
        AdapterOutcome(end_state=E.COMPLETED, signals=signals_of({F}, 0))


@pytest.mark.parametrize(
    "changes", [{"exit_code": "0"}, {"exit_code": 0.0}, {"exit_code": True}, {"refused": "yes"}]
)
def test_exit_signals_are_strictly_typed(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ExitSignals(**{"exit_code": 0, **changes})


# --------------------------------------------------------------------------- the adapter


def test_the_adapter_contract_is_abstract() -> None:
    with pytest.raises(TypeError):
        Adapter()  # type: ignore[abstract]
    assert {"render", "start", "exit_signals", "collect", "teardown"} <= (
        Adapter.__abstractmethods__
    )


def test_an_adapter_describes_itself_with_its_sheet(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    adapter = fake_adapter()
    assert adapter.describe().framework == "fake"
    assert adapter.describe() is adapter.describe()


def test_an_adapter_without_a_sheet_cannot_be_built(tmp_path: Path) -> None:
    class Nameless(FakeAdapter):
        framework = "ghost"
        sheets_dir = tmp_path

    with pytest.raises(ValueError, match="cannot read"):
        Nameless()


def test_an_adapter_with_a_bad_sheet_cannot_be_built(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    with pytest.raises(ValidationError):
        fake_adapter(good_sheet(model_call_paths=[]))


@pytest.mark.parametrize(
    "changes",
    [
        {"model": ModelConfig(name="qwen3:32b", num_ctx=4096)},
        {"model": ModelConfig(name="qwen3:32b", num_ctx=None)},
    ],
)
def test_a_run_refuses_to_start_on_a_context_the_framework_cannot_use(
    fake_adapter: Callable[..., FakeAdapter], changes: dict[str, Any]
) -> None:
    adapter = fake_adapter()
    result = adapter.prepare(run_for(model()).model_copy(update=changes))
    assert isinstance(result, UnsupportedRun)
    assert result.end_state is AgentEndState.UNSUPPORTED
    assert adapter.rendered == []  # nothing was rendered, so nothing can start


@pytest.mark.parametrize(
    "sheet",
    [
        good_sheet(support_level="none", wire_formats=[], model_call_paths=[]),
        good_sheet(side_channels={"update_check": channel("unresolved", None)}),
        good_sheet(max_turns_knob="unknown"),
    ],
    ids=["no-support", "unresolved-channel", "unknown-turn-cap"],
)
def test_a_run_refuses_to_start_on_a_sheet_that_blocks_it(
    fake_adapter: Callable[..., FakeAdapter], sheet: dict[str, Any]
) -> None:
    adapter = fake_adapter(sheet)
    assert isinstance(adapter.prepare(run_for(model(131072))), UnsupportedRun)
    assert adapter.rendered == []


def test_a_run_with_enough_context_is_rendered_with_its_own_context(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    adapter = fake_adapter()
    launch = adapter.prepare(run_for(model(32768)))
    assert isinstance(launch, AgentLaunch)
    assert launch.env["FAKE_NUM_CTX"] == "32768"
    assert len(adapter.rendered) == 1


def test_a_capped_framework_must_record_its_cap(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    recorded = {"FAKE_MAX_MEMBERS": "5", "FAKE_MAX_CONCURRENT": "2"}
    adapter = fake_adapter(good_sheet(sub_agent_cap=CAP), recorded_settings=recorded)
    launch = adapter.prepare(run_for(model()))
    assert isinstance(launch, AgentLaunch)
    assert launch.recorded_settings == recorded


@pytest.mark.parametrize(
    "recorded",
    [
        {},
        {"FAKE_MAX_MEMBERS": "5"},
        {"FAKE_MAX_MEMBERS": "6", "FAKE_MAX_CONCURRENT": "3"},  # above the framework's cap
        {"FAKE_MAX_MEMBERS": "0", "FAKE_MAX_CONCURRENT": "3"},
        {"FAKE_MAX_MEMBERS": "-1", "FAKE_MAX_CONCURRENT": "3"},
        {"FAKE_MAX_MEMBERS": "five", "FAKE_MAX_CONCURRENT": "3"},
        {"FAKE_MAX_MEMBERS": "5", "FAKE_MAX_CONCURRENT": "³"},
    ],
)
def test_a_capped_framework_with_a_missing_or_wrong_cap_is_refused(
    fake_adapter: Callable[..., FakeAdapter], recorded: dict[str, str]
) -> None:
    adapter = fake_adapter(good_sheet(sub_agent_cap=CAP), recorded_settings=recorded)
    with pytest.raises(ValueError, match="record"):
        adapter.prepare(run_for(model()))


def test_wait_keeps_the_outcome_and_every_signal(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path
) -> None:
    adapter = fake_adapter(tool_format_failure=True, refused=True)
    outcome = adapter.wait(run_for(model()), ExitSignals(exit_code=0), tmp_path)
    assert outcome.end_state is AgentEndState.REFUSED
    assert outcome.signals.tool_format_failure


@pytest.mark.parametrize(
    "rewrite", [{"exit_code": 0}, {"timed_out": False}, {"exit_code": 1, "timed_out": False}]
)
def test_wait_refuses_an_adapter_that_rewrites_what_the_runner_saw(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path, rewrite: dict[str, Any]
) -> None:
    adapter = fake_adapter(**rewrite)
    with pytest.raises(ValueError, match="runner"):
        adapter.wait(run_for(model()), ExitSignals(exit_code=137, timed_out=True), tmp_path)


def test_a_fresh_adapter_tears_down_from_the_run_alone(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    run = run_for(model())
    first = fake_adapter()
    assert isinstance(first.prepare(run), AgentLaunch)
    first.start(run, RecordingHost())
    before = RecordingHost()
    first.teardown(run, before)

    # the runner restarts: only the stored run survives, and a new adapter is built
    stored = run.model_dump_json()
    after = RecordingHost()
    fake_adapter().teardown(AdapterRun.model_validate_json(stored), after)
    assert after.commands == before.commands == [("cellguard", ("reap", f"fake-{run.run_id}"))]


# --------------------------------------------------------------------------- agent ids


def test_agent_ids_default_to_none(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path
) -> None:
    assert fake_adapter().agent_ids(tmp_path) is None


def test_an_adapter_whose_sheet_names_an_id_source_must_read_it(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path
) -> None:
    sheet = good_sheet(agent_id_source="events.jsonl agent_id", agent_id_gap=None)
    with pytest.raises(TypeError, match="agent_ids"):
        fake_adapter(sheet)

    write_sheet(tmp_path, sheet)

    class Reading(FakeAdapter):
        sheets_dir = tmp_path

        def agent_ids(self, collected: Path) -> dict[int, str] | None:
            return {0: "root"}

    assert Reading().agent_ids(tmp_path) == {0: "root"}


def _calls(seqs: Sequence[int]) -> list[Any]:
    return [unparsed_call(seq, None, "fixture") for seq in seqs]


def test_agent_ids_that_cover_every_call_are_taken_by_telemetry() -> None:
    run = summarise(new_id("run"), _calls([0, 1, 2]), {0: "root", 1: "child-1", 2: "root"})
    assert run.agents_source == "adapter"


@pytest.mark.parametrize(
    "ids",
    [
        {0: "root", 1: "child-1"},  # misses a call
        {0: "root", 1: "child-1", 2: "root", 3: "ghost"},  # names a call that never happened
        {0: "root", 1: "", 2: "root"},  # an empty agent id
        {},  # an empty map is not "no ids": use None
    ],
)
def test_agent_ids_that_do_not_cover_exactly_every_call_are_refused(ids: dict[int, str]) -> None:
    with pytest.raises(ValueError, match="agent ids"):
        summarise(new_id("run"), _calls([0, 1, 2]), ids)


def test_no_agent_ids_means_telemetry_infers_them() -> None:
    assert summarise(new_id("run"), _calls([0, 1]), None).agents_source == "inferred"


# --------------------------------------------------------------------------- launch and run


@pytest.mark.parametrize(
    "changes",
    [
        {"image": ""},
        {"command": ()},
        {"command": ("",)},
        {"env": {"1BAD": "x"}},
        {"env": {"BAD-NAME": "x"}},
        {"env": {"": "x"}},
        {"files": {"../escape": b"x"}},
        {"files": {"a/b": b"x"}},
        {"files": {"..": b"x"}},
        {"files": {"": b"x"}},
        {"recorded_settings": {"": "5"}},
        {"recorded_settings": {"FAKE_MAX_MEMBERS": 5}},
    ],
)
def test_a_launch_refuses_malformed_parts(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        AgentLaunch(**{"image": "lab-agent-fake", "command": ("fake",), **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"run_id": "../run"},
        {"run_id": ""},
        {"target_url": "ftp://goat"},
        {"llm_base_url": "tap:8080"},
        {"objective": ""},
        {"limits": {"max_turns": 0, "timeout_s": 60}},
        {"limits": {"max_turns": 10, "timeout_s": 0}},
        {"limits": {"max_turns": True, "timeout_s": 60}},
        {"limits": {"max_turns": 10, "timeout_s": 10**9}},
        {"limits": {"max_turns": 10, "timeout_s": 60, "budget_usd": 1.0}},
    ],
)
def test_an_adapter_run_refuses_malformed_parts(changes: dict[str, Any]) -> None:
    good = run_for(model()).model_dump()
    with pytest.raises(ValidationError):
        AdapterRun.model_validate({**good, **changes})


def test_channel_status_values() -> None:
    assert {s.value for s in ChannelStatus} == {"disabled", "unresolved"}
