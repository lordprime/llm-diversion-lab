"""The adapter base: capability sheets, the context check, end states and the ABC."""

from __future__ import annotations

import itertools
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml
from pydantic import ValidationError

from agents.base import (
    MAX_NUM_CTX,
    MAX_SHEET_BYTES,
    SHEETS_DIR,
    Adapter,
    AdapterRun,
    AgentEndState,
    AgentHost,
    AgentLaunch,
    CapabilitySheet,
    EndStateMapper,
    ExitSignals,
    ModelConfig,
    SupportLevel,
    UnsupportedRun,
)
from control.core.ids import new_id
from control.core.models import AgentEvent, EndStatus
from control.runner.experiment import RunLimits
from control.telemetry.extract import summarise
from control.telemetry.wire import unparsed_call

# --------------------------------------------------------------------------- helpers


def good_sheet(**changes: Any) -> dict[str, Any]:
    """A valid sheet document; ``changes`` replace (or, with ``None``, remove) keys."""
    doc: dict[str, Any] = {
        "framework": "fake",
        "version": "v1.0.0",
        "commit": "abc1234",
        "image_digest": "unknown",
        "support_level": "native",
        "wire_formats": ["ollama_chat"],
        "model_call_paths": ["main agent (fake/agent.py)"],
        "side_channels_disabled": {"telemetry": "FAKE_TELEMETRY=false"},
        "min_num_ctx": 16384,
        "sub_agents": "dynamic",
        "agent_id_source": None,
        "agent_id_gap": "unknown: no log of child ids was read",
        "patches": [],
        "max_turns_knob": "unknown",
        "audit_refs": {
            "version": "§2.2",
            "support_level": "§2.2",
            "wire_formats": "§1",
            "model_call_paths": "§2.2",
            "side_channels_disabled": "§2.2, §3",
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


_DROP = object()


def write_sheet(directory: Path, doc: object, name: str = "fake") -> Path:
    path = directory / f"{name}.yaml"
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def model(num_ctx: int | None = 32768) -> ModelConfig:
    return ModelConfig(name="qwen3:32b", num_ctx=num_ctx)


def run_for(cfg: ModelConfig) -> AdapterRun:
    return AdapterRun(
        run_id=new_id("run"),
        model=cfg,
        target_url="http://goat:8000",
        objective="find the flag",
        llm_base_url="http://tap:8080",
        limits=RunLimits(budget_usd=0.0, max_turns=50, timeout_s=3600),
    )


class FakeAdapter(Adapter):
    """A minimal adapter whose framework-specific steps record what they were given."""

    framework: ClassVar[str] = "fake"
    sheets_dir: ClassVar[Path]
    signals_update: ClassVar[dict[str, Any]] = {}

    def __init__(self) -> None:
        super().__init__()
        self.rendered: list[AdapterRun] = []

    def render(self, run: AdapterRun) -> AgentLaunch:
        self.rendered.append(run)
        return AgentLaunch(
            image="lab-agent-fake",
            command=("fake", "--headless"),
            env={"FAKE_MODEL": run.model.name, "FAKE_NUM_CTX": str(run.model.num_ctx)},
        )

    def start(self, host: AgentHost) -> None:
        return None

    def exit_signals(self, observed: ExitSignals, evidence: Path) -> ExitSignals:
        return observed.model_copy(update=self.signals_update)

    def collect(self, evidence: Path) -> list[AgentEvent]:
        return []

    def teardown(self, host: AgentHost) -> None:
        return None


@pytest.fixture
def fake_adapter(tmp_path: Path) -> Callable[..., FakeAdapter]:
    def make(sheet: dict[str, Any] | None = None, **signals: Any) -> FakeAdapter:
        write_sheet(tmp_path, sheet if sheet is not None else good_sheet())

        class Adapted(FakeAdapter):
            sheets_dir = tmp_path
            signals_update = signals

        return Adapted()

    return make


# --------------------------------------------------------------------------- the sheet


def test_a_good_sheet_validates() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet())
    assert sheet.support_level is SupportLevel.NATIVE
    assert sheet.min_num_ctx == 16384
    assert sheet.model_call_paths == ("main agent (fake/agent.py)",)


@pytest.mark.parametrize("level", ["native", "openai_compatible", "unofficial"])
def test_a_runnable_sheet_must_list_its_model_call_paths(level: str) -> None:
    with pytest.raises(ValidationError, match="model_call_paths"):
        CapabilitySheet.model_validate(good_sheet(support_level=level, model_call_paths=[]))


@pytest.mark.parametrize("level", ["native", "openai_compatible", "unofficial"])
def test_a_runnable_sheet_must_name_a_wire_format(level: str) -> None:
    with pytest.raises(ValidationError, match="wire_formats"):
        CapabilitySheet.model_validate(good_sheet(support_level=level, wire_formats=[]))


def test_a_sheet_with_no_support_may_list_nothing() -> None:
    sheet = CapabilitySheet.model_validate(
        good_sheet(support_level="none", wire_formats=[], model_call_paths=[])
    )
    assert sheet.support_level is SupportLevel.NONE


@pytest.mark.parametrize("setting", ["", "   ", "\t", "unknown", "UNKNOWN", " Unknown "])
def test_a_side_channel_needs_a_disabling_setting(setting: str) -> None:
    with pytest.raises(ValidationError, match="side_channels_disabled"):
        CapabilitySheet.model_validate(good_sheet(side_channels_disabled={"web_search": setting}))


@pytest.mark.parametrize("channel", ["", "  ", "two\nlines"])
def test_a_side_channel_needs_a_name(channel: str) -> None:
    with pytest.raises(ValidationError):
        CapabilitySheet.model_validate(good_sheet(side_channels_disabled={channel: "X=0"}))


@pytest.mark.parametrize("setting", [None, 0, False, ["X=0"]])
def test_a_side_channel_setting_must_be_text(setting: object) -> None:
    with pytest.raises(ValidationError):
        CapabilitySheet.model_validate(good_sheet(side_channels_disabled={"telemetry": setting}))


@pytest.mark.parametrize(
    "value",
    [0, -1, -16384, True, False, 1.5, 16384.0, "16384", "16k", "", None, MAX_NUM_CTX + 1, 10**12],
)
def test_min_num_ctx_is_a_sane_positive_integer_or_unknown(value: object) -> None:
    with pytest.raises(ValidationError, match="min_num_ctx"):
        CapabilitySheet.model_validate(good_sheet(min_num_ctx=value))


def test_min_num_ctx_may_be_unknown() -> None:
    assert CapabilitySheet.model_validate(good_sheet(min_num_ctx="unknown")).min_num_ctx == (
        "unknown"
    )


@pytest.mark.parametrize(
    ("field", "value"),
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
def test_malformed_fields_are_refused(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        CapabilitySheet.model_validate(good_sheet(**{field: value}))


@pytest.mark.parametrize(
    "field",
    ["framework", "commit", "support_level", "model_call_paths", "min_num_ctx", "audit_refs"],
)
def test_a_missing_field_is_refused(field: str) -> None:
    with pytest.raises(ValidationError, match=field):
        CapabilitySheet.model_validate(good_sheet(**{field: _DROP}))


def test_an_unknown_field_is_refused() -> None:
    with pytest.raises(ValidationError, match="extra"):
        CapabilitySheet.model_validate(good_sheet(base_url="http://ollama:11434"))


def test_a_sheet_is_frozen() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet())
    with pytest.raises(ValidationError):
        sheet.min_num_ctx = 1  # type: ignore[misc]


def test_a_real_image_digest_is_accepted() -> None:
    digest = "sha256:" + "a" * 64
    assert CapabilitySheet.model_validate(good_sheet(image_digest=digest)).image_digest == digest


def test_agent_ids_need_a_source_or_a_reason_when_there_are_sub_agents() -> None:
    with pytest.raises(ValidationError, match="agent_id"):
        CapabilitySheet.model_validate(good_sheet(agent_id_source=None, agent_id_gap=None))
    with pytest.raises(ValidationError, match="agent_id"):
        CapabilitySheet.model_validate(
            good_sheet(agent_id_source="events.jsonl agent_id", agent_id_gap="no reason")
        )
    sheet = CapabilitySheet.model_validate(
        good_sheet(agent_id_source="events.jsonl agent_id", agent_id_gap=None)
    )
    assert sheet.agent_id_source == "events.jsonl agent_id"


def test_a_single_agent_framework_names_no_agent_id_source() -> None:
    single = CapabilitySheet.model_validate(
        good_sheet(sub_agents="none", agent_id_source=None, agent_id_gap=None)
    )
    assert single.sub_agents == "none"
    with pytest.raises(ValidationError, match="agent_id"):
        CapabilitySheet.model_validate(
            good_sheet(sub_agents="none", agent_id_source="log", agent_id_gap=None)
        )


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
    ],
)
def test_every_audited_field_cites_an_audit_section(refs: dict[str, str]) -> None:
    with pytest.raises(ValidationError, match="audit_refs"):
        CapabilitySheet.model_validate(good_sheet(audit_refs=refs))


# --------------------------------------------------------------------------- loading


def test_load_reads_a_sheet_from_yaml(tmp_path: Path) -> None:
    sheet = CapabilitySheet.load(write_sheet(tmp_path, good_sheet()))
    assert sheet.framework == "fake"


def test_load_refuses_a_sheet_named_after_another_framework(tmp_path: Path) -> None:
    path = write_sheet(tmp_path, good_sheet(), name="strix")
    with pytest.raises(ValueError, match="strix"):
        CapabilitySheet.load(path)


def test_load_refuses_duplicate_keys(tmp_path: Path) -> None:
    path = tmp_path / "fake.yaml"
    text = yaml.safe_dump(good_sheet(), sort_keys=False)
    path.write_text(text + "min_num_ctx: 1024\n", encoding="utf-8")
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


# --------------------------------------------------------------------------- context check


def test_a_context_below_the_minimum_is_unsupported_with_a_reason() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet(min_num_ctx=16384))
    verdict = sheet.check_context(model(8192))
    assert isinstance(verdict, UnsupportedRun)
    assert verdict.end_state is AgentEndState.UNSUPPORTED
    assert "8192" in verdict.reason
    assert "16384" in verdict.reason
    assert "fake" in verdict.reason


@pytest.mark.parametrize("num_ctx", [16384, 16385, 131072, MAX_NUM_CTX])
def test_a_context_at_or_above_the_minimum_is_fine(num_ctx: int) -> None:
    sheet = CapabilitySheet.model_validate(good_sheet(min_num_ctx=16384))
    assert sheet.check_context(model(num_ctx)) is None


def test_an_unpinned_context_is_unsupported() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet(min_num_ctx=16384))
    verdict = sheet.check_context(model(None))
    assert isinstance(verdict, UnsupportedRun)
    assert "not pinned" in verdict.reason


def test_an_unpinned_context_is_unsupported_even_without_a_known_minimum() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet(min_num_ctx="unknown"))
    assert isinstance(sheet.check_context(model(None)), UnsupportedRun)


def test_an_unknown_minimum_accepts_any_pinned_context() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet(min_num_ctx="unknown"))
    assert sheet.check_context(model(1)) is None


def test_the_context_check_never_shrinks_or_changes_the_model() -> None:
    sheet = CapabilitySheet.model_validate(good_sheet(min_num_ctx=16384))
    cfg = model(8192)
    sheet.check_context(cfg)
    assert cfg.num_ctx == 8192
    with pytest.raises(ValidationError):
        cfg.num_ctx = 16384  # type: ignore[misc]


def test_a_framework_without_support_is_never_runnable() -> None:
    sheet = CapabilitySheet.model_validate(
        good_sheet(support_level="none", wire_formats=[], model_call_paths=[])
    )
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
    "state",
    [s for s in AgentEndState if s not in EndStateMapper.PENDING_IN_END_STATUS],
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


@pytest.mark.parametrize(
    ("signals", "expected"),
    [
        (ExitSignals(exit_code=0), AgentEndState.COMPLETED),
        (ExitSignals(exit_code=1), AgentEndState.CRASHED),
        (ExitSignals(exit_code=137), AgentEndState.CRASHED),
        (ExitSignals(exit_code=-9), AgentEndState.CRASHED),
        (ExitSignals(exit_code=None, timed_out=True), AgentEndState.TIMEOUT),
        (ExitSignals(exit_code=137, timed_out=True), AgentEndState.TIMEOUT),
        (ExitSignals(exit_code=0, budget_exhausted=True), AgentEndState.BUDGET_EXHAUSTED),
        (ExitSignals(exit_code=0, refused=True), AgentEndState.REFUSED),
        (ExitSignals(exit_code=0, tool_format_failure=True), AgentEndState.TOOL_FORMAT_FAILURE),
        (ExitSignals(exit_code=1, tool_format_failure=True), AgentEndState.TOOL_FORMAT_FAILURE),
    ],
)
def test_the_end_state_table(signals: ExitSignals, expected: AgentEndState) -> None:
    assert EndStateMapper.classify(signals) is expected


@pytest.mark.parametrize(
    "flags",
    list(itertools.product([False, True], repeat=4)),
    ids=lambda f: "".join("01"[x] for x in f),
)
@pytest.mark.parametrize("exit_code", [0, 1, None])
def test_the_precedence_covers_every_combination(
    flags: tuple[bool, bool, bool, bool], exit_code: int | None
) -> None:
    budget, timed_out, refused, tool_format = flags
    if exit_code is None and not timed_out:
        pytest.skip("an agent that never exited was killed at the timeout")
    signals = ExitSignals(
        exit_code=exit_code,
        timed_out=timed_out,
        budget_exhausted=budget,
        refused=refused,
        tool_format_failure=tool_format,
    )
    state = EndStateMapper.classify(signals)
    expected = next(
        s
        for flag, s in (
            (budget, AgentEndState.BUDGET_EXHAUSTED),
            (timed_out, AgentEndState.TIMEOUT),
            (refused, AgentEndState.REFUSED),
            (tool_format, AgentEndState.TOOL_FORMAT_FAILURE),
            (exit_code != 0, AgentEndState.CRASHED),
            (True, AgentEndState.COMPLETED),
        )
        if flag
    )
    assert state is expected
    # a run whose tool calls did not parse is never a completion
    if tool_format:
        assert state is not AgentEndState.COMPLETED
    assert state is not AgentEndState.UNSUPPORTED


def test_an_agent_that_never_exited_must_have_timed_out() -> None:
    with pytest.raises(ValidationError, match="timed_out"):
        ExitSignals(exit_code=None)


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
    assert {
        "render",
        "start",
        "exit_signals",
        "collect",
        "teardown",
    } <= Adapter.__abstractmethods__


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


def test_a_run_refuses_to_start_below_the_minimum_context(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    adapter = fake_adapter()
    result = adapter.prepare(run_for(model(4096)))
    assert isinstance(result, UnsupportedRun)
    assert result.end_state is AgentEndState.UNSUPPORTED
    assert adapter.rendered == []  # nothing was rendered, so nothing can start


def test_a_run_refuses_to_start_without_a_pinned_context(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    adapter = fake_adapter()
    assert isinstance(adapter.prepare(run_for(model(None))), UnsupportedRun)
    assert adapter.rendered == []


def test_a_run_refuses_to_start_on_an_unsupported_framework(
    fake_adapter: Callable[..., FakeAdapter],
) -> None:
    adapter = fake_adapter(good_sheet(support_level="none", wire_formats=[], model_call_paths=[]))
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


def test_wait_classifies_what_the_adapter_reports(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path
) -> None:
    adapter = fake_adapter(tool_format_failure=True)
    assert adapter.wait(ExitSignals(exit_code=0), tmp_path) is AgentEndState.TOOL_FORMAT_FAILURE


@pytest.mark.parametrize(
    "rewrite", [{"exit_code": 0}, {"timed_out": False}, {"exit_code": 1, "timed_out": False}]
)
def test_wait_refuses_an_adapter_that_rewrites_what_the_runner_saw(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path, rewrite: dict[str, Any]
) -> None:
    adapter = fake_adapter(**rewrite)
    with pytest.raises(ValueError, match="runner"):
        adapter.wait(ExitSignals(exit_code=137, timed_out=True), tmp_path)


# --------------------------------------------------------------------------- agent ids


def test_agent_ids_default_to_none_when_the_sheet_names_no_source(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path
) -> None:
    assert fake_adapter().agent_ids(tmp_path) is None


def test_agent_ids_must_be_implemented_when_the_sheet_names_a_source(
    fake_adapter: Callable[..., FakeAdapter], tmp_path: Path
) -> None:
    adapter = fake_adapter(good_sheet(agent_id_source="events.jsonl agent_id", agent_id_gap=None))
    with pytest.raises(NotImplementedError, match="agent_id_source"):
        adapter.agent_ids(tmp_path)


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
    ],
)
def test_an_adapter_run_refuses_malformed_parts(changes: dict[str, Any]) -> None:
    good = run_for(model()).model_dump()
    with pytest.raises(ValidationError):
        AdapterRun.model_validate({**good, **changes})
