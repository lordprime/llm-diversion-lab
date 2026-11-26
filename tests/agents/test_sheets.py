"""The five shipped capability sheets, checked against the Ollama support audit.

Each value in a sheet must be traceable to docs/OLLAMA_SUPPORT_AUDIT.md: every cited
section must exist there, and the facts the campaign depends on (support level, wire
format, minimum context, every side channel and its exact setting) are pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agents.base import (
    SHEETS_DIR,
    CapabilitySheet,
    ChannelStatus,
    ModelConfig,
    SubAgentCap,
    SupportLevel,
    UnsupportedRun,
)
from control.telemetry.model import WireFormat

AUDIT = Path(__file__).resolve().parents[2] / "docs" / "OLLAMA_SUPPORT_AUDIT.md"
FRAMEWORKS = ("hackingbuddygpt", "pentagi", "pentestgpt", "redamon", "strix")

#: Every side channel of every sheet: its exact setting, or None while it is unresolved.
SIDE_CHANNELS: dict[str, dict[str, str | None]] = {
    "strix": {
        "web_search_perplexity": "PERPLEXITY_API_KEY unset",
        "web_search_exa": "EXA_API_KEY unset",
        "telemetry": "STRIX_TELEMETRY=false",
        "context_images": "STRIX_MAX_CONTEXT_IMAGES=0",
        "codex_endpoint": "STRIX_LLM=ollama/<model>",
        "dedupe_endpoint": "STRIX_DEDUPE_MODEL and DEDUPE_LLM_API_BASE unset",
        "update_check": None,
    },
    "pentagi": {
        "openai_embeddings": "EMBEDDING_PROVIDER=ollama",
        "graphiti": None,
        "search_engines": None,
        "scraper": None,
        "oauth": None,
        "langfuse_otel": None,
    },
    "redamon": {
        "ai_attack_surface_judge": None,
        "kb_embeddings": "KB_EMBEDDING_API_BASE_URL unset",
        "keyed_provider_model_listing": "no OpenAI or Anthropic provider key configured",
        "hosted_default_models": (
            "agent model and every model by feature set to custom/<providerId>"
        ),
    },
    "pentestgpt": {
        "hosted_anthropic_api": "ANTHROPIC_BASE_URL=<tap>",
        "nonessential_traffic": "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
        "codex_backend": "--backend claude",
        "ccr_local_mode": "PENTESTGPT_AUTH_MODE is never local",
        "webfetch_anthropic_hosts": None,
        "hosted_web_search": None,
    },
    "hackingbuddygpt": {
        "rag_openai_embeddings": "rag_path unset",
        "openrouter_default_api_base": "llm.api_base=<tap> and OLLAMA_API_BASE=<tap>",
    },
}


def audit_sections() -> set[str]:
    """Section numbers of the audit's headings: ``## 3.`` gives 3, ``### 2.5`` gives 2.5."""
    found: set[str] = set()
    for line in AUDIT.read_text(encoding="utf-8").splitlines():
        match = re.match(r"^#{2,3} (\d+(?:\.\d+)*)\.? ", line)
        if match:
            found.add(match.group(1))
    return found


@pytest.fixture(scope="module")
def sheets() -> dict[str, CapabilitySheet]:
    return {name: CapabilitySheet.for_framework(name) for name in FRAMEWORKS}


def test_there_is_one_sheet_per_framework() -> None:
    assert sorted(p.stem for p in SHEETS_DIR.glob("*.yaml")) == list(FRAMEWORKS)


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_cited_section_exists_in_the_audit(
    sheets: dict[str, CapabilitySheet], name: str
) -> None:
    known = audit_sections()
    assert {"1", "2.1", "2.5", "3", "4"} <= known  # the parser reads the real headings
    sheet = sheets[name]
    refs = dict(sheet.audit_refs)
    refs |= {f"side_channels.{n}": c.audit_ref for n, c in sheet.side_channels.items()}
    if sheet.sub_agent_cap is not None:
        refs["sub_agent_cap"] = sheet.sub_agent_cap.audit_ref
    for where, ref in refs.items():
        for section in re.findall(r"§(\d+(?:\.\d+)*)", ref):
            assert section in known, f"{name}.{where} cites §{section}, not in the audit"


@pytest.mark.parametrize(
    ("name", "commit", "level", "wire", "min_ctx"),
    [
        ("hackingbuddygpt", "e23d918", "native", WireFormat.OLLAMA_CHAT, "unknown"),
        ("strix", "685bbc8", "native", WireFormat.OLLAMA_CHAT, 16384),
        ("redamon", "73ca9d3", "native", WireFormat.OPENAI_CHAT, "unknown"),
        ("pentestgpt", "e8b1bb7", "unofficial", WireFormat.ANTHROPIC_MESSAGES, 65536),
        ("pentagi", "b611fbe", "native", WireFormat.OLLAMA_CHAT, 110000),
    ],
)
def test_the_audited_facts(
    sheets: dict[str, CapabilitySheet],
    name: str,
    commit: str,
    level: str,
    wire: WireFormat,
    min_ctx: int | str,
) -> None:
    sheet = sheets[name]
    assert sheet.commit == commit
    assert sheet.support_level is SupportLevel(level)
    assert sheet.wire_formats == (wire,)
    assert sheet.min_num_ctx == min_ctx
    # nothing has been built yet: no sheet may claim an image digest it never saw
    assert sheet.image_digest == "unknown"
    assert sheet.model_call_paths


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_side_channel_and_its_exact_setting(
    sheets: dict[str, CapabilitySheet], name: str
) -> None:
    found = {
        channel_name: (channel.status, channel.setting)
        for channel_name, channel in sheets[name].side_channels.items()
    }
    expected = {
        channel_name: (
            ChannelStatus.UNRESOLVED if setting is None else ChannelStatus.DISABLED,
            setting,
        )
        for channel_name, setting in SIDE_CHANNELS[name].items()
    }
    assert found == expected


@pytest.mark.parametrize(
    ("name", "knob"),
    [
        ("strix", "unknown"),
        ("pentagi", "unknown"),
        ("redamon", "MAX_ITERATIONS"),
        ("pentestgpt", "unknown"),
        ("hackingbuddygpt", "unknown"),
    ],
)
def test_the_turn_cap_settings(sheets: dict[str, CapabilitySheet], name: str, knob: str) -> None:
    assert sheets[name].max_turns_knob == knob


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_no_framework_can_run_until_its_open_items_are_resolved(
    sheets: dict[str, CapabilitySheet], name: str
) -> None:
    # Every sheet still has an unresolved side channel or an unknown turn cap, so the
    # adapter tasks must resolve them before any run starts, whatever the model.
    verdict = sheets[name].check_runnable(ModelConfig(name="qwen3:32b", num_ctx=131072))
    assert isinstance(verdict, UnsupportedRun)


def test_only_hackingbuddygpt_needs_a_patch(sheets: dict[str, CapabilitySheet]) -> None:
    patched = {name for name, sheet in sheets.items() if sheet.patches}
    assert patched == {"hackingbuddygpt"}
    (patch,) = sheets["hackingbuddygpt"].patches
    assert patch.upstream_file == "src/hackingBuddyGPT/utils/llm.py"
    assert "api_base=self.api_base" in patch.change


def test_hackingbuddygpt_runs_one_single_agent_use_case(
    sheets: dict[str, CapabilitySheet],
) -> None:
    sheet = sheets["hackingbuddygpt"]
    assert sheet.use_case is not None
    assert "WebTestingAgent" in sheet.use_case
    assert sheet.sub_agents == "none"
    assert sheet.agent_id_source is None
    assert sheet.agent_id_gap is None
    assert sheet.model_call_paths == (
        "main agent: LiteLLM.raw_completion calling litellm.completion "
        "(src/hackingBuddyGPT/utils/llm.py)",
    )


def test_redamon_caps_its_fireteam(sheets: dict[str, CapabilitySheet]) -> None:
    assert sheets["redamon"].sub_agent_cap == SubAgentCap(
        max_agents=5,
        max_concurrent=5,
        max_agents_setting="FIRETEAM_MAX_MEMBERS",
        max_concurrent_setting="FIRETEAM_MAX_CONCURRENT",
        audit_ref="§2.3, §3",
    )
    assert all(s.sub_agent_cap is None for n, s in sheets.items() if n != "redamon")


def test_the_unofficial_route_is_labelled(sheets: dict[str, CapabilitySheet]) -> None:
    unofficial = {n for n, s in sheets.items() if s.support_level is SupportLevel.UNOFFICIAL}
    assert unofficial == {"pentestgpt"}


@pytest.mark.parametrize("name", [n for n in FRAMEWORKS if n != "hackingbuddygpt"])
def test_no_sheet_claims_agent_ids_the_audit_never_saw(
    sheets: dict[str, CapabilitySheet], name: str
) -> None:
    # The audit read no framework log for sub-agent ids; each adapter task sets the source
    # once it has a recorded log fixture. Until then the sheet says why ids are missing.
    sheet = sheets[name]
    assert sheet.sub_agents == "dynamic"
    assert sheet.agent_id_source is None
    assert sheet.agent_id_gap is not None
    assert sheet.agent_id_gap.startswith("unknown")
