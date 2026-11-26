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

DOCS = Path(__file__).resolve().parents[2] / "docs"
AUDIT = DOCS / "OLLAMA_SUPPORT_AUDIT.md"
FEASIBILITY = DOCS / "AUTOMATION_FEASIBILITY.md"
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
        "litellm_cost_map": None,
    },
    "pentagi": {
        "openai_embeddings": "EMBEDDING_PROVIDER=ollama",
        "graphiti": None,
        "search_engines": None,
        "scraper": None,
        "oauth": None,
        "langfuse_otel": None,
        "update_reporter": None,
        "image_selection": None,
    },
    "redamon": {
        "ai_attack_surface_judge": (
            "the recon-orchestrator service is never started (the driver starts postgres, "
            "neo4j, kali, agent and webapp only)"
        ),
        "kb_embeddings": "KB_EMBEDDING_API_BASE_URL unset",
        "keyed_provider_model_listing": "no OpenAI or Anthropic provider key configured",
        "hosted_default_models": (
            "agentOpenaiModel=custom/<providerId> and no model by feature set"
        ),
        "settings_fallback_default_model": (
            "patches 0001 and 0002: a failed settings or provider fetch ends the run "
            "(error code settings_unavailable)"
        ),
        "out_of_run_default_model": "patch 0003, and targetGuardrailEnabled=false",
        "agent_in_the_loop": "AGENT_IN_THE_LOOP_ENABLED=false",
        "msf_update": "MSF_AUTO_UPDATE=false",
        "nuclei_template_update": "NUCLEI_AUTO_UPDATE=false",
        "hardcoded_dns": (
            "upstream docker-compose.yml is not used; cell-guard forces HostConfig.Dns to "
            "the cell resolver"
        ),
        "internet_only_tools": (
            "agentToolPhaseMap maps web_search, cve_intel, shodan, google_dork, "
            "execute_subfinder, execute_amass, execute_gau, tradecraft_lookup and "
            "execute_guarddog to no phase"
        ),
        "tunnels": (
            "TUNNEL_AUTH_TOKEN unset, agentNgrokTunnelEnabled=false and "
            "agentChiselTunnelEnabled=false"
        ),
        "webapp_telemetry": "NEXT_TELEMETRY_DISABLED=1 and CHECKPOINT_DISABLE=1",
        "webapp_version_check": "the webapp UI is never opened; only the driver calls the webapp",
        "webapp_plugin_catalog": "PLUGINS_CATALOG_URL=http://127.0.0.1:9/catalog.json",
        "webapp_api_usage_check": "API_USAGE_CHECK_ENABLED=false",
        "workspace_url_import": "WORKSPACE_URL_IMPORT_ENABLED=false",
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
        "litellm_cost_map": None,
    },
}


def sections(doc: Path) -> set[str]:
    """Section numbers of a doc's headings: ``## 3.`` gives 3, ``### 2.5`` gives 2.5."""
    found: set[str] = set()
    for line in doc.read_text(encoding="utf-8").splitlines():
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
    known = sections(AUDIT)
    assert {"1", "2.1", "2.5", "3", "4"} <= known  # the parser reads the real headings
    sheet = sheets[name]
    refs = dict(sheet.audit_refs)
    refs |= {
        f"side_channels.{n}": c.audit_ref
        for n, c in sheet.side_channels.items()
        if c.audit_ref is not None
    }
    if sheet.sub_agent_cap is not None:
        refs["sub_agent_cap"] = sheet.sub_agent_cap.audit_ref
    for where, ref in refs.items():
        for section in re.findall(r"§(\d+(?:\.\d+)*)", ref):
            assert section in known, f"{name}.{where} cites §{section}, not in the audit"


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_every_feasibility_citation_exists(sheets: dict[str, CapabilitySheet], name: str) -> None:
    known = sections(FEASIBILITY)
    assert {"2.2", "2.5", "3", "6.4"} <= known
    for channel_name, channel in sheets[name].side_channels.items():
        cited = channel.feasibility_ref or ""
        for section in re.findall(r"§(\d+(?:\.\d+)*)", cited):
            assert section in known, f"{name}.{channel_name} cites feasibility §{section}"


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_a_candidate_switch_stays_unresolved_until_verified(
    sheets: dict[str, CapabilitySheet], name: str
) -> None:
    # A switch AUTOMATION_FEASIBILITY names is only a candidate: the adapter task checks it
    # at the pinned commit before the channel may become disabled.
    for channel_name, channel in sheets[name].side_channels.items():
        if channel.note is not None and "candidate:" in channel.note:
            assert channel.status is ChannelStatus.UNRESOLVED, channel_name
            assert "AUTOMATION_FEASIBILITY §" in channel.note, channel_name
            assert channel.note.endswith("unverified at the audited commit"), channel_name
        if channel.audit_ref is None:  # found only by the feasibility study
            assert channel.feasibility_ref is not None, channel_name
            # It may be disabled only once the adapter task read the switch in the
            # source at the pinned commit, and says so.
            if channel.status is ChannelStatus.DISABLED:
                assert channel.note is not None, channel_name
                assert (
                    f"verified at {sheets[name].commit}" in channel.note
                    or "found by the adapter task" in channel.note
                ), channel_name
            else:
                assert channel.status is ChannelStatus.UNRESOLVED, channel_name


#: The candidate switch each unresolved channel's note must name (N4).
CANDIDATES = {
    ("strix", "update_check"): "STRIX_NO_UPDATE_CHECK=1",
    ("strix", "litellm_cost_map"): "LITELLM_LOCAL_MODEL_COST_MAP=True",
    ("hackingbuddygpt", "litellm_cost_map"): "LITELLM_LOCAL_MODEL_COST_MAP=True",
    ("pentagi", "graphiti"): "GRAPHITI_ENABLED=false",
    ("pentagi", "search_engines"): "DUCKDUCKGO_ENABLED=false",
    ("pentagi", "langfuse_otel"): "no LANGFUSE_* and no OTEL_HOST",
    ("pentagi", "update_reporter"): "UPDATE_CHECK_INTERVAL=0",
    ("pentagi", "image_selection"): "DOCKER_IMAGE_SELECTION_MODE=fixed",
    ("pentestgpt", "webfetch_anthropic_hosts"): "disallowed_tools=[WebSearch, WebFetch]",
    ("pentestgpt", "hosted_web_search"): "disallowed_tools=[WebSearch, WebFetch]",
}


@pytest.mark.parametrize(("name", "channel_name"), sorted(CANDIDATES))
def test_the_feasibility_candidates_are_named(
    sheets: dict[str, CapabilitySheet], name: str, channel_name: str
) -> None:
    note = sheets[name].side_channels[channel_name].note
    assert note is not None
    assert f"candidate: {CANDIDATES[name, channel_name]}" in note


def test_webfetch_notes_that_its_preflight_bypasses_the_tap(
    sheets: dict[str, CapabilitySheet],
) -> None:
    channel = sheets["pentestgpt"].side_channels["webfetch_anthropic_hosts"]
    assert channel.audit_ref == "§4"
    assert channel.note is not None
    assert "§1 says its domain preflight goes straight to api.anthropic.com" in channel.note
    assert "§2.4 that the preflight bypasses ANTHROPIC_BASE_URL" in channel.note


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


#: Sheets whose adapter task resolved every side channel and the turn cap.
RESOLVED = frozenset({"redamon"})


@pytest.mark.parametrize("name", FRAMEWORKS)
def test_no_framework_can_run_until_its_open_items_are_resolved(
    sheets: dict[str, CapabilitySheet], name: str
) -> None:
    # A sheet with an unresolved side channel or an unknown turn cap refuses every run,
    # whatever the model; a resolved one accepts a model with a pinned context.
    verdict = sheets[name].check_runnable(ModelConfig(name="qwen3:32b", num_ctx=131072))
    if name in RESOLVED:
        assert verdict is None
        assert sheets[name].unresolved_side_channels == ()
    else:
        assert isinstance(verdict, UnsupportedRun)


def test_the_recorded_patches(sheets: dict[str, CapabilitySheet]) -> None:
    # Only what the sheets record: the audit settles hackingBuddyGPT's api_base patch.
    # Patches AUTOMATION_FEASIBILITY proposes are for the adapter tasks to confirm, so
    # this test does not claim the other frameworks need none.
    patches = {p.upstream_file: p for p in sheets["hackingbuddygpt"].patches}
    patch = patches["src/hackingBuddyGPT/utils/llm.py"]
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


def test_redamon_reads_agent_ids_from_its_request_tag(
    sheets: dict[str, CapabilitySheet],
) -> None:
    # The adapter task added the tag (patch 0002) and reads it back (agent_ids()).
    sheet = sheets["redamon"]
    assert sheet.agent_id_source is not None
    assert "user field" in sheet.agent_id_source
    assert sheet.agent_id_gap is None
    assert any("patch 0002" in p.change for p in sheet.patches)


@pytest.mark.parametrize(
    "name", [n for n in FRAMEWORKS if n not in {"hackingbuddygpt", "redamon"}]
)
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
