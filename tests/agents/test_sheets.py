"""The five shipped capability sheets, checked against the Ollama support audit.

Each value in a sheet must be traceable to docs/OLLAMA_SUPPORT_AUDIT.md: every cited
section must exist there, and the facts the campaign depends on (support level, wire
format, minimum context, the side channels the plan names) are pinned here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agents.base import SHEETS_DIR, CapabilitySheet, SupportLevel
from control.telemetry.model import WireFormat

AUDIT = Path(__file__).resolve().parents[2] / "docs" / "OLLAMA_SUPPORT_AUDIT.md"
FRAMEWORKS = ("hackingbuddygpt", "pentagi", "pentestgpt", "redamon", "strix")


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
    for field, ref in sheets[name].audit_refs.items():
        for section in re.findall(r"§(\d+(?:\.\d+)*)", ref):
            assert section in known, f"{name}.{field} cites §{section}, not in the audit"


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


@pytest.mark.parametrize(
    ("name", "settings"),
    [
        (
            "strix",
            ["PERPLEXITY_API_KEY", "EXA_API_KEY", "STRIX_MAX_CONTEXT_IMAGES=0", "STRIX_TELEMETRY="],
        ),
        ("redamon", ["AI-attack-surface", "KB_EMBEDDING_API_BASE_URL"]),
        ("pentagi", ["EMBEDDING_PROVIDER=ollama", "Graphiti"]),
        ("pentestgpt", ["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1", "ANTHROPIC_BASE_URL"]),
        ("hackingbuddygpt", ["rag_path", "llm.api_base"]),
    ],
)
def test_the_side_channels_the_plan_names_are_listed(
    sheets: dict[str, CapabilitySheet], name: str, settings: list[str]
) -> None:
    text = "\n".join(sheets[name].side_channels_disabled.values())
    for setting in settings:
        assert setting in text, f"{name}: no side channel switched off with {setting}"


def test_only_hackingbuddygpt_needs_a_patch(sheets: dict[str, CapabilitySheet]) -> None:
    patched = {name for name, sheet in sheets.items() if sheet.patches}
    assert patched == {"hackingbuddygpt"}
    (patch,) = sheets["hackingbuddygpt"].patches
    assert patch.upstream_file == "src/hackingBuddyGPT/utils/llm.py"
    assert "api_base" in patch.change


def test_redamon_caps_turns_with_max_iterations(sheets: dict[str, CapabilitySheet]) -> None:
    assert sheets["redamon"].max_turns_knob.startswith("MAX_ITERATIONS")


def test_the_unofficial_route_is_labelled(sheets: dict[str, CapabilitySheet]) -> None:
    unofficial = {n for n, s in sheets.items() if s.support_level is SupportLevel.UNOFFICIAL}
    assert unofficial == {"pentestgpt"}


@pytest.mark.parametrize("name", FRAMEWORKS)
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
