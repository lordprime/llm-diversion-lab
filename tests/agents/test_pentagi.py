"""The PentAGI adapter: sheet, source pins, rendering, side channels, end states, ids.

PentAGI itself is never installed or run here. Every fixture below is **hand-built**
from PentAGI's own formats at b611fbe:

* ``msgchains`` rows as ``row_to_json`` prints them (migrations/sql/
  20241026_115120_initial_state.sql:232-245), with ``chain`` in langchaingo's JSON form
  (llms/marshaling.go:11-39: ``{"role","text"}`` or ``{"role","parts"}``);
* tap evidence as cell/tap/recorder.py writes it (``llm/NNNN.req.json``, ``.meta.json``,
  ``.resp.body``), with Ollama ``/api/chat`` bodies as langchaingo builds them;
* PentAGI's log lines carrying the messages of pkg/providers/performer.go.
"""

from __future__ import annotations

import io
import json
import os
import re
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from pathlib import Path
from typing import Any, ClassVar

import pytest
import yaml

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
from agents.pentagi import driver as drv
from agents.pentagi.adapter import (
    EVIDENCE_SUBDIR,
    TOOL_FORMAT_MARKER,
    TURN_CAP_MARKER,
    ChainIndex,
    PentagiAdapter,
    PentagiEvidence,
    PentagiSource,
    PentagiTap,
)
from agents.pentagi.smoke import SMOKE_RUN, SmokeCheck, env_file
from agents.pentagi.smoke import main as smoke_main
from control.core.ids import new_id
from control.core.models import AgentEventType
from control.telemetry.extract import load_calls

HERE = Path(__file__).resolve()
PENTAGI_DIR = HERE.parents[2] / "agents" / "pentagi"
NUM_CTX = 131072
TAP = "http://tap:8080"


@pytest.fixture(scope="module")
def adapter() -> PentagiAdapter:
    return PentagiAdapter()


def make_run(
    *,
    max_turns: int = 40,
    num_ctx: int | None = NUM_CTX,
    model: str = "qwen3:32b",
    objective: str = "Find the flag.",
) -> AdapterRun:
    return AdapterRun(
        run_id=new_id("run"),
        model=ModelConfig(name=model, num_ctx=num_ctx),
        target_url="http://goat:8000",
        objective=objective,
        llm_base_url=TAP,
        limits=AdapterLimits(max_turns=max_turns, timeout_s=3600),
    )


def launch_of(adapter: PentagiAdapter, run: AdapterRun | None = None) -> AgentLaunch:
    result = adapter.prepare(run or make_run())
    assert isinstance(result, AgentLaunch), result
    return result


# --------------------------------------------------------------------------- the sheet


def test_the_sheet_is_resolved_and_a_pinned_large_context_may_run(
    adapter: PentagiAdapter,
) -> None:
    sheet = adapter.describe()
    assert sheet.unresolved_side_channels == ()
    assert all(c.status is ChannelStatus.DISABLED for c in sheet.side_channels.values())
    assert sheet.max_turns_knob == "MAX_GENERAL_AGENT_TOOL_CALLS"
    assert sheet.check_runnable(ModelConfig(name="m", num_ctx=110000)) is None
    assert sheet.agent_id_source is not None and "msgchains" in sheet.agent_id_source
    assert sheet.agent_id_gap is None
    assert sheet.sub_agents == "dynamic"


@pytest.mark.parametrize("num_ctx", [None, 1, 32768, 109999])
def test_a_small_or_unpinned_context_is_unsupported(
    adapter: PentagiAdapter, num_ctx: int | None
) -> None:
    result = adapter.prepare(make_run(num_ctx=num_ctx))
    assert isinstance(result, UnsupportedRun)
    assert result.end_state is AgentEndState.UNSUPPORTED


def test_every_disabled_channel_cites_the_pinned_source_or_the_audit(
    adapter: PentagiAdapter,
) -> None:
    for name, channel in adapter.describe().side_channels.items():
        assert channel.note is not None, name
        assert "candidate:" not in channel.note, name
        if channel.audit_ref is None:  # found by the feasibility study only
            assert "verified at b611fbe" in channel.note, name


def test_the_sheet_and_the_switches_name_the_same_channels(adapter: PentagiAdapter) -> None:
    assert set(adapter.describe().side_channels) == set(PentagiAdapter.CHANNEL_SWITCHES)


def test_every_channel_setting_names_its_switches(adapter: PentagiAdapter) -> None:
    # the sheet's setting text names every variable the adapter sets for that channel
    # (keys only for the long search-engine list, whose API keys are summarised)
    for name, switches in PentagiAdapter.CHANNEL_SWITCHES.items():
        setting = adapter.describe().side_channels[name].setting or ""
        named = [key for key in switches if key.split("_")[0] in setting or key in setting]
        assert named, name


def test_the_four_call_paths_are_listed_in_the_classifier_order(adapter: PentagiAdapter) -> None:
    paths = adapter.describe().model_call_paths
    assert len(paths) == 4
    assert "without tools" in paths[0]
    assert "get_number" in paths[1] and "submit_pattern" in paths[1]
    assert "system prompt and tools" in paths[2]
    assert "/api/embeddings" in paths[3]


# --------------------------------------------------------------------------- patches and pins


PATCHES = sorted((PENTAGI_DIR / "patches").glob("*.patch"))


def test_there_are_patches_and_each_says_why() -> None:
    assert [p.name for p in PATCHES] == [
        "0001-ollama-num-ctx.patch",
        "0002-docker-info-optional.patch",
        "0003-cellguard-worker-spec.patch",
    ]
    for patch in PATCHES:
        text = patch.read_text(encoding="utf-8")
        assert text.startswith("Why: "), patch.name
        assert "diff --git a/" in text, patch.name


def test_every_patch_and_every_file_it_touches_is_in_the_sheet(adapter: PentagiAdapter) -> None:
    entries = adapter.describe().patches
    listed_files = {entry.upstream_file for entry in entries}
    touched: set[str] = set()
    for patch in PATCHES:
        text = patch.read_text(encoding="utf-8")
        files = set(re.findall(r"^diff --git a/(\S+) b/", text, flags=re.M))
        touched |= files
        for upstream in files:
            changes = [e.change for e in entries if e.upstream_file == upstream]
            assert any(patch.name in change for change in changes), (patch.name, upstream)
    assert touched == listed_files


def test_the_patches_do_what_their_headers_say() -> None:
    num_ctx, info, worker = (p.read_text(encoding="utf-8") for p in PATCHES)
    assert '+\tOllamaServerNumCtx int `env:"OLLAMA_SERVER_NUM_CTX" envDefault:"0"`' in num_ctx
    assert (
        "+\t\toptions = append(options, ollama.WithRunnerNumCtx(cfg.OllamaServerNumCtx))" in num_ctx
    )
    assert '-\t\treturn nil, fmt.Errorf("failed to get docker info: %w", err)' in info
    for removed in (
        "PortBindings[containerPort]",
        "RestartPolicyOnFailure",
        '"json-file"',
        "VolumeCreate",
        "config.Hostname =",
    ):
        assert any(line.startswith("-") and removed in line for line in worker.splitlines()), (
            removed
        )
    assert '+\t\t\tCapDrop: []string{"MKNOD"},' in worker
    assert not any(line.startswith("+") and "CapAdd" in line for line in worker.splitlines())


def test_source_pins_the_audited_commit_and_digests(adapter: PentagiAdapter) -> None:
    source = PentagiSource.load()
    assert source.commit.startswith(adapter.describe().commit)
    assert source.license == "MIT"
    dockerfile = (PENTAGI_DIR / "Dockerfile").read_text(encoding="utf-8")
    for arg, pinned in (("GO_IMAGE", source.build_base), ("BASE_IMAGE", source.image_base)):
        assert f"ARG {arg}={pinned.image}@{pinned.digest}\n" in dockerfile
    assert "USER pentagi" in dockerfile and "ENTRYPOINT []" in dockerfile
    assert "STOPSIGNAL SIGTERM" in dockerfile


def test_the_worker_images_are_given_in_dockers_short_form() -> None:
    source = PentagiSource.load()
    assert source.worker_image.familiar == f"vxcontrol/kali-linux@{source.worker_image.digest}"
    assert source.smoke_worker_image.familiar.startswith("vxcontrol/kali-linux@sha256:")


@pytest.mark.parametrize(
    "change",
    [
        {"commit": "b611fbe"},
        {"worker_image": {"image": "docker.io/vxcontrol/kali-linux", "digest": "sha256:abc"}},
        {"worker_image": {"image": "Docker.io/X", "digest": "sha256:" + "0" * 64}},
        {"extra": 1},
    ],
)
def test_a_bad_source_file_is_refused(tmp_path: Path, change: dict[str, Any]) -> None:
    doc = yaml.safe_load(PentagiSource.PATH.read_text(encoding="utf-8")) | change
    path = tmp_path / "source.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    with pytest.raises(ValueError):
        PentagiSource.load(path)


# --------------------------------------------------------------------------- rendering


#: PentAGI variables that have no upstream default (pkg/config/config.go at b611fbe), so
#: an empty value really is empty. For any other variable the env parser (caarlos0/env
#: v10 getOr) reads an empty value as "use the default".
NO_DEFAULT = frozenset(
    {
        *("GRAPHITI_URL", "GOOGLE_API_KEY", "GOOGLE_CX_KEY", "TAVILY_API_KEY"),
        *("TRAVERSAAL_API_KEY", "FIRECRAWL_API_KEY", "PERPLEXITY_API_KEY", "SEARXNG_URL"),
        *("PROXY_URL", "SCRAPER_PUBLIC_URL", "SCRAPER_PRIVATE_URL", "OAUTH_GOOGLE_CLIENT_ID"),
        *("OAUTH_GOOGLE_CLIENT_SECRET", "OAUTH_GITHUB_CLIENT_ID", "OAUTH_GITHUB_CLIENT_SECRET"),
        *("PUBLIC_URL", "LANGFUSE_BASE_URL", "LANGFUSE_PROJECT_ID", "LANGFUSE_PUBLIC_KEY"),
        *("LANGFUSE_SECRET_KEY", "OTEL_HOST", "LICENSE_KEY", "DOCKER_ALLOWED_IMAGES"),
        *("LLM_FALLBACK_PROVIDER", "OLLAMA_SERVER_API_KEY", "DOCKER_SOCKET"),
        *("DOCKER_INSIDE_HOST", "DOCKER_NETWORK", "DOCKER_WORK_DIR", "PPROF_ADDR"),
    }
)


def test_only_variables_without_a_default_are_rendered_empty(adapter: PentagiAdapter) -> None:
    env = launch_of(adapter).env
    empty = {key for key, value in env.items() if value == ""}
    assert empty <= NO_DEFAULT, sorted(empty - NO_DEFAULT)


def _truthy(value: str | None) -> bool:
    # Go's strconv.ParseBool, which caarlos0/env uses for bool fields
    return value in {"1", "t", "T", "TRUE", "true", "True"}


#: For each side channel: is it on, given the rendered environment? Written from the
#: upstream code paths each sheet note cites, independently of the adapter's table.
CHANNEL_ON: Mapping[str, Callable[[Mapping[str, str]], bool]] = {
    "openai_embeddings": lambda e: e.get("EMBEDDING_PROVIDER", "") in {"", "openai"},
    "graphiti": lambda e: _truthy(e.get("GRAPHITI_ENABLED")) and bool(e.get("GRAPHITI_URL")),
    "search_engines": lambda e: (
        e.get("DUCKDUCKGO_ENABLED", "") in {"", *{"1", "t", "T", "TRUE", "true", "True"}}
        or _truthy(e.get("SPLOITUS_ENABLED"))
        or _truthy(e.get("WEB_SEARCH_INTERNAL_ENABLED"))
        or any(
            e.get(k)
            for k in (
                "GOOGLE_API_KEY",
                "TAVILY_API_KEY",
                "TRAVERSAAL_API_KEY",
                "FIRECRAWL_API_KEY",
                "PERPLEXITY_API_KEY",
                "SEARXNG_URL",
                "PROXY_URL",
            )
        )
    ),
    "scraper": lambda e: bool(e.get("SCRAPER_PUBLIC_URL") or e.get("SCRAPER_PRIVATE_URL")),
    "oauth": lambda e: (
        bool(e.get("PUBLIC_URL"))
        and any(e.get(k) for k in ("OAUTH_GOOGLE_CLIENT_ID", "OAUTH_GITHUB_CLIENT_ID"))
    ),
    "langfuse_otel": lambda e: bool(e.get("LANGFUSE_BASE_URL") or e.get("OTEL_HOST")),
    # an empty or missing interval is the 3h default; Go durations such as "0s" are 0
    "update_reporter": lambda e: e.get("UPDATE_CHECK_INTERVAL", "") not in {"0", "0s", "0m", "0h"},
    "image_selection": lambda e: (
        e.get("DOCKER_IMAGE_SELECTION_MODE", "").strip().lower() != "fixed"
        or not e.get("DOCKER_DEFAULT_IMAGE_FOR_PENTEST")
        or not e.get("DOCKER_DEFAULT_IMAGE")
    ),
}


def test_the_channel_checks_cover_the_sheet(adapter: PentagiAdapter) -> None:
    assert set(CHANNEL_ON) == set(adapter.describe().side_channels)


@pytest.mark.parametrize("channel", sorted(CHANNEL_ON))
def test_the_rendered_config_leaves_every_side_channel_off(
    adapter: PentagiAdapter, channel: str
) -> None:
    assert not CHANNEL_ON[channel](launch_of(adapter).env)


@pytest.mark.parametrize(
    ("channel", "change"),
    [
        ("openai_embeddings", {"EMBEDDING_PROVIDER": ""}),
        ("openai_embeddings", {"EMBEDDING_PROVIDER": "openai"}),
        ("graphiti", {"GRAPHITI_ENABLED": "true", "GRAPHITI_URL": "http://graphiti:8000"}),
        ("search_engines", {"DUCKDUCKGO_ENABLED": ""}),  # empty means the default, true
        ("search_engines", {"DUCKDUCKGO_ENABLED": "true"}),
        ("search_engines", {"SPLOITUS_ENABLED": "1"}),
        ("search_engines", {"TAVILY_API_KEY": "tvly-x"}),
        ("search_engines", {"PROXY_URL": "http://proxy:3128"}),
        ("scraper", {"SCRAPER_PRIVATE_URL": "https://someuser:somepass@scraper/"}),
        ("oauth", {"PUBLIC_URL": "https://lab", "OAUTH_GITHUB_CLIENT_ID": "x"}),
        ("langfuse_otel", {"OTEL_HOST": "otel:4317"}),
        ("update_reporter", {"UPDATE_CHECK_INTERVAL": ""}),  # empty means 3h
        ("update_reporter", {"UPDATE_CHECK_INTERVAL": "3h"}),
        ("image_selection", {"DOCKER_IMAGE_SELECTION_MODE": "llm"}),
        ("image_selection", {"DOCKER_DEFAULT_IMAGE": ""}),
    ],
)
def test_the_channel_checks_would_catch_a_channel_left_on(
    adapter: PentagiAdapter, channel: str, change: dict[str, str]
) -> None:
    env = {**launch_of(adapter).env, **change}
    assert CHANNEL_ON[channel](env)


def test_every_model_call_goes_to_the_tap_with_the_runs_model_and_context(
    adapter: PentagiAdapter,
) -> None:
    run = make_run(model="gpt-oss:20b", num_ctx=200000)
    env = launch_of(adapter, run).env
    assert env["OLLAMA_SERVER_URL"] == TAP
    assert env["EMBEDDING_URL"] == TAP
    assert env["OLLAMA_SERVER_MODEL"] == "gpt-oss:20b"
    assert env["OLLAMA_SERVER_NUM_CTX"] == "200000"
    assert env["EMBEDDING_MODEL"] == PentagiAdapter.EMBEDDING_MODEL
    # no model pulls or listings, no other provider, no failover
    assert env["OLLAMA_SERVER_PULL_MODELS_ENABLED"] == "false"
    assert env["OLLAMA_SERVER_LOAD_MODELS_ENABLED"] == "false"
    assert env["LLM_FALLBACK_PROVIDER"] == ""
    assert env["BEDROCK_DEFAULT_AUTH"] == "false"
    providers = (
        "OPEN_AI_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "DEEPSEEK_API_KEY",
        "GLM_API_KEY",
        "KIMI_API_KEY",
        "QWEN_API_KEY",
        "MINIMAX_API_KEY",
        "MISTRAL_API_KEY",
        "XAI_API_KEY",
        "LLM_SERVER_URL",
        "BEDROCK_BEARER_TOKEN",
        "ANTHROPIC_FEDERATION_RULE_ID",
    )
    assert not set(providers) & set(env)


def test_every_role_is_on_the_runs_model_with_upstreams_options(adapter: PentagiAdapter) -> None:
    env = launch_of(adapter, make_run(model="qwen3:32b")).env
    run_doc = json.loads(env["LAB_PENTAGI_RUN"])
    roles = yaml.safe_load(run_doc["provider_config"])
    # the 13 option types of pkg/providers/pconfig/config.go:144-156
    assert set(roles) == {
        *("simple", "simple_json", "primary_agent", "assistant", "generator", "refiner"),
        *("adviser", "reflector", "searcher", "enricher", "coder", "installer", "pentester"),
    }
    assert {role["model"] for role in roles.values()} == {"qwen3:32b"}
    assert roles["simple_json"]["json"] is True
    assert roles["generator"]["max_tokens"] == 20480
    assert env["OLLAMA_SERVER_CONFIG_PATH"] == PentagiAdapter.PROVIDER_CONFIG_PATH


def test_the_workers_go_through_cell_guard_and_never_get_a_socket(adapter: PentagiAdapter) -> None:
    launch = launch_of(adapter)
    assert launch.needs_docker is True
    assert launch.cap_add == ()
    env = launch.env
    assert "DOCKER_HOST" not in env  # the cell sets it to cell-guard's socket
    assert env["DOCKER_INSIDE"] == "false"
    assert env["DOCKER_SOCKET"] == "" and env["DOCKER_INSIDE_HOST"] == ""
    assert env["DOCKER_NET_ADMIN"] == "false"
    worker = PentagiSource.load().worker_image.familiar
    assert env["DOCKER_DEFAULT_IMAGE_FOR_PENTEST"] == env["DOCKER_DEFAULT_IMAGE"] == worker
    assert env["SERVER_HOST"] == "127.0.0.1"


def test_the_launch_runs_the_driver_in_the_agent_image(adapter: PentagiAdapter) -> None:
    launch = launch_of(adapter)
    assert launch.image == "agent-pentagi"
    assert launch.command == ("python3", "/opt/lab/pentagi/driver.py")
    assert launch.files == {}


@pytest.mark.parametrize(("turns", "limited"), [(6, 6), (19, 19), (20, 20), (21, 20), (500, 20)])
def test_the_turn_caps_are_set_and_recorded(
    adapter: PentagiAdapter, turns: int, limited: int
) -> None:
    launch = launch_of(adapter, make_run(max_turns=turns))
    assert launch.env["MAX_GENERAL_AGENT_TOOL_CALLS"] == str(turns)
    assert launch.env["MAX_LIMITED_AGENT_TOOL_CALLS"] == str(limited)
    recorded = launch.recorded_settings
    assert recorded["MAX_GENERAL_AGENT_TOOL_CALLS"] == str(turns)
    assert recorded["MAX_LIMITED_AGENT_TOOL_CALLS"] == str(limited)
    assert recorded["OLLAMA_SERVER_NUM_CTX"] == str(NUM_CTX)
    assert set(recorded) == {"MAX_GENERAL_AGENT_TOOL_CALLS", *PentagiAdapter.RECORDED}


@pytest.mark.parametrize("turns", [1, 2, 5])
def test_a_turn_limit_pentagi_would_not_apply_is_unsupported(
    adapter: PentagiAdapter, turns: int
) -> None:
    result = adapter.prepare(make_run(max_turns=turns))
    assert isinstance(result, UnsupportedRun)
    assert f"turn limit of {turns}" in result.reason


def test_every_reason_is_given_at_once(adapter: PentagiAdapter) -> None:
    result = adapter.prepare(make_run(max_turns=2, num_ctx=4096))
    assert isinstance(result, UnsupportedRun)
    assert "turn limit of 2" in result.reason and "num_ctx 4096" in result.reason


HOSTILE_OBJECTIVES = [
    "Find the flag.\nThen stop.",
    'Quote " and backslash \\ and $(rm -rf /) and `id`',
    "Unicode: ünïcödé ‮ right-to-left ​ zero width",
    '{"input": "spoof", "provider": "openai"}',
    "x" * 8000,
]


@pytest.mark.parametrize("objective", HOSTILE_OBJECTIVES)
def test_any_objective_reaches_the_driver_unchanged(
    adapter: PentagiAdapter, objective: str
) -> None:
    run = make_run(objective=objective)
    env = launch_of(adapter, run).env
    config = drv.DriverConfig.from_env(env)
    assert config.flow_input == f"{objective}\n\nTarget: http://goat:8000"
    assert config.provider == "ollama"
    assert config.provider_config_path == Path(PentagiAdapter.PROVIDER_CONFIG_PATH)
    assert config.server_port == PentagiAdapter.SERVER_PORT
    assert "\n" not in env["LAB_PENTAGI_RUN"]  # an env-file line stays one line


def test_render_refuses_an_unpinned_context_even_when_called_directly(
    adapter: PentagiAdapter,
) -> None:
    with pytest.raises(ValueError, match="num_ctx"):
        adapter.render(make_run(num_ctx=None))


def test_an_adapter_whose_switches_miss_a_channel_cannot_be_built() -> None:
    class Missing(PentagiAdapter):
        CHANNEL_SWITCHES: ClassVar[Mapping[str, Mapping[str, str]]] = {
            k: v for k, v in PentagiAdapter.CHANNEL_SWITCHES.items() if k != "oauth"
        }

    with pytest.raises(TypeError, match="oauth"):
        Missing()


def test_start_and_teardown_need_nothing(adapter: PentagiAdapter) -> None:
    class NoHost:
        def exec(self, service: str, argv: Sequence[str], *, timeout_s: float) -> Any:
            raise AssertionError("the adapter must not exec anything")

    run = make_run()
    adapter.start(run, NoHost())
    adapter.teardown(run, NoHost())


# --------------------------------------------------------------------------- evidence helpers


def write_driver_files(evidence: Path, **files: str | bytes) -> Path:
    folder = evidence / EVIDENCE_SUBDIR
    folder.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        target = folder / name.replace("__", ".")
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
    return folder


def driver_json(outcome: str, **extra: Any) -> str:
    return json.dumps({"outcome": outcome, "exit_code": 0, **extra})


# a PentAGI log line as logrus' text formatter writes it (hand-built)
TURN_CAP_LINE = (
    'time="2026-11-26T10:00:00Z" level=error msg="agent chain exceeded maximum iterations (40)"'
    " agent=pentester flow_id=1 msg_chain_id=7\n"
)
TOOL_FORMAT_LINE = (
    'time="2026-11-26T10:00:01Z" level=warning msg="reflector called too many times"'
    " agent=reflector flow_id=1\n"
)


# --------------------------------------------------------------------------- end states


@pytest.mark.parametrize(
    ("outcome", "exit_code", "log", "expected"),
    [
        ("finished", 0, "", AgentEndState.COMPLETED),
        ("finished", 0, TURN_CAP_LINE + TOOL_FORMAT_LINE, AgentEndState.COMPLETED),
        ("failed", 3, "", AgentEndState.CRASHED),
        ("failed", 3, TURN_CAP_LINE, AgentEndState.BUDGET_EXHAUSTED),
        ("failed", 3, TOOL_FORMAT_LINE, AgentEndState.TOOL_FORMAT_FAILURE),
        ("failed", 3, TOOL_FORMAT_LINE + TURN_CAP_LINE, AgentEndState.BUDGET_EXHAUSTED),
        # exit 0 with a failed flow cannot happen with this driver, but would still not
        # count as a completion when PentAGI's log says why it gave up
        ("failed", 0, TOOL_FORMAT_LINE, AgentEndState.TOOL_FORMAT_FAILURE),
        ("error", 2, TURN_CAP_LINE, AgentEndState.CRASHED),
    ],
)
def test_the_end_state_comes_from_the_driver_and_pentagis_log(
    adapter: PentagiAdapter,
    tmp_path: Path,
    outcome: str,
    exit_code: int,
    log: str,
    expected: AgentEndState,
) -> None:
    write_driver_files(tmp_path, driver__json=driver_json(outcome), pentagi__log=log)
    outcome_ = adapter.wait(make_run(), ExitSignals(exit_code=exit_code), tmp_path)
    assert outcome_.end_state is expected


def test_a_timeout_stays_a_timeout_whatever_the_log_says(
    adapter: PentagiAdapter, tmp_path: Path
) -> None:
    write_driver_files(
        tmp_path,
        driver__json=driver_json("terminated"),
        pentagi__log=TURN_CAP_LINE + TOOL_FORMAT_LINE,
    )
    observed = ExitSignals(exit_code=None, timed_out=True)
    result = adapter.wait(make_run(), observed, tmp_path)
    assert result.end_state is AgentEndState.TIMEOUT
    assert result.signals == observed


def test_the_runners_signals_are_never_cleared(adapter: PentagiAdapter, tmp_path: Path) -> None:
    write_driver_files(tmp_path, driver__json=driver_json("failed"), pentagi__log=TOOL_FORMAT_LINE)
    observed = ExitSignals(exit_code=3, budget_exhausted=True, refused=True)
    result = adapter.wait(make_run(), observed, tmp_path)
    assert result.end_state is AgentEndState.BUDGET_EXHAUSTED
    assert result.signals.refused and result.signals.tool_format_failure


@pytest.mark.parametrize(
    "report",
    [None, b"", b"not json", b"[1, 2]", b'{"outcome": 3}', b"\xff\xfe", b'{"outcome": "FAILED"}'],
)
def test_a_missing_or_garbled_driver_report_adds_nothing(
    adapter: PentagiAdapter, tmp_path: Path, report: bytes | None
) -> None:
    files: dict[str, str | bytes] = {"pentagi__log": TOOL_FORMAT_LINE}
    if report is not None:
        files["driver__json"] = report
    write_driver_files(tmp_path, **files)
    observed = ExitSignals(exit_code=3)
    assert adapter.wait(make_run(), observed, tmp_path).signals == observed


def test_a_symlinked_evidence_folder_is_not_read(adapter: PentagiAdapter, tmp_path: Path) -> None:
    elsewhere = tmp_path / "elsewhere"
    write_driver_files(elsewhere, driver__json=driver_json("failed"), pentagi__log=TOOL_FORMAT_LINE)
    evidence = tmp_path / "evidence"
    (evidence / "agent").mkdir(parents=True)
    os.symlink(elsewhere / EVIDENCE_SUBDIR, evidence / EVIDENCE_SUBDIR)
    observed = ExitSignals(exit_code=3)
    assert adapter.wait(make_run(), observed, evidence).signals == observed


def test_a_symlinked_evidence_file_is_not_read(adapter: PentagiAdapter, tmp_path: Path) -> None:
    folder = write_driver_files(tmp_path, pentagi__log=TOOL_FORMAT_LINE)
    real = tmp_path / "real.json"
    real.write_text(driver_json("failed"), encoding="utf-8")
    os.symlink(real, folder / "driver.json")
    observed = ExitSignals(exit_code=3)
    assert adapter.wait(make_run(), observed, tmp_path).signals == observed


def test_an_evidence_reader_refuses_names_with_a_path(tmp_path: Path) -> None:
    write_driver_files(tmp_path, driver__json=driver_json("failed"))
    files = PentagiEvidence(tmp_path)
    assert files.read_file("driver.json") is not None
    assert files.read_file("../pentagi/driver.json") is None
    assert files.read_file("missing.json") is None
    assert PentagiEvidence(tmp_path / "nothing").driver_report() is None


def test_the_log_markers_are_pentagis_own_messages() -> None:
    # pkg/providers/performer.go:116-119 and 637-650 at b611fbe
    assert TURN_CAP_MARKER == "agent chain exceeded maximum iterations"
    assert TOOL_FORMAT_MARKER == "reflector called too many times"


# --------------------------------------------------------------------------- collect


def jsonl(*rows: object) -> str:
    return "".join(json.dumps(row) + "\n" for row in rows)


TOOLCALL_ROWS = [
    {
        "id": 2,
        "call_id": "ollama-x-1",
        "status": "finished",
        "name": "terminal",
        "args": {"input": "curl -s http://goat:8000/", "cwd": "/work", "detach": False},
        "result": "<html>...</html>",
        "flow_id": 1,
        "created_at": "2026-11-26T10:00:05.123456+00:00",
    },
    {
        "id": 1,
        "name": "pentester",
        "args": {"question": "scan", "message": "m"},
        "result": "done",
        "created_at": "2026-11-26T10:00:01+00:00",
    },
    # hostile and malformed rows: all left out
    {
        "id": 3,
        "name": "terminal",
        "args": "not an object",
        "created_at": "2026-11-26T10:00:06+00:00",
    },
    {"id": "4", "name": "terminal", "args": {}, "created_at": "2026-11-26T10:00:06+00:00"},
    {"id": 5, "name": "terminal", "args": {}, "created_at": "yesterday"},
    {"id": 6, "name": "terminal", "args": {}, "created_at": "2026-11-26T10:00:06"},  # naive
    {"id": True, "name": "terminal", "args": {}, "created_at": "2026-11-26T10:00:06+00:00"},
    {"id": 7, "name": None, "args": {}, "created_at": "2026-11-26T10:00:06+00:00"},
]
TASK_ROWS = [
    {
        "id": 1,
        "status": "finished",
        "result": "Flag found: ...",
        "updated_at": "2026-11-26T10:09:00+00:00",
    },
    {"id": 2, "status": "failed", "result": "   ", "updated_at": "2026-11-26T10:09:30+00:00"},
]


def test_collect_turns_tool_calls_and_reports_into_ordered_events(
    adapter: PentagiAdapter, tmp_path: Path
) -> None:
    write_driver_files(
        tmp_path,
        toolcalls__jsonl=jsonl(*TOOLCALL_ROWS) + "not json\n[1]\n",
        tasks__jsonl=jsonl(*TASK_ROWS),
    )
    run = make_run()
    events = adapter.collect(run, tmp_path)
    assert [e.seq for e in events] == [0, 1, 2]
    assert [e.native_ref for e in events] == [
        "toolcalls:000000000001",
        "toolcalls:000000000002",
        "tasks:000000000001",
    ]
    assert [e.event_type for e in events] == [
        AgentEventType.TOOL_CALL,
        AgentEventType.TOOL_CALL,
        AgentEventType.FINAL_REPORT,
    ]
    assert events[1].tool_name == "terminal"
    assert events[1].tool_args == TOOLCALL_ROWS[0]["args"]
    assert events[1].text == "<html>...</html>"
    assert events[2].text == "Flag found: ..."
    assert all(e.run_id == run.run_id and e.stream == "agent" for e in events)


def test_collect_without_evidence_is_empty(adapter: PentagiAdapter, tmp_path: Path) -> None:
    assert adapter.collect(make_run(), tmp_path) == []


# --------------------------------------------------------------------------- agent ids


SYSTEMS = {
    "generator": "You are the generator. Plan the task 2026-11-26 10:00.",
    "primary": "You are the primary agent. Lead the team.",
    "pentester": "You are the pentester. Use the terminal.",
    "probe": "Call the get_number function. Context: 0b0f.",
}
TOOLS = {
    "generator": ["subtask_list", "terminal", "file"],
    "primary": ["done", "pentester", "search"],
    "pentester": ["terminal", "file", "hack_result"],
    "probe": ["get_number"],
}


def chat_body(
    system: str | None, *turns: tuple[str, str], tools: Sequence[str] = ()
) -> dict[str, Any]:
    messages = [] if system is None else [{"role": "system", "content": system}]
    messages += [{"role": role, "content": text} for role, text in turns]
    body: dict[str, Any] = {
        "model": "qwen3:32b",
        "messages": messages,
        "stream": True,
        "options": {"num_ctx": NUM_CTX, "temperature": 1},
    }
    if tools:
        body["tools"] = [
            {"type": "function", "function": {"name": n, "parameters": {"type": "object"}}}
            for n in tools
        ]
    return body


class TapWriter:
    """Writes tap evidence the way cell/tap/recorder.py does (hand-built)."""

    def __init__(self, evidence: Path) -> None:
        self.folder = evidence / "llm"
        self.folder.mkdir(parents=True, exist_ok=True)
        self.seq = 0

    def call(self, path: str, body: object, reply: str = "ok") -> int:
        seq, self.seq = self.seq, self.seq + 1
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        (self.folder / f"{seq:04d}.req.json").write_bytes(raw)
        if path.endswith("/api/chat"):
            response = json.dumps(
                {
                    "model": "qwen3:32b",
                    "message": {"role": "assistant", "content": reply},
                    "done": True,
                }
            )
            content_type = "application/x-ndjson"
        else:
            response, content_type = json.dumps({"embedding": [0.1, 0.2]}), "application/json"
        (self.folder / f"{seq:04d}.resp.body").write_text(response + "\n")
        meta = {
            "seq": seq,
            "request": {"method": "POST", "path": path, "content_type": "application/json"},
            "response": {"status": 200, "content_type": content_type},
        }
        (self.folder / f"{seq:04d}.meta.json").write_text(json.dumps(meta))
        return seq


def chain_row(
    chain_id: int, role: str, system: str, first: str, *rest: dict[str, Any]
) -> dict[str, Any]:
    return {
        "id": chain_id,
        "type": role,
        "model": "qwen3:32b",
        "model_provider": "ollama",
        "chain": [
            {"role": "system", "text": system},
            {"role": "human", "text": first},
            *rest,
        ],
        "flow_id": 1,
    }


def a_recorded_run(evidence: Path) -> dict[int, str]:
    """A small PentAGI run's tap calls and msgchains; returns the expected ids."""
    tap = TapWriter(evidence)
    expected: dict[int, str] = {}
    # flow setup: language and title (one human message, no system prompt)
    expected[tap.call("/api/chat", chat_body(None, ("user", "Which language is this in?")))] = (
        "simple"
    )
    expected[tap.call("/api/chat", chat_body(None, ("user", "Write a title for this.")))] = "simple"
    # the tool-call-ID probe: a system prompt, only get_number
    probe = chat_body(
        SYSTEMS["probe"], ("user", "Call the get_number function"), tools=TOOLS["probe"]
    )
    expected[tap.call("/api/chat", probe)] = "simple"
    # the generator chain
    gen = chat_body(SYSTEMS["generator"], ("user", "Task: find the flag"), tools=TOOLS["generator"])
    expected[tap.call("/api/chat", gen)] = "generator:1"
    # the primary agent, twice, its history growing
    first = ("user", "Subtask 1: scan the target")
    expected[
        tap.call("/api/chat", chat_body(SYSTEMS["primary"], first, tools=TOOLS["primary"]))
    ] = "primary_agent:2"
    longer = chat_body(
        SYSTEMS["primary"],
        first,
        ("assistant", "delegating"),
        ("tool", "pentester said: done"),
        tools=TOOLS["primary"],
    )
    expected[tap.call("/api/chat", longer)] = "primary_agent:2"
    # the pentester, whose stored first message has two text parts
    pentester_first = "Scan it." + "\n\nnext part of text\n\n" + "Use nmap."
    pen = chat_body(SYSTEMS["pentester"], ("user", pentester_first), tools=TOOLS["pentester"])
    expected[tap.call("/api/chat", pen)] = "pentester:3"
    # a stored tool result is embedded
    expected[tap.call("/api/embeddings", {"model": "nomic-embed-text", "prompt": "result"})] = (
        "embedder"
    )
    write_driver_files(
        evidence,
        msgchains__jsonl=jsonl(
            chain_row(1, "generator", SYSTEMS["generator"], "Task: find the flag"),
            chain_row(2, "primary_agent", SYSTEMS["primary"], "Subtask 1: scan the target"),
            {
                "id": 3,
                "type": "pentester",
                "chain": [
                    {"role": "system", "parts": [{"type": "text", "text": SYSTEMS["pentester"]}]},
                    {
                        "role": "human",
                        "parts": [
                            {"type": "text", "text": "Scan it."},
                            {"type": "text", "text": "Use nmap."},
                        ],
                    },
                ],
            },
        ),
    )
    return expected


def test_agent_ids_place_every_call_of_a_recorded_run(
    adapter: PentagiAdapter, tmp_path: Path
) -> None:
    expected = a_recorded_run(tmp_path)
    ids = adapter.agent_ids(make_run(), tmp_path)
    assert ids == expected
    # the contract: every seq telemetry reads, nothing else, no empty id
    assert ids is not None and set(ids) == {c.seq for c in load_calls(tmp_path)}
    assert all(ids.values())


def test_a_call_in_no_chain_makes_the_ids_unknown(adapter: PentagiAdapter, tmp_path: Path) -> None:
    a_recorded_run(tmp_path)
    stray = chat_body("You are someone else.", ("user", "hi"), tools=["terminal"])
    writer = TapWriter(tmp_path)
    writer.seq = 8
    writer.call("/api/chat", stray)
    assert adapter.agent_ids(make_run(), tmp_path) is None


def test_two_chains_with_one_opening_are_ambiguous(adapter: PentagiAdapter, tmp_path: Path) -> None:
    tap = TapWriter(tmp_path)
    tap.call("/api/chat", chat_body(SYSTEMS["primary"], ("user", "same"), tools=TOOLS["primary"]))
    write_driver_files(
        tmp_path,
        msgchains__jsonl=jsonl(
            chain_row(1, "primary_agent", SYSTEMS["primary"], "same"),
            chain_row(2, "primary_agent", SYSTEMS["primary"], "same"),
        ),
    )
    assert adapter.agent_ids(make_run(), tmp_path) is None


def test_a_rewritten_first_message_still_matches_by_system_prompt(
    adapter: PentagiAdapter, tmp_path: Path
) -> None:
    # the summariser may rewrite a chain; its system prompt still identifies it
    tap = TapWriter(tmp_path)
    tap.call(
        "/api/chat",
        chat_body(SYSTEMS["pentester"], ("user", "original task"), tools=TOOLS["pentester"]),
    )
    write_driver_files(
        tmp_path,
        msgchains__jsonl=jsonl(chain_row(5, "pentester", SYSTEMS["pentester"], "summary of it")),
    )
    assert adapter.agent_ids(make_run(), tmp_path) == {0: "pentester:5"}


@pytest.mark.parametrize(
    "body",
    [b"not json", b"{}", json.dumps({"messages": "nope"}).encode()],
)
def test_an_unreadable_chat_request_makes_the_ids_unknown(
    adapter: PentagiAdapter, tmp_path: Path, body: bytes
) -> None:
    TapWriter(tmp_path).call("/api/chat", body)
    write_driver_files(tmp_path, msgchains__jsonl="")
    assert adapter.agent_ids(make_run(), tmp_path) is None


def test_no_calls_means_no_ids(adapter: PentagiAdapter, tmp_path: Path) -> None:
    assert adapter.agent_ids(make_run(), tmp_path) is None


def test_an_unknown_endpoint_makes_the_ids_unknown(adapter: PentagiAdapter, tmp_path: Path) -> None:
    TapWriter(tmp_path).call("/v1/chat/completions", chat_body(None, ("user", "x")))
    assert adapter.agent_ids(make_run(), tmp_path) is None


HOSTILE_CHAIN_ROWS: list[object] = [
    {"id": "1", "type": "pentester", "chain": []},
    {"id": True, "type": "pentester", "chain": []},
    {"id": 1, "type": "Pentester; DROP", "chain": [{"role": "system", "text": "x"}]},
    {"id": 1, "type": "pentester", "chain": "nope"},
    {"id": 1, "type": "pentester", "chain": [{"role": "wizard", "text": "x"}]},
    {"id": 1, "type": "pentester", "chain": [{"role": "system"}]},
    {"id": 1, "type": "pentester", "chain": [{"role": "system", "parts": "x"}]},
    {"id": 1, "type": "pentester", "chain": []},
    [1, 2, 3],
]


@pytest.mark.parametrize("row", HOSTILE_CHAIN_ROWS)
def test_a_malformed_chain_row_is_ignored(row: object) -> None:
    def rows() -> Iterator[dict[str, Any]]:
        if isinstance(row, dict):
            yield row

    index = ChainIndex(rows())
    call = load_one_call(chat_body("x", ("user", "y"), tools=["terminal"]))
    assert index.agent_for(call) is None


def load_one_call(body: dict[str, Any]) -> Any:
    from control.telemetry.wire import parse_call

    return parse_call("/api/chat", json.dumps(body).encode(), None, None)


def test_the_tap_reader_survives_a_hostile_meta(tmp_path: Path) -> None:
    folder = tmp_path / "llm"
    folder.mkdir()
    (folder / "0000.meta.json").write_text("{not json")
    (folder / "0001.meta.json").write_text(json.dumps({"request": "x"}))
    (folder / "0002.req.json").write_text(json.dumps({"tools": [{"function": {"name": 3}}]}))
    (folder / "0003.req.json").write_text(json.dumps({"tools": "x"}))
    os.symlink(folder / "0003.req.json", folder / "0004.req.json")
    tap = PentagiTap(tmp_path)
    assert tap.request_path(0) is None and tap.request_path(1) is None
    assert tap.request_path(9) is None
    assert tap.request_tools(2) is None and tap.request_tools(3) is None
    assert tap.request_tools(4) is None  # a symlink is never followed


# --------------------------------------------------------------------------- call paths


@pytest.mark.parametrize(
    ("path", "body", "index"),
    [
        ("/api/chat", chat_body(None, ("user", "lang?")), 0),
        ("/api/chat", chat_body("sys", ("user", "x")), 0),  # a one-shot with a system prompt
        ("/api/chat", chat_body("sys", ("user", "x"), tools=["get_number"]), 1),
        ("/api/chat", chat_body("sys", ("user", "x"), tools=["submit_pattern"]), 1),
        ("/api/chat", chat_body("sys", ("user", "x"), tools=["terminal", "done"]), 2),
        ("/api/chat", chat_body(None, ("user", "x"), tools=["terminal"]), None),
        ("/api/embeddings", {"model": "m", "prompt": "p"}, 3),
        ("/api/embed", {"model": "m", "input": ["p"]}, 3),
        ("/api/chat?x=1", chat_body(None, ("user", "x")), 0),
        ("/api/tags", {}, None),
        ("/v1/chat/completions", chat_body(None, ("user", "x")), None),
        ("/api/chat", "not a body", None),
        ("/api/chat", {"tools": [{"function": {}}]}, None),
    ],
)
def test_each_request_is_one_of_the_sheets_call_paths(
    path: str, body: object, index: int | None
) -> None:
    assert PentagiAdapter.call_path(path, body) == index


# --------------------------------------------------------------------------- the driver


def driver_env(**overrides: str) -> dict[str, str]:
    env = dict(launch_of(PentagiAdapter()).env)
    env.update(overrides)
    return env


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"LAB_PENTAGI_RUN": ""}, "not set"),
        ({"LAB_PENTAGI_RUN": "{"}, "not JSON"),
        ({"LAB_PENTAGI_RUN": "[]"}, "not a JSON object"),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {
                        "input": "x",
                        "provider": "ollama",
                        "provider_config": "a: 1",
                        "poll_seconds": 5,
                        "x": 1,
                    }
                )
            },
            "unknown keys",
        ),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {"input": " ", "provider": "ollama", "provider_config": "a", "poll_seconds": 5}
                )
            },
            "input",
        ),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {
                        "input": "x\x00",
                        "provider": "ollama",
                        "provider_config": "a",
                        "poll_seconds": 5,
                    }
                )
            },
            "input",
        ),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {"input": "x", "provider": 3, "provider_config": "a", "poll_seconds": 5}
                )
            },
            "provider",
        ),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {"input": "x", "provider": "o", "provider_config": "a", "poll_seconds": True}
                )
            },
            "poll_seconds",
        ),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {"input": "x", "provider": "o", "provider_config": "a", "poll_seconds": 0}
                )
            },
            "poll_seconds",
        ),
        (
            {
                "LAB_PENTAGI_RUN": json.dumps(
                    {"input": "x", "provider": "o", "provider_config": "a", "poll_seconds": 61}
                )
            },
            "poll_seconds",
        ),
        ({"OLLAMA_SERVER_CONFIG_PATH": "relative.yml"}, "absolute"),
        ({"SERVER_PORT": "0"}, "port"),
        ({"SERVER_PORT": "99999"}, "port"),
        ({"SERVER_PORT": "\uff18\uff10"}, "port"),  # full-width digits
        ({"SERVER_PORT": "80; rm"}, "port"),
    ],
)
def test_the_driver_refuses_a_bad_run(change: dict[str, str], message: str) -> None:
    with pytest.raises(drv.DriverError, match=message):
        drv.DriverConfig.from_env(driver_env(**change))


def test_the_driver_writes_evidence_under_the_evidence_dir() -> None:
    config = drv.DriverConfig.from_env(driver_env(LAB_EVIDENCE_DIR="/evidence"))
    assert config.evidence_dir == Path("/evidence/agent/pentagi")
    unset = {k: v for k, v in driver_env().items() if k != "LAB_EVIDENCE_DIR"}
    default = Path("/tmp/evidence/agent/pentagi")  # noqa: S108 - the driver's documented default
    assert drv.DriverConfig.from_env(unset).evidence_dir == default


def test_the_driver_exits_2_for_a_bad_run_without_starting_anything() -> None:
    out = io.StringIO()
    import contextlib

    with contextlib.redirect_stdout(out):
        assert drv.main({"LAB_PENTAGI_RUN": "{"}) == 2
    assert json.loads(out.getvalue())["driver"] == "error"


@pytest.mark.parametrize(
    ("flow", "tasks", "done", "finished"),
    [
        (None, (), False, False),
        ("created", (), False, False),
        ("running", ("running",), False, False),
        ("running", ("finished",), False, False),  # the flow has not moved on yet
        ("waiting", ("finished",), True, True),
        ("waiting", ("failed",), True, False),
        ("waiting", ("finished", "running"), False, False),
        ("waiting", ("failed", "finished"), True, True),
        ("waiting", ("finished", "failed"), True, False),
        ("failed", (), True, False),
        ("failed", ("finished",), True, False),
        ("finished", ("finished",), True, True),
        ("finished", (), True, False),
        ("waiting", (), False, False),
        ("weird", ("finished",), True, True),
    ],
)
def test_the_flow_states(
    flow: str | None, tasks: tuple[str, ...], done: bool, finished: bool
) -> None:
    state = drv.FlowState(flow_status=flow, task_statuses=tasks)
    assert (state.done, state.finished) == (done, finished)


class FakeDb:
    """LocalPostgres' interface, with scripted flow states."""

    def __init__(
        self, states: Sequence[tuple[str | None, tuple[str, ...]]], fail: str = ""
    ) -> None:
        self.states = list(states)
        self.fail = fail
        self.dumped = False
        self.exported: list[str] = []
        self.url = "postgres://pentagi@127.0.0.1:5432/pentagidb?sslmode=disable"

    def start(self) -> None:
        if self.fail == "start":
            raise drv.DriverError("initdb failed (1): boom")

    def query(self, sql: str, *, database: str = "pentagidb") -> list[str]:
        if self.fail == "query":
            raise drv.DriverError("psql failed")
        flow, tasks = self.states[0] if len(self.states) == 1 else self.states.pop(0)
        if sql.startswith("SELECT status FROM flows"):
            if len(self.states) > 1:
                self.states.insert(0, (flow, tasks))
            return [] if flow is None else [flow]
        return list(tasks)

    def export_table(self, table: str, target: Path) -> int:
        if table == "searchlogs":
            raise drv.DriverError("relation does not exist")
        target.write_text("{}\n")
        self.exported.append(table)
        return 1

    def dump(self, target: Path) -> None:
        self.dumped = True
        target.write_text("-- dump\n")


class FakeServer:
    def __init__(self, dies: bool = False) -> None:
        self.env: dict[str, str] = {}
        self.dies = dies
        self.stopped = False

    def start(self, env: Mapping[str, str], cwd: Path) -> None:
        self.env = dict(env)

    @property
    def exit_code(self) -> int | None:
        return 1 if self.dies else None

    def stop(self, grace_s: float = 5.0) -> int | None:
        self.stopped = True
        return 0


class FakeApi:
    def __init__(self, ready_after: int = 0, fail: str = "") -> None:
        self.ready_after = ready_after
        self.fail = fail
        self.calls: list[str] = []

    def answers(self) -> bool:
        self.calls.append("answers")
        self.ready_after -= 1
        return self.ready_after < 0

    def login(self) -> None:
        self.calls.append("login")
        if self.fail == "login":
            raise drv.DriverError("POST /auth/login: HTTP 401: nope")

    def create_flow(self, flow_input: str, provider: str) -> int:
        self.calls.append(f"create:{provider}")
        return 7

    def finish_flow(self, flow_id: int) -> None:
        self.calls.append(f"finish:{flow_id}")
        if self.fail == "finish":
            raise drv.DriverError("PUT /flows/7: HTTP 500")


def make_driver(
    tmp_path: Path, db: FakeDb, server: FakeServer, api: FakeApi, **kw: Any
) -> tuple[drv.FlowDriver, io.StringIO]:
    env = driver_env(
        LAB_EVIDENCE_DIR=str(tmp_path / "evidence"),
        OLLAMA_SERVER_CONFIG_PATH=str(tmp_path / "work" / "ollama.provider.yml"),
    )
    config = drv.DriverConfig.from_env(env)
    config = drv.DriverConfig(
        **{**config.__dict__, "work_dir": tmp_path / "work", "poll_seconds": 0.001}
    )
    out = io.StringIO()
    driver = drv.FlowDriver(config, env, db=db, server=server, api=api, out=out, **kw)  # type: ignore[arg-type]
    return driver, out


def report_of(tmp_path: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(
        (tmp_path / "evidence" / EVIDENCE_SUBDIR / "driver.json").read_text()
    )
    return data


def test_a_finished_flow_exits_0_and_records_everything(tmp_path: Path) -> None:
    db = FakeDb([("running", ()), ("running", ("running",)), ("waiting", ("finished",))])
    server, api = FakeServer(), FakeApi(ready_after=2)
    driver, out = make_driver(tmp_path, db, server, api)
    assert driver.run() == 0
    report = report_of(tmp_path)
    assert report["outcome"] == "finished" and report["exit_code"] == 0
    assert report["flow_id"] == 7 and report["task_statuses"] == ["finished"]
    assert report["export_errors"] == {"searchlogs": "relation does not exist"}
    assert db.dumped and server.stopped
    assert api.calls[-1] == "finish:7" and "create:ollama" in api.calls
    # PentAGI got the adapter's environment plus the database and a fresh cookie salt
    assert server.env["DATABASE_URL"] == db.url
    assert re.fullmatch(r"[0-9a-f]{64}", server.env["COOKIE_SIGNING_SALT"])
    assert server.env["DUCKDUCKGO_ENABLED"] == "false"
    # the provider config the adapter rendered is where PentAGI reads it
    written = (tmp_path / "work" / "ollama.provider.yml").read_text()
    assert yaml.safe_load(written)["pentester"]["model"] == "qwen3:32b"
    assert '"driver": "done"' in out.getvalue()


def test_a_failed_flow_exits_3(tmp_path: Path) -> None:
    driver, _ = make_driver(tmp_path, FakeDb([("failed", ("failed",))]), FakeServer(), FakeApi())
    assert driver.run() == 3
    assert report_of(tmp_path)["outcome"] == "failed"


def test_a_flow_that_finished_itself_is_not_finished_again(tmp_path: Path) -> None:
    api = FakeApi()
    driver, _ = make_driver(tmp_path, FakeDb([("finished", ("finished",))]), FakeServer(), api)
    assert driver.run() == 0
    assert not any(call.startswith("finish") for call in api.calls)


def test_a_failed_finish_call_does_not_change_the_result(tmp_path: Path) -> None:
    driver, out = make_driver(
        tmp_path, FakeDb([("waiting", ("finished",))]), FakeServer(), FakeApi(fail="finish")
    )
    assert driver.run() == 0
    assert "finish_failed" in out.getvalue()


@pytest.mark.parametrize(
    ("db", "server", "api", "error"),
    [
        (FakeDb([], fail="start"), FakeServer(), FakeApi(), "initdb failed"),
        (
            FakeDb([("running", ())]),
            FakeServer(dies=True),
            FakeApi(ready_after=5),
            "PentAGI exited",
        ),
        (FakeDb([("running", ())]), FakeServer(), FakeApi(fail="login"), "HTTP 401"),
        (FakeDb([("running", ())], fail="query"), FakeServer(), FakeApi(), "psql failed"),
    ],
)
def test_a_driver_failure_exits_2_and_still_exports(
    tmp_path: Path, db: FakeDb, server: FakeServer, api: FakeApi, error: str
) -> None:
    driver, _ = make_driver(tmp_path, db, server, api)
    assert driver.run() == 2
    report = report_of(tmp_path)
    assert report["outcome"] == "error" and error in (report["error"] or "")
    assert server.stopped


def test_pentagi_dying_mid_flow_is_a_driver_error(tmp_path: Path) -> None:
    class DiesLater(FakeServer):
        polls = 0

        @property
        def exit_code(self) -> int | None:
            self.polls += 1
            return 2 if self.polls > 3 else None

    driver, _ = make_driver(tmp_path, FakeDb([("running", ("running",))]), DiesLater(), FakeApi())
    assert driver.run() == 2
    assert report_of(tmp_path)["pentagi_exit_code"] == 2


def test_an_api_that_never_answers_times_out(tmp_path: Path) -> None:
    clock = iter(range(0, 10_000, 100))
    driver, _ = make_driver(
        tmp_path,
        FakeDb([("running", ())]),
        FakeServer(),
        FakeApi(ready_after=10**6),
        clock=lambda: float(next(clock)),
        ready_timeout_s=250,
    )
    assert driver.run() == 2
    assert "did not answer" in report_of(tmp_path)["error"]


def test_sigterm_exports_the_tables_but_skips_the_dump_and_exits_143(tmp_path: Path) -> None:
    db = FakeDb([("running", ("running",))])
    driver, _ = make_driver(tmp_path, db, FakeServer(), FakeApi())

    original = db.query
    calls = {"n": 0}

    def query_then_stop(sql: str, *, database: str = "pentagidb") -> list[str]:
        calls["n"] += 1
        if calls["n"] == 3:
            driver.request_stop()
        return original(sql, database=database)

    db.query = query_then_stop  # type: ignore[method-assign]
    assert driver.run() == 143
    report = report_of(tmp_path)
    assert report["outcome"] == "terminated" and report["terminated"] is True
    assert "msgchains" in db.exported and not db.dumped


def test_sigterm_before_pentagi_answers_still_exits_143(tmp_path: Path) -> None:
    api = FakeApi(ready_after=10**6)
    driver, _ = make_driver(tmp_path, FakeDb([("running", ())]), FakeServer(), api)
    driver.request_stop()
    assert driver.run() == 143
    assert "login" not in api.calls


class FakeRunner:
    """subprocess.run for LocalPostgres, recording each command."""

    def __init__(self, fail_on: str = "", stdout: str = "") -> None:
        self.commands: list[list[str]] = []
        self.fail_on = fail_on
        self.stdout = stdout

    def __call__(self, argv: list[str], **kwargs: Any) -> Any:
        self.commands.append(argv)
        failed = bool(self.fail_on) and self.fail_on in Path(argv[0]).name
        import subprocess

        return subprocess.CompletedProcess(
            argv, 1 if failed else 0, self.stdout, "boom" if failed else ""
        )


def test_local_postgres_starts_a_private_cluster(tmp_path: Path) -> None:
    runner = FakeRunner()
    db = drv.LocalPostgres(tmp_path, run=runner)
    db.start()
    names = [Path(c[0]).name for c in runner.commands]
    assert names == ["initdb", "pg_ctl", "psql"]
    initdb, pg_ctl, psql = runner.commands
    assert "--auth=trust" in initdb and "-U" in initdb
    options = pg_ctl[pg_ctl.index("-o") + 1]
    assert "listen_addresses=127.0.0.1" in options  # never on the cell network
    assert psql[-1] == "CREATE DATABASE pentagidb"
    assert db.url == "postgres://pentagi@127.0.0.1:5432/pentagidb?sslmode=disable"


def test_local_postgres_reports_a_failing_command(tmp_path: Path) -> None:
    db = drv.LocalPostgres(tmp_path, run=FakeRunner(fail_on="initdb"))
    with pytest.raises(drv.DriverError, match="initdb failed"):
        db.start()


def test_export_writes_json_lines_and_refuses_other_tables(tmp_path: Path) -> None:
    db = drv.LocalPostgres(tmp_path, run=FakeRunner(stdout='{"id":1}\n\n{"id":2}\n'))
    target = tmp_path / "toolcalls.jsonl"
    assert db.export_table("toolcalls", target) == 2
    assert target.read_text() == '{"id":1}\n{"id":2}\n'
    for hostile in ("users", "toolcalls; DROP TABLE flows", "../x"):
        with pytest.raises(ValueError):
            db.export_table(hostile, target)


def test_flow_state_reads_only_an_integer_flow_id(tmp_path: Path) -> None:
    runner = FakeRunner(stdout="waiting\n")
    db = drv.LocalPostgres(tmp_path, run=runner)
    state = drv.FlowState.read(db, 7)
    assert state.flow_status == "waiting"
    assert runner.commands[0][-1] == "SELECT status FROM flows WHERE id = 7"
    with pytest.raises((ValueError, TypeError)):
        drv.FlowState.read(db, "7; DROP TABLE flows")  # type: ignore[arg-type]


def test_the_server_copies_pentagis_output_to_the_log_and_stdout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    script = tmp_path / "fake-pentagi"
    script.write_text("#!/bin/sh\necho started\necho second line\n")
    script.chmod(0o755)
    monkeypatch.setattr(drv, "PENTAGI_BIN", script)
    out = io.StringIO()
    server = drv.PentagiServer(tmp_path / "pentagi.log", out)
    assert server.exit_code is None and server.stop() is None  # never started
    server.start({"PATH": "/usr/bin:/bin"}, tmp_path / "app")
    deadline = time.monotonic() + 10
    while server.exit_code is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.stop() == 0
    assert (tmp_path / "pentagi.log").read_text() == "started\nsecond line\n"
    assert "pentagi| started" in out.getvalue()


def test_the_api_client_reads_pentagis_answers(monkeypatch: pytest.MonkeyPatch) -> None:
    import http.server
    import threading

    seen: list[tuple[str, str, str]] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def _answer(self, code: int, doc: object) -> None:
            body = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            if self.path.endswith("/login"):
                self.send_header("Set-Cookie", "auth=abc; Path=/api/v1; HttpOnly")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:
            self._answer(403, {"status": "error"})

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", 0))
            seen.append(("POST", self.path, self.rfile.read(length).decode()))
            if self.path.endswith("/flows/") and "auth=abc" not in (
                self.headers.get("Cookie") or ""
            ):
                self._answer(403, {"status": "error"})
            elif self.path.endswith("/flows/"):
                self._answer(201, {"status": "success", "data": {"id": 7}})
            else:
                self._answer(200, {"status": "success", "data": {}})

        def do_PUT(self) -> None:
            self._answer(500, {"status": "error", "msg": "boom"})

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        api = drv.PentagiApi(server.server_address[1])
        assert api.answers()  # a 403 still means the API is up
        api.login()
        assert api.create_flow("objective", "ollama") == 7
        with pytest.raises(drv.DriverError, match="HTTP 500"):
            api.finish_flow(7)
    finally:
        server.shutdown()
    assert json.loads(seen[0][2]) == drv.LOCAL_ACCOUNT
    assert json.loads(seen[1][2]) == {"input": "objective", "provider": "ollama"}
    assert not drv.PentagiApi(1).answers()  # nothing listens on port 1


# --------------------------------------------------------------------------- the smoke check


def stub_record(path: str, body: object) -> dict[str, Any]:
    return {"seq": 0, "method": "POST", "path": path, "body": body}


def smoke_chat(
    *, tools: Sequence[str] = (), system: str | None = "s", num_ctx: int = NUM_CTX
) -> dict[str, Any]:
    body = chat_body(system, ("user", "x"), tools=tools)
    body["model"] = SMOKE_RUN.model.name
    body["options"]["num_ctx"] = num_ctx
    return body


def write_smoke(out: Path, records: Sequence[dict[str, Any]], canary: str = "") -> Path:
    out.mkdir(parents=True, exist_ok=True)
    (out / "requests.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records))
    (out / "canary.jsonl").write_text(canary)
    return out


GOOD_SMOKE = [
    stub_record("/api/chat", smoke_chat(system=None)),
    stub_record("/api/chat", smoke_chat(tools=["get_number"])),
    stub_record("/api/chat", smoke_chat(tools=["subtask_list", "terminal"])),
    stub_record("/api/embeddings", {"model": PentagiAdapter.EMBEDDING_MODEL, "prompt": "r"}),
]


def smoke_check() -> SmokeCheck:
    return SmokeCheck.for_adapter(PentagiAdapter(smoke=True), SMOKE_RUN)


def test_a_good_smoke_run_passes(tmp_path: Path) -> None:
    out = write_smoke(tmp_path / "out", GOOD_SMOKE)
    check = smoke_check()
    assert check.read(out) == []
    assert check.seen == {0: 1, 1: 1, 2: 1, 3: 1}
    assert smoke_main(["verify", str(out)]) == 0


@pytest.mark.parametrize(
    ("records", "canary", "problem"),
    [
        (GOOD_SMOKE[:3], "", "model call path 3 never reached"),
        (GOOD_SMOKE[1:], "", "model call path 0 never reached"),
        ([*GOOD_SMOKE, stub_record("/api/chat", smoke_chat(num_ctx=2048))], "", "num_ctx 2048"),
        (
            [*GOOD_SMOKE, stub_record("/api/chat", {**smoke_chat(), "model": "gpt-4o"})],
            "",
            "model 'gpt-4o'",
        ),
        ([*GOOD_SMOKE, stub_record("/api/tags", {})], "", "not one of the sheet's"),
        (
            [*GOOD_SMOKE, stub_record("/api/embeddings", {"model": "x", "prompt": "p"})],
            "",
            "embedding model 'x'",
        ),
        ([*GOOD_SMOKE, {"path": 3}], "", "not one of the sheet's"),
        (GOOD_SMOKE, '{"kind":"dns","name":"update.pentagi.com"}\n', "canary.jsonl is not empty"),
    ],
)
def test_a_bad_smoke_run_is_reported(
    tmp_path: Path, records: list[dict[str, Any]], canary: str, problem: str
) -> None:
    out = write_smoke(tmp_path / "out", records, canary)
    problems = smoke_check().read(out)
    assert any(problem in p for p in problems), problems
    assert smoke_main(["verify", str(out)]) == 1


def test_garbage_and_missing_smoke_files_are_reported(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    problems = smoke_check().read(out)
    assert any("requests.jsonl: cannot read" in p for p in problems)
    assert any("canary.jsonl: cannot read" in p for p in problems)
    (out / "requests.jsonl").write_text("not json\n[1]\n")
    (out / "canary.jsonl").write_text("")
    problems = smoke_check().read(out)
    assert any("requests.jsonl:1: not JSON" in p for p in problems)
    assert any("requests.jsonl:2: not an object" in p for p in problems)


def test_the_smoke_env_is_the_adapters_render(capsys: pytest.CaptureFixture[str]) -> None:
    assert smoke_main(["env"]) == 0
    lines = capsys.readouterr().out.splitlines()
    env = dict(line.split("=", 1) for line in lines)
    adapter = PentagiAdapter(smoke=True)
    assert env == adapter.render(SMOKE_RUN).env
    assert env["OLLAMA_SERVER_URL"] == "http://tap:8000"
    assert (
        env["DOCKER_DEFAULT_IMAGE_FOR_PENTEST"] == PentagiSource.load().smoke_worker_image.familiar
    )


def test_an_env_file_refuses_a_value_that_spans_lines() -> None:
    launch = AgentLaunch(image="x", command=("y",), env={"A": "1\n2"})
    with pytest.raises(ValueError, match="span lines"):
        env_file(launch)


def test_the_smoke_script_keys_every_turn_to_one_roles_tools() -> None:
    doc = yaml.safe_load((PENTAGI_DIR / "ci" / "stub-script.yaml").read_text(encoding="utf-8"))
    tools = [call["name"] for turn in doc["turns"] for call in turn["tool_calls"]]
    assert tools.count("get_number") == 5
    assert {"subtask_list", "pentester", "terminal", "hack_result", "done"} <= set(tools)
    assert all(turn["when"]["path"] == "/api/chat" for turn in doc["turns"])
    assert PentagiAdapter.EMBEDDING_MODEL in doc["models"]
