# Ollama support in open-source autonomous pentest agents

Audit date: 2026-11-24. Method: read-only review of source and docs on GitHub (raw files at a pinned
commit), project docs, issue trackers, and the Ollama, LiteLLM, Claude Code and Claude Agent SDK
sources/docs. Nothing was cloned, installed or run. Every claim below cites a file at a commit, or a
docs URL. "Inference" marks a conclusion drawn from reading code rather than from a statement by the
project.

## 1. Summary

Of the five tools in the paper, four document Ollama as a provider option: Strix, PentAGI, RedAmon
and hackingBuddyGPT. The fifth, the PentestGPT agentic pipeline, does not mention Ollama. It runs on
Claude Code or Codex. Claude Code reads `ANTHROPIC_BASE_URL` from the environment, and Ollama has
served the Anthropic Messages API since v0.14.0, so the pipeline can reach Ollama without a code
change. This route is unofficial, and Ollama's Anthropic API leaves out `tool_choice`, token counting
and hosted web search. Two of the four "native" tools need care before their traffic can be captured
cleanly through a proxy:

- **hackingBuddyGPT** documents `llm.api_base` but never passes it to LiteLLM. The repo's own
  benchmark script works around this with `OLLAMA_API_BASE`.
- **RedAmon** routes models per provider and per feature. It also starts its own Ollama container for
  the AI-attack-surface judge, which does not use the configured provider.

Strix and PentAGI send every model call through one configurable endpoint. Strix's optional
web-search tool can call Perplexity's hosted LLM directly. Every tool except RedAmon's main agent
needs native structured tool calls. Every project that gives guidance warns that small local models
emit malformed tool calls, or none, and asks for a large `num_ctx`: 16–32k for Strix, 64k+ for Claude
Code according to Ollama, and 110k for PentAGI.

Wire formats differ, which affects how the recording proxy parses traffic:

| Wire format | Used by |
|---|---|
| Ollama native `/api/chat` | PentAGI, and LiteLLM's `ollama_chat` route (Strix, hackingBuddyGPT, CAI, Decepticon) |
| OpenAI `/v1/chat/completions` | RedAmon, PentestGPT legacy |
| Anthropic `/v1/messages` | PentestGPT agentic via Claude Code |

### Summary table

| Tool | Version / commit read | Support level | Client library | Base URL honoured for every model call | Native tool calling needed | Sub-agents (default) | Main source |
|---|---|---|---|---|---|---|---|
| hackingBuddyGPT | v0.5.0, `e23d918` (HEAD of `main`) | native | LiteLLM (`litellm.completion`), LiteLLM 1.97.0 in `uv.lock` | **No via `llm.api_base`** (not passed). Yes via `OLLAMA_API_BASE` env, except the optional RAG embeddings (OpenAI) | Yes for tool-calling use cases; no for the template-based privesc use cases | 1 agent in most use cases. The AD use case runs a planner plus one fresh executor per delegated task | `.env.example`, `README.md`, `src/hackingBuddyGPT/utils/llm.py` |
| Strix | v1.7.1, `685bbc8` (LLM config identical to the audited 1.7.0 `6b7ae2e`) | native | OpenAI Agents SDK 0.19.0 with LiteLLM extension (LiteLLM 1.101.0) | Yes for all model calls (`litellm.api_base` is set globally). Exception: optional `web_search` calls Perplexity `sonar-reasoning-pro` or Exa at fixed URLs | Yes, structured `tool_calls` are mandatory | Root agent plus child agents spawned on demand in parallel. No hard cap found | `docs/llm-providers/local.mdx`, `strix/config/settings.py`, `strix/config/models.py` |
| RedAmon | v7.9.0, `73ca9d3` (setup code also checked at audited 7.6.0 `03b46b8`) | native (OpenAI-compatible provider with a built-in "Ollama" preset) | LangChain (`ChatOpenAI` for OpenAI-compatible endpoints) | Per provider: yes. Not globally: each "Model by feature" picks its own provider, and the AI-attack-surface judge uses its own Ollama container at a fixed URL | Main agent: no (JSON decision parsed from text). CypherFix agents: yes (`bind_tools`) | Root agent plus "fireteam" waves, on by default, max 5 members and 5 concurrent | `README.md`, `webapp/src/lib/llmProviderPresets.ts`, `agentic/orchestrator_helpers/llm_setup.py`, `agentic/project_settings.py` |
| PentestGPT (agentic) | `e8b1bb7` (HEAD of `main`, 2026-07-14). `unified-agent==0.3.0` pinned | **unofficial** for the autonomous pipeline (works through Claude Code's `ANTHROPIC_BASE_URL` and Ollama's Anthropic API). The legacy interactive mode is native | Claude Agent SDK, which drives the Claude Code CLI; `openai-codex` SDK for Codex | Yes if `ANTHROPIC_BASE_URL` is set in the process environment. Claude Code's WebSearch is server-side and unsupported by Ollama | Yes (Claude Code tools and an MCP tool server) | Supervisor and Executor, run in sequence, a fresh session each episode. Claude Code may spawn its own subagents | `README.md`, `unified_agent/backends/claude_code.py`, `scripts/entrypoint.sh` |
| PentAGI | v2.2.0, `b611fbe` (latest release; `main` at `cffed94` has the same Ollama config fields) | native | Go `vxcontrol/langchaingo` Ollama client using native `/api/chat` | Yes: one `OLLAMA_SERVER_URL` for all agent roles, and `PROXY_URL` covers LLM, embedding and search calls. Exceptions: optional Graphiti service; embeddings default to OpenAI | Yes. The reflector steps in when a model replies without tool calls | Primary agent delegates to role agents (13 option types: searcher, pentester, coder, installer, adviser, etc.) | `backend/docs/ollama.md`, `README.md`, `backend/pkg/providers/ollama/ollama.go` |
| CAI (Alias Robotics) | `6dc7925` (`archive` branch; repo archived) | native | Fork of the OpenAI Agents SDK with LiteLLM | Not checked in code | Yes (inference: Agents SDK) | Multi-agent patterns (not counted) | `docs/providers/ollama.md` |
| PentestAgent (GH05TCREW) | `5bcf872` | native | LiteLLM | Probably, with a caveat (see §2.6) | Yes (inference) | `/crew` mode: an orchestrator spawns workers | `.env.example`, `pentestagent/llm/llm.py` |
| Shannon (Keygraph) | `d72c082` | native (documented local-model path) | "Pi harness" provider catalogue | Yes: `SHANNON_AI_BASE_URL`; "a single unified model setting throughout a pentest" | Yes (README warning about tool-use constraints) | Not checked | `docs/ai-providers.md`, `README.md` |
| Decepticon (BitterSecurity, formerly PurpleAILAB) | `6b15092` | native (`ollama_local` auth method) | LiteLLM proxy in front of LangGraph agents | Yes in design: every call goes through one LiteLLM proxy | Not checked | Multiple named agents with a per-agent model tier | `docs/models.md` |
| Nebula (berylliumsec) | `6f6bb82` | native (README lists Ollama as a provider) | Not checked | Not checked | Not checked | Delegated child agents (README) | `README.md` |
| NeuroSploit (now JoasASantos) | `54d8e86` | native (README lists `ollama` provider) | Not checked | Not checked | Not checked | Not checked | `README.md` |
| HexStrike AI | `d689933` | not applicable: MCP tool server with no LLM client of its own | none (`requirements.txt` has no LLM SDK) | n/a (the MCP client chooses the model) | n/a | n/a | `README.md`, `requirements.txt` |

Link prefixes used below:

- HBG = `https://github.com/ipa-lab/hackingBuddyGPT/blob/e23d918592556f71b8e3b2ee152449e82fa14794/`
- STRIX = `https://github.com/usestrix/strix/blob/685bbc8138d35fc9fe378ac37ec0d9198b9c46a3/`
- REDAMON = `https://github.com/samugit83/redamon/blob/73ca9d38ced026be6d88d1dc526c72317e7d193c/`
- PGPT = `https://github.com/GreyDGL/PentestGPT/blob/e8b1bb77d1ac00329675cec3b060aba971ec1ac8/`
- PENTAGI = `https://github.com/vxcontrol/pentagi/blob/b611fbebcf55b6deb88ad1fb7bf1f1ce7a357242/`

---

## 2. Per-tool details

### 2.1 hackingBuddyGPT (ipa-lab), v0.5.0, commit `e23d918`

- **Licence:** MIT (GitHub licence metadata; `pyproject.toml` points at `LICENSE`).
- **Support level: native.** The README says any provider is reachable through `llm.model`,
  "including a local Ollama". It gives `ollama_chat/llama3` as an example (HBG`README.md`, lines 82,
  121). `.env.example` lists `ollama_chat/llama3  (a local Ollama model)`. The benchmark launcher
  defaults to Ollama: `--provider ollama --model ollama_chat/llama3` (HBG`benchmark_privesc.py`,
  lines 21, 71, 534).
- **Configuration:** `.env` keys or CLI flags `llm.model`, `llm.api_key`, `llm.context_size`,
  `llm.api_base`, `llm.proxy`, `llm.proxy_insecure`, `llm.api_timeout`, `llm.api_retries`
  (HBG`.env.example`; HBG`src/hackingBuddyGPT/utils/llm.py`).
- **How it calls models:** one class, `LiteLLM`, in `src/hackingBuddyGPT/utils/llm.py`. It calls
  `litellm.completion(...)`. The project dropped direct `openai` use (`pyproject.toml` lines 30–32).
  The lockfile pins LiteLLM 1.97.0.
- **Base URL caveat (important):** the `api_base` argument is commented out in `raw_completion`:
  `# api_base=self.api_base, TODO: why is this not working anymore` (`utils/llm.py`). So
  `llm.api_base`, which the README documents and defaults to OpenRouter, is ignored. The project
  admits this in `benchmark_privesc.py` lines 259–262: "api_base is currently not wired through to
  litellm, so a custom Ollama endpoint is passed via the env var litellm reads for the ollama
  provider" (`OLLAMA_API_BASE`). In LiteLLM 1.97.0 the Ollama route resolves the endpoint as
  `litellm.api_base or api_base or OLLAMA_API_BASE or "http://localhost:11434"`
  (`https://github.com/BerriAI/litellm/blob/v1.97.0/litellm/main.py`, line 4211). With
  `OLLAMA_API_BASE` set, every completion goes there. The `llm.proxy` option installs an httpx client
  with a proxy as `litellm.client_session`. Whether LiteLLM's `ollama_chat` handler uses that session
  was not verified.
- **Tool calling / JSON / vision / context:**
  - Chat-style use cases turn capabilities into OpenAI-style `tools`
    (`capability.py: capabilities_to_tools`).
  - The web-API use cases force `tool_choice="required"`
    (`usecases/web_api/simple_openapi_documentation.py` line 339;
    `utils/web_api/response_analyzer_with_llm.py` line 175).
  - The classic Linux privesc use cases render Mako text templates and need no tool calling
    (`strategies.py` line 102; `usecases/priv_esc/linux_privesc.py`).
  - No vision use was found.
  - The context window is user-declared (`llm.context_size`, default 16385 in `.env.example`) and
    drives history trimming (`strategies.py` line 98).
- **Auxiliary model calls:** optional "update state" and "explanation" calls
  (`linux_privesc.py` lines 222, 252) and the web-API response analyser. All of these use the same
  `LiteLLM` instance. The optional RAG extra uses
  `OpenAIEmbeddings(model="text-embedding-3-large", api_key=llm.api_key)` (`utils/rag.py` line 28).
  That is a separate, hard-coded OpenAI embeddings call, made only when `rag_path` is set.
- **Multi-agent:** most use cases run one agent. The AD use case is a planner whose
  `perform_task` tool builds a fresh `ADExecutor` for each delegated sub-task
  (`usecases/ad/executor.py`). `usecases/web/advanced.py` uses `SubAgentCapability`.
- **Known caveats with local models:**
  - Closed issues #93 ("Issues with Using Ollama as LLM Backend", 2024) and #138 ("Accessing with
    Local LLM model", 2025) predate the LiteLLM rewrite.
  - The current README gives no model-size guidance.

### 2.2 Strix (usestrix), v1.7.1, commit `685bbc8`

- **Version note:** the paper audited 1.7.0 (`6b7ae2e`). `strix/config/models.py` and
  `docs/llm-providers/local.mdx` are byte-identical between the two. `strix/config/settings.py`
  differs only in the default sandbox image tag (1.3.1 → 1.4.1).
- **Licence:** Apache-2.0 (GitHub licence metadata).
- **Support level: native.**
  - `docs/llm-providers/overview.mdx` lists `ollama/llama4` with
    `LLM_API_BASE="http://localhost:11434"`.
  - `docs/llm-providers/local.mdx` has an Ollama section: `STRIX_LLM="ollama/qwen3-vl"`, recommended
    models Qwen3 VL, DeepSeek V3.1 and Devstral 2.
  - The code maps the `ollama/` prefix to LiteLLM `ollama_chat/` (STRIX`strix/config/models.py`
    lines 609–610).
- **Configuration (STRIX`strix/config/settings.py`):**
  - `STRIX_LLM` sets the model.
  - `LLM_API_BASE` sets the endpoint. Aliases: `OPENAI_API_BASE`, `OPENAI_BASE_URL`,
    `LITELLM_BASE_URL`, `OLLAMA_API_BASE`.
  - Other connection settings: `LLM_API_KEY`, `LLM_EXTRA_HEADERS`, `LLM_EXTRA_BODY`,
    `STRIX_REASONING_EFFORT` (default `high`), `LLM_DISABLE_STREAMING`, `LLM_TIMEOUT`.
  - Settings can also be stored in `~/.strix/cli-config.json` (`strix/config/loader.py`).
- **How it calls models:**
  - The OpenAI Agents SDK (`openai-agents[litellm]` 0.19.0) with its `LitellmModel`, behind a custom
    `StrixProvider` (`models.py` lines 563–660). LiteLLM is 1.101.0 per `uv.lock`.
  - `configure_sdk_model_defaults` sets `OPENAI_BASE_URL` and `litellm.api_base` globally from
    `LLM_API_BASE` (`models.py` lines 721–723, 978–982).
  - In LiteLLM's Ollama route the global `litellm.api_base` takes precedence over a per-call base
    (`litellm/main.py` at v1.101.0, line 4332). So the main agent, the compaction summariser and the
    dedupe judge all reach the same endpoint when they route to Ollama.
  - Inference: for an Ollama-routed dedupe model, a separate `DEDUPE_LLM_API_BASE` is overridden by
    that global.
- **Tool calling / vision / context:**
  - Native tool calls are mandatory. local.mdx section "Tool calling must return structured
    `tool_calls`": "every working turn must be a **native** function/tool call".
  - For Ollama, the docs say to disable thinking on reasoning models and to raise `num_ctx` to "at
    least 16k–32k".
  - Vision: `model_supports_images` returns True for any model missing from LiteLLM's catalogue
    ("Assume yes until proven otherwise", `models.py` lines 1013–1015). Browser screenshots are kept
    in context (`STRIX_MAX_CONTEXT_IMAGES`, default 3, `settings.py`). Inference: a text-only Ollama
    model will receive images unless `STRIX_MAX_CONTEXT_IMAGES=0`. The docs recommend `qwen3-vl`.
  - Context budget: when LiteLLM has no model info, Strix assumes `STRIX_CONTEXT_FALLBACK_TOKENS`,
    default 200,000 (`strix/llm/context_budget.py` lines 61–68; `settings.py`). Inference: set this to
    the real `num_ctx`, or compaction will fire too late.
- **Auxiliary model calls:**
  - History compaction: `_summarize` calls `StrixProvider().get_model(model)` with no tools
    (`strix/llm/compaction.py` lines 302–316).
  - Report dedupe judge: `STRIX_DEDUPE_MODEL` defaults to the main model
    (`strix/report/dedupe.py` line 365).
  - Both can use the same local model.
  - `web_search` posts to `https://api.perplexity.ai/chat/completions` with model
    `sonar-reasoning-pro` when `PERPLEXITY_API_KEY` is set, otherwise to Exa
    (`strix/tools/web_search/tool.py` lines 49–53, 122). This is a hosted LLM call that bypasses
    `LLM_API_BASE`.
  - `chatgpt/` models use a hard-coded Codex endpoint (`strix/config/codex.py` line 50). This is not
    relevant to Ollama.
- **Other egress:** telemetry is on by default (`STRIX_TELEMETRY=True`; PostHog and Scarf,
  `strix/interface/main.py`), plus an update check against GitHub and PyPI
  (`strix/interface/update_check.py`).
- **Multi-agent:** the root agent calls `create_agent` to spawn specialist children that run
  asynchronously in parallel (`strix/tools/agents_graph/tools.py` lines 495–545). The docstring caps
  skills per child at 5 but no cap on the number of children was found in that file or in
  `strix/core/agents.py`.
- **Known caveats:**
  - Docs warning: models "under 70B parameters, struggle". Small models "(< ~30B) emit malformed or
    text-form tool calls far more often" (local.mdx).
  - Issue #580 (open): qwen3.6:35b and deepseek-r1:70b through Ollama gave JSON-decoding and
    tool-not-found errors.
  - PR #913 (open) documents local context sizing.
  - PR #673 (open) proposes executing tool calls that arrive as plain text.

### 2.3 RedAmon (samugit83), v7.9.0, commit `73ca9d3`

- **Version note:** the paper audited 7.6.0 (`03b46b8`). The Ollama preset and the
  `openai_compatible` branch of `setup_llm` are present at both commits. Changes in between concern
  instance-level providers and Anthropic SDK handling.
- **Licence:** MIT (`README.md` line 1135). The Kali sandbox bundles WPScan under its own licence.
- **Support level: native.**
  - README line 234: "any OpenAI-compatible endpoint (Ollama, vLLM, Groq, etc.)". Line 745 lists
    Ollama among supported endpoints.
  - The provider form has a preset named "Ollama" with `baseUrl: 'http://host.docker.internal:11434/v1'`
    (REDAMON`webapp/src/lib/llmProviderPresets.ts` lines 20–22).
  - `ollama_local` is a recognised custom provider type
    (REDAMON`agentic/llm_builder.py` line 42).
- **Configuration:** in the web UI, Global Settings → LLM Providers → OpenAI-Compatible (Ollama
  preset). Then choose the `custom/<providerId>` model in project settings. A legacy env path also
  exists: prefix `openai_compat/` plus `OPENAI_COMPAT_BASE_URL`
  (REDAMON`agentic/orchestrator_helpers/llm_setup.py` lines 322–336).
- **How it calls models:** LangChain. Custom OpenAI-compatible rows build `ChatOpenAI(base_url=…,
  api_key=… or "ollama", streaming=True, stream_usage=True)` (`llm_setup.py` lines 280–320). The code
  comment says streaming is forced because "runtimes such as Ollama can otherwise leave a
  non-streaming request silent … causing an intermediary/read timeout". `validate_llm_base_url`
  allows localhost and LAN hosts and blocks cloud metadata addresses.
- **Tool calling / JSON:**
  - The main agent emits a structured JSON `LLMDecision` (`use_tool`, `plan_tools`,
    `deploy_fireteam`, …). Tool output goes into the prompt text, "not delivered through a
    provider-native structured-tool-use channel" (REDAMON`docs/readmes/README.AGENTIC_SYSTEM.md`
    lines 539, 653). So native tool calling is not required, but reliable JSON output is.
  - CypherFix triage and codefix use `llm.bind_tools(...)`
    (`agentic/cypherfix_triage/orchestrator.py` line 1341;
    `agentic/cypherfix_codefix/orchestrator.py` line 737).
  - Vision use was not checked.
- **Auxiliary model calls:**
  - Deep Think pre-step, Cypher-translator LLM for `query_graph`, LLM scope guardrail, LATS expansion
    (off by default), and report summariser (README.AGENTIC_SYSTEM.md lines 545, 607, 31, 134, 732).
  - Ten "Models by feature" (`roe_parse`, `triage`, `codefix`, `report_narratives`, `navigator`, …)
    each need a model picked per user, with "no fallback to the project's agent model"
    (`agentic/feature_models.py`). All can point at the same `custom/<id>` Ollama provider.
  - The out-of-run guardrail uses the first custom provider when one exists
    (`agentic/api.py` lines 1899–1958).
  - KB embeddings default to local sentence-transformers, or any OpenAI-compatible
    `KB_EMBEDDING_API_BASE_URL` (`.env.example` lines 50–79).
  - The AI-attack-surface module starts its own Ollama container (`ollama/ollama:latest`, model
    `qwen2.5:7b`) reached at `http://redamon-local-llm:11434`
    (`recon_orchestrator/local_llm_manager.py`). That endpoint is separate from the configured
    provider.
- **Base URL everywhere:**
  - Each provider row's `baseUrl` is used for every call made with that provider.
  - Fixed URLs exist for keyed providers: model listing from api.openai.com, api.anthropic.com and
    others (`orchestrator_helpers/model_providers.py`), but only when those keys are configured.
  - Inference: for clean capture, configure one Ollama/proxy provider only, and assign it to the
    agent and every feature.
- **Multi-agent:** fireteam is on by default. `FIRETEAM_ENABLED: True`,
  `FIRETEAM_MAX_CONCURRENT: 5`, `FIRETEAM_MAX_MEMBERS: 5` (`agentic/project_settings.py` lines
  119–122). Members cannot spawn further fireteams (README.AGENTIC_SYSTEM.md line 47).
  `MAX_ITERATIONS` defaults to 100. The default agent model is `claude-opus-4-6` (`project_settings.py`
  line 92).
- **Known caveats:** merged PRs #150 ("stream OpenAI-compatible LLM responses to avoid timeout in
  ollama cloud") and #151/#152 ("add Ollama reasoning controls"). The docs give no model-size
  guidance for the agent.

### 2.4 PentestGPT (GreyDGL), commit `e8b1bb7`

- **Licence:** MIT (`LICENSE.md`; README line 262).
- **What exists at this commit:**
  - The autonomous pipeline (`pentestgpt_agent/`, built on the external `unified-agent==0.3.0`,
    pinned to git rev `acff8ee`) drives the **Claude Code** CLI or the **Codex** CLI (PGPT`README.md`
    lines 57–63; `pentestgpt_agent/pyproject.toml` lines 11, 32).
  - The separate `pentestgpt-legacy` interactive mode talks to providers directly.
  - The tagged v1.0.0 release (2025-12-24) predates this restructure.
- **Support level, autonomous pipeline: unofficial.**
  - PentestGPT's docs for the pipeline say nothing about Ollama or base URLs. `.env.example` says
    the pipeline "uses the authenticated Claude Code or Codex CLI … no API key is read from this
    file".
  - It works through upstream features:
    1. `unified_agent/backends/claude_code.py` calls the Claude Agent SDK `query()` with
       `ClaudeAgentOptions(..., env=dict(opts.extra_env))`.
    2. The SDK starts the `claude` subprocess with `{**os.environ (minus CLAUDECODE), **options.env}`
       (`claude-agent-sdk-python` `_internal/transport/subprocess_cli.py` lines 764–768, `main` at
       `6fc539e`). So `ANTHROPIC_BASE_URL` set in the parent process reaches Claude Code.
    3. Claude Code documents `ANTHROPIC_BASE_URL` to "route requests through a proxy or gateway"
       (https://code.claude.com/docs/en/env-vars).
    4. Ollama added "Anthropic API compatibility: support for the `/v1/messages` API" in **v0.14.0**
       (release 2026-01-10, https://github.com/ollama/ollama/releases/tag/v0.14.0). Its Claude Code
       guide sets `ANTHROPIC_BASE_URL=http://localhost:11434`, `ANTHROPIC_AUTH_TOKEN=ollama`,
       `ANTHROPIC_API_KEY=""` (https://docs.ollama.com/integrations/claude-code).
  - Not wired in the current Makefile: the Docker image still installs Claude Code Router and
    `scripts/entrypoint.sh` still has a `PENTESTGPT_AUTH_MODE=local` branch. That branch routes to
    `http://host.docker.internal:1234/v1/chat/completions` (LM Studio port) with models
    `qwen/qwen3-coder-30b` and `openai/gpt-oss-20b` (`scripts/ccr-config-template.json`;
    `entrypoint.sh` lines 20, 102–105). However, the `make config` / `make connect` targets that
    wrote this mode are gone from the Makefile, and `docker-compose.yml` line 42 lists only
    "openrouter", "anthropic" and "manual". Open issue #426 says edits to the CCR template are
    ignored. Open issue #398 says the local/offline backend does not work.
  - The Codex backend could in principle use Codex's `--oss` / `oss_provider = "ollama"`
    (https://developers.openai.com/codex/config-advanced; https://docs.ollama.com/integrations/codex).
    The backend passes only MCP config overrides (`unified_agent/backends/codex.py`), so this would
    need `~/.codex/config.toml` set outside PentestGPT. Not verified.
- **Support level, legacy interactive mode: native.**
  - `pentestgpt-legacy --reasoning-model ollama:qwen3 --base-url http://localhost:11434/v1`
    (README lines 174–175, 198).
  - The registry entry is `"ollama"` with `base_url="http://localhost:11434/v1"`
    (`pentestgpt_legacy/llm/registry.py` lines 108–119). `OLLAMA_BASE_URL` can override it
    (`.env.example`).
  - This mode is human-in-the-loop, with three sessions: reasoning, parsing and generation.
- **How the pipeline calls models:** the Claude Agent SDK, which uses Claude Code's preset system
  prompt, `setting_sources=["project"]`, and optional `output_format` JSON schema; or the
  `openai-codex` SDK. In `FULL_ACCESS` mode `permission_mode="bypassPermissions"` and no tools are
  disallowed (`claude_code.py` lines 59–113).
  - Inference: `setting_sources=["project"]` means `env` blocks in `~/.claude/settings.json` are not
    loaded, so the Ollama variables must be in the process environment.
- **Tool calling / context:**
  - Claude Code needs tool use (Bash, Read, Write, MCP).
  - Ollama's Anthropic endpoint supports tools and streaming but not `tool_choice`, not
    `/v1/messages/count_tokens`, and not prompt caching
    (https://docs.ollama.com/api/anthropic-compatibility).
  - Ollama recommends "a 64k+ context window" for Claude Code.
- **Auxiliary model calls:**
  - Claude Code uses the `haiku` alias "also used for background functionality". Subagents default
    to `CLAUDE_CODE_SUBAGENT_MODEL` (Claude Code env-vars docs). With Ollama,
    `ANTHROPIC_DEFAULT_HAIKU_MODEL` / `_SONNET_` / `_OPUS_` and `CLAUDE_CODE_SUBAGENT_MODEL` must be
    mapped to the local model name. They then use the same base URL.
  - The hosted WebSearch tool is "not fully supported" through Ollama (Ollama Claude Code guide).
  - Telemetry, update checks and similar traffic go elsewhere unless
    `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` is set.
- **Multi-agent:** two PentestGPT roles, Supervisor and Executor. Each episode is a fresh provider
  session (`resume = null`), and the README says "There is no … parallel scheduler"
  (`pentestgpt_agent/README.md`). Claude Code can still spawn its own subagents inside an episode,
  because the Agent tool is not disallowed in `FULL_ACCESS`. That count is not fixed by PentestGPT.
- **Known caveats:** open issues #383 ("local llm"), #393 ("ollama connect error"), #398, #426.

### 2.5 PentAGI (vxcontrol), v2.2.0, commit `b611fbe`

- **Licence:** MIT (GitHub licence metadata).
- **Support level: native.**
  - A dedicated provider (`backend/pkg/providers/ollama/ollama.go`) and docs
    (PENTAGI`backend/docs/ollama.md`).
  - A README section "Ollama Provider Configuration" (README lines 1519–1680), covering local
    Ollama and Ollama Cloud.
  - Prebuilt configs ship at `/opt/pentagi/conf/ollama-llama318b.provider.yml`,
    `ollama-qwen332b-fp16-tc.provider.yml` and `ollama-qwq32b-fp16-tc.provider.yml`.
- **Configuration:**
  - `OLLAMA_SERVER_URL`, `OLLAMA_SERVER_API_KEY` (cloud), `OLLAMA_SERVER_MODEL`.
  - `OLLAMA_SERVER_CONFIG_PATH`: per-agent-role YAML for model, temperature and max tokens.
  - `OLLAMA_SERVER_PULL_MODELS_*`, `OLLAMA_SERVER_LOAD_MODELS_ENABLED`, `PROXY_URL`.
  - Defined in `backend/pkg/config/config.go` lines 146 and 273.
- **How it calls models:** Go, `github.com/vxcontrol/langchaingo/llms/ollama` plus the official
  `ollama/api` client (`ollama.go` lines 19–22, 227–228). These post to Ollama's native `/api/chat`
  (`vxcontrol/langchaingo` `llms/ollama/internal/ollamaclient/ollamaclient.go`), not to `/v1`. The
  HTTP client comes from `system.GetHTTPClient(cfg)` (`ollama.go` line 198).
- **Tool calling / context:**
  - Function calling is required. Agents have tool-call budgets, and the "Reflector" is "invoked when
    LLM fails to generate tool calls after 3 attempts" (README lines 498–507).
  - A `simple_json` role exists (`backend/pkg/providers/pconfig/config.go` line 147).
  - Context: "PentAGI requires models with larger context windows than the default Ollama
    configurations … PentAGI uses 110K context size". `num_ctx` must be set in a Modelfile
    (README lines 1627–1631).
- **Auxiliary model calls:**
  - Chain summarisation (`SUMMARIZER_*`), reflector, adviser/planner, enricher, memorist and
    refiner. All are agent roles served by the same provider and configurable per role in the YAML.
  - Embeddings default to `EMBEDDING_PROVIDER=openai` (`config.go` line 122), which falls back to
    the OpenAI server URL (README line 3770). For an all-local setup, set `EMBEDDING_PROVIDER=ollama`.
  - Optional Graphiti uses its own OpenAI-compatible LLM and embedder (README lines 2883–2888).
- **Base URL / proxy:** README line 885: `PROXY_URL` routes "every request to LLM and embedding
  providers and to search engines — self-hosted ones such as Ollama … included, as there is no
  `NO_PROXY` exemption". It does not cover the sandbox containers, the scraper, Graphiti, OAuth or
  Langfuse/OTel. This is the cleanest capture story of the five.
- **Multi-agent:** 13 agent option types (`primary_agent`, `assistant`, `simple`, `simple_json`,
  `adviser`, `generator`, `refiner`, `searcher`, `enricher`, `coder`, `installer`, `pentester`,
  `reflector`; `pconfig/config.go` lines 144–156). The primary agent delegates to specialists, and
  the planner produces 3–7 steps (README line 485).
- **Known caveats:**
  - Open issue #477: with local Ollama, reflector, generator, enricher and searcher "produce
    well-formed tool-call JSON as message content instead of `tool_calls`", including the documented
    default `llama3.1:8b-instruct-q8_0`.
  - PR #437 ("small-model tuning profile behind SMALL_MODEL_MODE") was closed without merging.
  - QwQ 32B FP16 "requires approximately 71.3 GB VRAM" (README).

### 2.6 Additional tools (for paper context)

- **CAI, Alias Robotics** (`aliasrobotics/cai`, `archive` branch `6dc7925`)
  - **Status:** archived. The README says "No further releases, bug fixes, security patches or
    support will be provided". The public PyPI line is frozen at 0.5.10.
  - **Ollama: native.** `docs/providers/ollama.md` sets `OLLAMA_API_BASE` and uses the `ollama/`
    prefix in `CAI_MODEL`; `ollama_cloud/` for Ollama Cloud. Models go through LiteLLM inside a fork
    of the OpenAI Agents SDK.
  - **Licence:** "MIT + Proprietary" (README badge and licence section).
  - **Caveat:** include it only as a historical reference, not as actively maintained.
- **PentestAgent, GH05TCREW** (`5bcf872`)
  - **Ollama: native.** `.env.example` line 12: `ollama/qwen2.5:7b-instruct (local Ollama)`.
    Optional `OLLAMA_BASE_URL`.
  - **Client:** LiteLLM. MIT.
  - **Modes:** `/agent`, plus `/crew`, where an orchestrator spawns specialised workers (README
    "Modes").
  - **Embeddings:** RAG embeddings default to OpenAI when `OPENAI_API_KEY` is set, otherwise local.
  - **Base-URL caveat (inference):** `pentestagent/llm/llm.py` lines 57–68 copy `OLLAMA_BASE_URL` to
    `OLLAMA_URL`, `OLLAMA_API_URL`, `LITELLM_OLLAMA_*` and `OLLAMA_HOST`, but not to
    `OLLAMA_API_BASE`, which is the variable LiteLLM reads. A non-default Ollama host or a proxy may
    need `OLLAMA_API_BASE` set directly.
- **Shannon, Keygraph** (`d72c082`)
  - **Ollama: native.** It is a documented local path. README line 397 and
    `docs/ai-providers.md` "Local and self-hosted models": describe the Ollama server as a provider in
    a Pi `models.json` passed with `--models-config`. The model is chosen with
    `SHANNON_AI_MODEL=<provider>:<model>`, the endpoint with `SHANNON_AI_BASE_URL`.
  - "Shannon uses a single unified model setting throughout a pentest".
  - Use `host.docker.internal`, not `localhost`.
  - **Licence:** AGPL-3.0.
- **Decepticon** (`BitterSecurity/Decepticon`, redirected from `PurpleAILAB/Decepticon`, `6b15092`)
  - **Ollama: native.** Auth method `ollama_local` maps every tier to
    `ollama_chat/<OLLAMA_MODEL>`. Set `DECEPTICON_AUTH_PRIORITY=ollama_local` and
    `OLLAMA_API_BASE=…` (`docs/models.md` lines 16, 40–42, 191–201).
  - All calls go through one LiteLLM proxy, which suits traffic capture.
  - **Licence:** Apache-2.0.
- **Nebula, berylliumsec** (`6f6bb82`)
  - The README says to "connect Claude, OpenRouter, Ollama, or vLLM as providers". Codex, Grok or
    Claude can also act as "harnesses".
  - **Licence:** BSD-2-Clause.
  - Code paths not checked.
- **NeuroSploit** (`JoasASantos/NeuroSploit`, redirected from `CyberSecurityUP/NeuroSploit`,
  `54d8e86`)
  - The README provider list includes `ollama` and `litellm`. MIT.
  - Code paths not checked.
- **HexStrike AI** (`0x4m4/hexstrike-ai`, `d689933`)
  - **Ollama: not applicable.** It is an MCP server exposing about 150 tools to an external AI
    client (README architecture: "AI Agent - Claude/GPT/Copilot → MCP Protocol → HexStrike MCP
    Server").
  - `requirements.txt` has no LLM SDK. Its "agents" are Python logic, and the model belongs to
    whatever MCP client drives it.
  - **Licence:** MIT.
- **Villager, Cyberspike:** excluded. No public source repository was found; it is distributed as a
  PyPI package (press reports, e.g. https://thehackernews.com/2025/09/ai-powered-villager-pen-testing-tool.html).
  Checking it would need the package to be downloaded, which this audit's rules forbid.
- **MAPTA** (`arthurgervais/mapta`) exists, but its last push was 2025-08-28 and it has 136 stars.
  It was left out as not actively maintained.

---

## 3. What this means for the open-weight campaign

**Can go on Ollama directly (configuration only):**

- **Strix:** `STRIX_LLM=ollama/<model>`, `LLM_API_BASE=<proxy or Ollama>`.
  - Also set `STRIX_CONTEXT_FALLBACK_TOKENS` to the real `num_ctx`.
  - Set `STRIX_MAX_CONTEXT_IMAGES=0` for text-only models.
  - Leave `PERPLEXITY_API_KEY` and `EXA_API_KEY` unset so `web_search` cannot reach a hosted LLM.
  - Set `STRIX_TELEMETRY=false`.
- **PentAGI:** `OLLAMA_SERVER_URL` (or `PROXY_URL`), a per-role YAML, `EMBEDDING_PROVIDER=ollama`,
  Graphiti off, and models rebuilt with `num_ctx` ≈ 110k. Expect tool-call-as-text failures on small
  models (issue #477).
- **RedAmon:** a single OpenAI-compatible provider whose base URL is the proxy, assigned to the agent
  and to every "Model by feature".
  - Keep the AI-attack-surface scan off: its judge uses a separately spawned Ollama.
  - Keep KB embeddings local.
  - Turn the fireteam off, or record its member count.
- **hackingBuddyGPT:** `llm.model=ollama_chat/<model>` with `OLLAMA_API_BASE=<proxy or Ollama>`
  exported. Do not rely on `llm.api_base`. Do not use the RAG extra.

**Works without code changes, but unofficially:**

- **PentestGPT agentic:** export `ANTHROPIC_BASE_URL`, `ANTHROPIC_AUTH_TOKEN=ollama`,
  `ANTHROPIC_API_KEY=""`, `ANTHROPIC_MODEL` and `ANTHROPIC_DEFAULT_{HAIKU,SONNET,OPUS}_MODEL`,
  `CLAUDE_CODE_SUBAGENT_MODEL` and `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` in the process that
  runs `pentestgpt-agent`, then pass `--backend claude --model <ollama model>`. This needs
  Ollama ≥ 0.14.0. The paper should label it a configuration PentestGPT does not support, and note
  that the server rejects `tool_choice` and has no token-count endpoint.

**Needs a small patch for clean configuration:**

- **hackingBuddyGPT, `src/hackingBuddyGPT/utils/llm.py`, `LiteLLM.raw_completion`:** pass
  `api_base=self.api_base` when the user set it explicitly. The default is OpenRouter, which is
  presumably why the line was commented out. With the patch, `llm.api_base` works for Ollama and for
  the proxy. Until then, `OLLAMA_API_BASE` is the workaround.
- **PentestAgent, `pentestagent/llm/llm.py`:** also set `OLLAMA_API_BASE` from `OLLAMA_BASE_URL`, or
  document that users must set it. This is an inference and was not run.

**Cannot be pointed at Ollama by itself:** none of the five paper tools. HexStrike has no model of
its own. Villager could not be checked.

---

## 4. Claims not verified

1. Whether LiteLLM's `ollama_chat` handler uses `litellm.client_session`. This decides whether
   hackingBuddyGPT's `llm.proxy` option captures Ollama traffic.
2. Whether `tool_choice="required"` (hackingBuddyGPT web-API use cases) is accepted, dropped or
   rejected on LiteLLM's `ollama_chat` route.
3. Whether LiteLLM's `get_model_info` returns a context size for `ollama_chat/*` models, which
   would make Strix's 200k fallback irrelevant.
4. Whether Claude Code's JSON-schema `output_format` (used by PentestGPT's Supervisor) depends on
   `tool_choice`, which Ollama's Anthropic endpoint does not support.
5. Whether Claude Code's WebFetch makes non-model calls to Anthropic hosts that would bypass
   `ANTHROPIC_BASE_URL`. The env-vars page did not say.
6. Whether PentestGPT's Codex backend can be pointed at Ollama through `~/.codex/config.toml`.
   Remote-host `base_url` problems are reported in https://github.com/openai/codex/issues/8240.
7. Whether the Docker `local` (Claude Code Router) mode in PentestGPT still starts correctly at
   `e8b1bb7`.
8. Whether RedAmon sends screenshots to the model (Playwright MCP), and whether its in-run scope
   guardrail always uses the run's model.
9. Whether PentAGI's primary agent delegates to one specialist at a time or several in parallel,
   and whether any PentAGI agent sends images to the model.
10. Decepticon, Nebula and NeuroSploit: no code paths read beyond docs. Their base-URL coverage,
    tool-calling needs and sub-agent counts are unverified. CAI's code paths were not read either.
11. Whether Strix's `DEDUPE_LLM_API_BASE` is really overridden by the global `litellm.api_base` for
    Ollama routes (read from LiteLLM code, not tested).
12. Villager's provider handling: there is no public source, and the package was not downloaded.
