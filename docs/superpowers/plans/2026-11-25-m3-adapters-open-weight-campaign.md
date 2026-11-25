# M3 Agent Adapters and Open-Weight Campaign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every pentest tool that can reach Ollama runs complete end-to-end tests against the three GOATs on open-weight models served on the CISPA VM. Each tool runs at least 5 times per model, target and arm. The outcome is a results package the CISPA professor can read before any frontier-model run is approved.

**Architecture:**
- **One adapter per framework** behind the existing adapter contract (DEVELOPMENT_PLAN §2.3: describe, prepare, start, wait, collect, teardown).
  - Each adapter configures its framework to send every model call to the cell's LLM tap, which forwards to the M2 gateway and then to Ollama.
  - Each adapter switches off every side channel the Ollama audit found.
  - Where the framework exposes them, each adapter reports its sub-agent identities, so telemetry agent counts become exact (`agents_source="adapter"`).
- **Campaign:** a single experiment definition expands to tool × model × target × arm × repetition.
- **Results:** a deterministic exporter builds the professor's package from evidence alone.

**Tech Stack:** Python 3.12 + uv; each framework's own runtime in its own pinned agent image (Python, Go or Node); Docker Compose; the M2 gateway and Ollama; GitHub Actions → GHCR.

**Spec:**
- `docs/OLLAMA_SUPPORT_AUDIT.md`, §3 "What this means for the open-weight campaign": per-tool settings, patches and side channels.
- `docs/DEVELOPMENT_PLAN.md`: §2.2 roster, §2.3 adapter contract, §2.4 containment for agents that spawn containers (cell-guard), §9 pilot discipline.
- The memory note "ollama-first-campaign": at least 5 runs per tool; record agent counts, context used and reasoning; the prof sees open-weight results before frontier runs.
- M2 plan: gateway, Ollama, telemetry in the runner, three arms.

**Prerequisites:** M1a and M2 merged, and the CISPA VM accepted (M2 Task 7).

## Global Constraints

- All M1a and M2 constraints still apply.
- **Every model call goes through the tap.**
  - Each adapter's capability sheet lists every model-calling code path in its framework. Each listed path must be shown, by a smoke run with a recording stub, to hit the tap.
  - A framework call that bypasses the tap is a blocker: patch it or disable the feature, never ignore it.
- **Side channels:**
  - **Strix:** keep `PERPLEXITY_API_KEY` and `EXA_API_KEY` unset; set `STRIX_MAX_CONTEXT_IMAGES=0` for text-only models; `STRIX_TELEMETRY=false`.
  - **RedAmon:** turn the AI-attack-surface judge off (it spawns its own Ollama); keep KB embeddings local; set the fireteam size explicitly and record it.
  - **PentAGI:** `EMBEDDING_PROVIDER=ollama`; Graphiti off.
  - **PentestGPT agentic:** `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`.
  - **hackingBuddyGPT:** pass `OLLAMA_API_BASE`, and patch `llm.py` to honour `api_base`.
- **Support labels:** a tool reached through an unofficial route (PentestGPT agentic via Claude Code's Anthropic API) is labelled `support: unofficial` in its capability sheet and in every result row. The paper reports it separately.
- **Context window:** each model's `num_ctx` is pinned in the experiment file and must meet the framework's documented minimum (Strix 16–32k, Claude Code 64k+, PentAGI about 110k). Otherwise the cell is marked `unsupported`, never run with a silently smaller context.
- **Patches:** small, kept as patch files applied at image build, never forks (DEVELOPMENT_PLAN §2.3). Each is listed in the capability sheet.
- **Fixed limits per run,** identical across arms and frozen before the first run: wall-clock timeout, max turns mapped to each framework's own setting, and a token budget enforced by the gateway in place of a dollar budget.
- **No real targets.** Agents only ever see the GOAT cell's addresses, and egress canaries prove it per run.

## Review Focus

- **A framework silently falling back** to a hosted endpoint when the local model errors (retry-with-default-provider logic).
- **Tool calls returned as plain text** by small models: the framework may loop, crash or "complete". Each case must end in a classified end state (completed, budget, timeout, crashed, refused, or a new `tool_format_failure`), never as a silent success.
- **Sub-agent and container spawning:** frameworks that start their own containers must go through cell-guard, never get the real Docker socket.
- **The reasoning trace** must be captured for models that expose it (gpt-oss, DeepSeek-R1 distills, Qwen3 thinking), including the `<think>`-prefilled form.
- **Resumability:** a 500+ run campaign must survive a host reboot or a runner crash without losing or duplicating runs.

---

### Task 1: Adapter base and the capability sheet

**Files:**
- Create: `agents/base.py` (an `Adapter` ABC with describe/prepare/start/wait/collect/teardown, a `CapabilitySheet` pydantic model, and an `EndStateMapper`), plus `agents/sheets/` (one YAML per framework).
- Modify: `control/runner/cell_spec.py` (`AGENT_SPECS` built from adapters), `control/runner/runner.py` (calls the adapter lifecycle; passes adapter agent ids to telemetry).

**Interfaces:**
- `CapabilitySheet`:
  - framework, version, commit, image digest;
  - support level `native | openai_compatible | unofficial | none`;
  - wire format(s);
  - `model_call_paths: list[str]`;
  - `side_channels_disabled: dict[str, str]`;
  - `min_num_ctx: int`;
  - `sub_agents: Literal["none","fixed","dynamic"]`;
  - `agent_id_source: str | None`;
  - patches list;
  - `max_turns_knob: str`.
- `Adapter.agent_ids(collected: Path) -> dict[int, str] | None` maps tap call seq to a sub-agent id when the framework's own logs allow it.
- New end state `tool_format_failure`: the framework gave up because the model's tool calls didn't parse. It is a valid outcome and never counts as success.

- [ ] **Steps:**
  1. Failing tests: the sheet schema validates the five audit entries; a run refuses to start when the model's `num_ctx` is below the sheet's `min_num_ctx` (end state `unsupported`); the end-state mapping table is covered.
  2. Implement.
  3. Gates.
  4. Commit `feat(agents): adapter base and capability sheets`.
  5. Push.

### Tasks 2–6: One adapter per framework (parallel, one agent each)

The same shape for each of: **2 Strix**, **3 PentAGI**, **4 RedAmon**, **5 hackingBuddyGPT**, **6 PentestGPT agentic** (unofficial route).

**Files:** `agents/<name>/adapter.py`, `agents/<name>/Dockerfile` (pinned by digest; patches applied at build), `agents/<name>/patches/*.patch`, `agents/sheets/<name>.yaml`, `agents/<name>/ci/{build.sh,check.sh}`, `tests/agents/test_<name>.py`.

**Done when:**
- The image builds in CI.
- A smoke run against the stub model shows every model call path from the sheet hitting the tap.
- A smoke run with Ollama on the CISPA VM completes end to end on one GOAT with evidence complete: telemetry, verdict and pcap.
- Every side channel the audit lists is shown disabled, by a test that would fail if it were enabled.
- `agent_ids()` is implemented where the framework exposes sub-agents (Strix child agents, the RedAmon fireteam, PentAGI roles); otherwise it returns None and the sheet says why.

- [ ] **Steps per adapter:**
  1. Failing tests: config rendering; the side-channel switches; end-state mapping from the framework's own exit signals; `agent_ids` from a recorded log fixture.
  2. Implement.
  3. CI image build.
  4. Smoke runs.
  5. Commit and push.

### Task 7: Campaign definition and runner

**Files:**
- Create: `experiments/campaign-openweight-v1.yaml`.
- Modify: `control/runner/experiment.py` (an `agents × models` cross-product with per-pair `unsupported` pruning from the sheets), `control/runner/schedule.py` (interleaving by model to keep one model warm: blocks grouped per model, randomised within the group), and `control/cli` (`labctl campaign plan|start|status|resume`).

**Behaviour:**
- **The matrix:** tool × model × target × arm × repetitions, with repetitions ≥ 5.
- **`labctl campaign plan`:** prints the matrix, the pruned cells with reasons, and the run count.
- **Resumable:** the queue lives in Postgres, and a restart resumes without duplicating a run.
- **Models are switched only between model groups,** and `OLLAMA_KEEP_ALIVE` keeps the current one loaded.
- **The model list is configuration.** The user picks the final models (candidates: Qwen3/Qwen3-Coder, gpt-oss, DeepSeek, Llama/Mistral), sized for the GPU: an H100 80 GB at worst. Each model gets a pinned `num_ctx`.

- [ ] **Steps:**
  1. Failing tests: matrix expansion and pruning; grouping by model keeps arms balanced within each block; resuming after a simulated crash runs each remaining run exactly once.
  2. Implement.
  3. Gates.
  4. Commit and push.

### Task 8: Results package for the professor

**Files:**
- Create: `control/results/` (an exporter) and `labctl results package --campaign <id> --out <dir>`.

**Output, all derived from evidence and deterministic:**
- `runs.csv`: one row per run, with every telemetry and verdict field from M2 Task 3 plus `support` and `end_state`.
- `summary.md`, with these tables:
  - **The support matrix:** tool × model, with supported / unsupported / unofficial and the reason.
  - **Per tool × model × target × arm:** n, effect rate and mechanism rate with Wilson 95% intervals, and the end-state counts.
  - **Funnel counts:** Access, Visible (tag and fingerprint), Uptake, Outcome, with denominators.
  - **Telemetry medians and IQRs:** calls, agents (marking whether inferred or from the adapter), peak context, tokens, reasoning chars, tool calls.
  - **Consistency across the ≥5 repetitions:** each cell's success count and its spread. This is what the professor asked about.
- `reasoning/`: one readable trace per run, from telemetry's reasoning.jsonl.
- `manifest.json`: the campaign hash, image digests, model digests, the telemetry and labeller versions, and the git commit.
- Pilot wording rules from DEVELOPMENT_PLAN §9.4 apply: the development targets are descriptive only, with no prevention claims.

- [ ] **Steps:**
  1. Failing tests: deterministic output on a fixture campaign; Wilson intervals; a refusal to mix telemetry versions; an unofficial-support row marked in every table.
  2. Implement.
  3. Gates.
  4. Commit and push.

### Task 9: The open-weight campaign (with the user)

1. Confirm the model list and the `num_ctx` for each model with the user.
2. Pull the models: `labctl models pull`.
3. `labctl campaign plan`, reviewed with the user (run count, expected duration).
4. `labctl campaign start`, then monitor; `labctl campaign resume` after any interruption.
5. `labctl results package`, then review it with the user before it goes to the professor.
6. Record the campaign in `docs/DEPLOYMENT.md` and in a campaign log, then commit and push.
