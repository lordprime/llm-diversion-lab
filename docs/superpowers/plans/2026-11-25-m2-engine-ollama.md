# M2 Simulation Engine and Ollama Route Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The harness runs a real agent against an open-weight model served by Ollama on the CISPA VM. Every run is in the three-arm design, records full telemetry, and stays contained.

**Architecture:**
- **Model gateway.** A small, auditable passthrough proxy, `control/gateway`, sits between each cell's LLM tap and Ollama.
  - It authenticates each run by a per-run key and allows only that run's model.
  - It allows only inference endpoints, and streams bytes through unchanged so the tap's capture stays exact.
- **Ollama.** It runs as a digest-pinned container with the NVIDIA runtime, on an internal network shared only with the gateway.
- **Runs.** They become triplets (control / neutral / instruction) with a block id.
- **The runner** derives telemetry after each run and ships it with the evidence.
- **The CISPA VM** uses the `sysbox` host profile.

**Tech Stack:** Python 3.12 + uv, Starlette and httpx (streaming), pydantic v2, SQLAlchemy/Alembic, Docker Compose, Ansible, the NVIDIA Container Toolkit, Ollama, Sysbox.

**Spec:**
- `docs/paper/register-triage.md`: decided items T1, T2, S1, I1, L7.
- `docs/OLLAMA_SUPPORT_AUDIT.md`: wire formats, endpoints, per-tool caveats.
- The memory note "ollama-first-campaign": the CISPA layout. One PVE VM runs everything; Ollama is a container on the NVIDIA runtime, on an internal network that only the gateway joins, with no published ports; the GPU is an H100 80 GB at worst, an H200 141 GB likely.
- `docs/DEPLOYMENT.md` §0.6 (the sysbox profile) and §0.2 (firewall).
- `docs/DEVELOPMENT_PLAN.md` §3 (APIs), §5.3 (self-test).

**Place in the roadmap:**
- Before this: phase 1, M1a GOAT platforms (`docs/superpowers/plans/2026-11-24-m1a-goat-platforms.md`).
- After this: phase 3, the agent adapters and the open-weight campaign (at least 5 end-to-end runs per tool per model), with a results package for the professor.
- Tasks 1–3 below don't touch M1a's files, so they can run alongside M1a's last tasks. Tasks 4–6 start after M1a Task 8 merges, because they share `control/runner/selftest.py`, `experiments/` and the scheduler.

## Global Constraints

- All of M1a's global constraints still apply:
  - single-author commits with no AI attribution;
  - push after every task;
  - `core.filemode=false` executable bits;
  - shipped target files never name the study;
  - images are built only in CI and pinned by digest in `deploy/images.lock`;
  - no third-party attack tools on the workstation.
- **The tap's evidence stays byte-exact.** The gateway never rewrites a request or response body. If it refuses a request, it answers with its own error, and that error is recorded like any other response.
- **Cells reach models only through tap → gateway.** Neither the gateway nor Ollama publishes a port on the host. A cell that tries Ollama directly must fail, and the self-test proves it.
- **Only inference endpoints are allowed through the gateway:**
  - `POST /api/chat`, `POST /api/generate`, `POST /v1/chat/completions` and `POST /v1/messages`;
  - `GET /api/tags`, `POST /api/show` and `GET /v1/models`, read-only, filtered to the run's model;
  - everything else is denied, including `/api/pull`, `/api/push`, `/api/create`, `/api/copy`, `/api/delete`, `/api/embed*` (unless the run's config allows embeddings), `/api/ps` and `/api/version`.
- **Each run may use only its configured model id(s)**, compared exactly after one normalisation rule: an `ollama/` or `ollama_chat/` prefix added by LiteLLM-based clients is stripped. Any other model gives 403, recorded.
- **Models are pulled only by an admin command** (`labctl models pull <id>`), never during a run. `labctl doctor` lists the pulled models with their digests, and an experiment file pins each model by Ollama digest.

## Review Focus

- **A model swap mid-run:** an agent asking for a different model, or for the same name with a different tag, must get 403, and the run is flagged.
- **Streaming pass-through:** NDJSON (Ollama) and SSE (OpenAI and Anthropic) must stream chunk by chunk with no buffering of the whole body, or agents time out. The bytes the tap records must equal Ollama's bytes.
- **Management endpoints:** a cell must never pull, delete or create models, or list other runs' models.
- **The gateway admin API** (registering run keys) is reachable only from the control plane, never from a cell network.
- **Three arms:** the neutral arm carries the tag, so the control arm is the only tag-free one. The contamination checks must still catch a tag leaking into control.

---

### Task 1: Model gateway (`control/gateway`)

**Files:**
- Create: `control/gateway/__init__.py`, `control/gateway/policy.py` (endpoint and model policy), `control/gateway/keys.py` (the per-run key registry), `control/gateway/app.py` (the Starlette app: a streaming proxy plus the admin routes), `control/gateway/__main__.py`
- Modify: `deploy/compose/control-plane.yml` (a `gateway` service from the control image, on a `models` internal network and on the cells' gateway address), `control/runner/runner.py` (register the run key before the agent starts and revoke it after), `control/runner/cell_spec.py` (give the agent its run key through the agent env)
- Test: `tests/gateway/test_policy.py`, `tests/gateway/test_app.py` (with a fake Ollama upstream that streams NDJSON and SSE), `tests/runner/test_runner.py`

**Interfaces:**
- `class EndpointPolicy`: `decide(method: str, path: str) -> Decision`, where `Decision` is `ALLOW | ALLOW_FILTERED | DENY`, plus a reason.
- `class ModelPolicy(allowed: frozenset[str])`: `check(body: bytes, path: str) -> str | None` returns the normalised model id, or None when the request carries no model field. It raises `ModelRefused` for any other model.
- `class RunKeys`: `register(run_id, key_sha256, models, expires_at)`, `revoke(run_id)`, `lookup(key) -> RunGrant | None`. Kept in memory and mirrored to Postgres table `gateway_grants` (migration 0010), so a gateway restart keeps working grants.
- **Admin API** on a separate listener, bound to the control-plane network only:
  - `POST /admin/grants` and `DELETE /admin/grants/{run_id}`;
  - authenticated by a control-plane secret from `lab.env`.
- **Proxy:**
  - `ANY /{path}`: the key comes from `Authorization: Bearer`, `x-api-key` or `api-key` (whichever the client sends);
  - the upstream is `LAB_OLLAMA_URL`;
  - streaming uses `httpx.AsyncClient.stream`, with the response yielded chunk by chunk and hop-by-hop headers stripped;
  - each refusal is answered as `{"error": {"type": "gateway_refused", "reason": ...}}`, status 403 (or 404 for a denied endpoint).

- [ ] **Step 1:** Write the failing tests:
  - `test_denies_management_endpoints` (every path in the deny list, every method);
  - `test_model_must_match_grant` (the exact id, a prefix-normalised id, a different tag such as `qwen3:32b` vs `qwen3:14b`, a missing model field, a body that isn't JSON);
  - `test_streams_ndjson_and_sse_unbuffered` (the first chunk arrives before the upstream finishes);
  - `test_bytes_pass_through_unchanged` (sha256 of the upstream bytes equals the client's);
  - `test_unknown_or_revoked_key_is_401`;
  - `test_admin_api_rejects_without_secret`;
  - `test_tags_and_show_filtered_to_grant`;
  - `test_upstream_down_is_502_not_hang`.
- [ ] **Step 2:** Run the tests and confirm they FAIL.
- [ ] **Step 3:** Implement. Keep the proxy core small (about 300 lines) and readable: it is a security boundary.
- [ ] **Step 4:** Run the four gates.
- [ ] **Step 5:** Commit `feat(gateway): per-run model gateway for Ollama with an inference-only policy`, then push.

### Task 2: Ollama service, model management and containment checks

**Files:**
- Create: `deploy/ansible/roles/nvidia/` (NVIDIA driver check and Container Toolkit, digest- or version-pinned; the `nvidia` runtime registered in Docker), and `deploy/compose/models.yml` (the `ollama` service).
- Modify:
  - `deploy/images.lock` (ollama/ollama pinned by digest);
  - `deploy/release.sh` (bring up `models.yml` on hosts with `gpu: true`);
  - `control/cli/` (`labctl models pull|list|rm`, admin only, talking to Ollama through the control plane, never through a cell path);
  - `control/cli/doctor.py` (the GPU is visible in the ollama container; pulled models and digests; a cell network cannot reach Ollama);
  - `control/runner/selftest.py` (a containment check: a cell probe to the ollama service name and address must fail);
  - `deploy/hosts.example.yml` (`gpu: true`, `ollama_models_volume`).
- Test: `tests/deploy/` (role lint, compose render), `tests/cli/test_models.py`, `tests/runner/test_selftest.py`

**Interfaces:**
- **The `ollama` service:**
  - `image: ${OLLAMA_IMAGE}` (digest);
  - `runtime: nvidia` with `NVIDIA_VISIBLE_DEVICES=all`;
  - `OLLAMA_HOST=0.0.0.0:11434` inside its network only;
  - `OLLAMA_KEEP_ALIVE=-1`, so the campaign keeps one model warm;
  - `OLLAMA_NUM_PARALLEL` and `OLLAMA_CONTEXT_LENGTH` come from host config;
  - networks: `models` only (internal: true), shared with `gateway`;
  - volume: `ollama_models:/root/.ollama`;
  - **no `ports:`**.
- **The experiment file** pins models as `{id: "qwen3:32b", ollama_digest: "sha256:…", num_ctx: 65536}`. The runner refuses to start if `labctl models list` doesn't show that digest.

- [ ] **Steps:**
  1. Write failing tests:
     - the compose render has no published ports, and `models` is internal;
     - doctor fails without a GPU;
     - `labctl models pull` refuses to run from inside a cell context;
     - the self-test check fails when a probe reaches Ollama.
  2. Implement.
  3. Run the gates.
  4. Commit `feat(models): Ollama service on the NVIDIA runtime with admin-only model pulls`, then push.

### Task 3: Telemetry in the run pipeline

**Files:**
- Modify:
  - `control/runner/runner.py`: after collection, call `control.telemetry.extract.load_calls`, then `summarise`, then `write_derived` into the run's derived folder, and ship the files as artifacts `telemetry/*`. A telemetry failure never invalidates a run; it records `telemetry_error`.
  - `control/db/tables.py` with migration 0011: a `run_telemetry` table holding the summary fields — calls, agents, agents_source, peak_input_tokens, the token totals, reasoning_chars, calls_with_reasoning, single_call_threads, largest_thread_calls, branch_points, persona_splits, telemetry_version.
  - `control/api` Results API: `GET /v1/runs/{id}/telemetry`.
  - `control/cli`: `labctl run telemetry <run>` and `labctl export telemetry --experiment <id> --format csv|md`.
- Test: `tests/runner/test_runner.py`, `tests/db/test_migrations.py`, `tests/cli/test_labctl.py`

- [ ] **Steps:**
  1. Write failing tests:
     - a run with recorded Ollama NDJSON gets a telemetry row and artifacts;
     - broken telemetry leaves the run valid and records the error;
     - the export lists one row per run with the headline columns.
  2. Implement.
  3. Run the gates.
  4. Commit `feat(runner): derive and store run telemetry after every run`, then push.

### Task 4: Three-arm design (T1, T2, S1). Starts after M1a Task 8.

**Files:**
- Modify:
  - `control/core/models.py`: `Arm` becomes `CONTROL | NEUTRAL | INSTRUCTION`. `RunManifest` invariant: only CONTROL is tag-free; NEUTRAL and INSTRUCTION both carry the tag and placements. `block_id` replaces `pair_id`; keep `pair_id` as a deprecated alias in the API for one release.
  - `control/runner/experiment.py`: `ExperimentArms(control, neutral: NeutralArmSpec, instruction: InstructionArmSpec)`. The neutral payload has one template per surface, matched within 5% on lines, characters and tokens, with the same tag, URL and markup.
  - `control/runner/schedule.py`: triplets, randomised order within a block, seeded.
  - `control/runner/render.py`: `forbidden_tags_for` (a control run forbids its block's tags).
  - `control/labeler/funnel.py`: contamination rules for three arms.
  - `control/db` with migration 0012 (the arm enum and block_id).
  - `experiments/selftest.yaml`.
- Test: the scheduler, models, render, labeller, migration and self-test tests.

**Interfaces:**
- `PayloadSpec.match_tolerance: float = 0.05`.
- `check_neutral_match(instruction: PayloadSpec, neutral: PayloadSpec, tokenizer: Tokenizer) -> list[Mismatch]`, where `Tokenizer` is a protocol. The default implementation counts with a pinned `tiktoken`-free byte-pair estimate (`len(text.encode()) / 4`); a real tokenizer can be plugged in later.
- The experiment hash covers both payloads.

- [ ] **Steps:**
  1. Write failing tests:
     - the triplet schedule is balanced, deterministic and seeded;
     - a neutral run without a tag is rejected;
     - a control run with a tag is rejected;
     - a neutral payload outside 5% is rejected, with the measured numbers;
     - a tag from the block's neutral or instruction run found in control raises ContaminationError.
  2. Implement.
  3. Run the gates.
  4. Commit `feat(design): three arms with matched neutral text and block ids`, then push.

### Task 5: Injector differential-equivalence check (I1). After Task 4.

**Files:**
- Modify: `control/runner/selftest.py` (a new check family `equivalence`), `cell/injector/preflight.py` (fetch helpers).
- Test: `tests/runner/test_selftest.py`

**Behaviour:** for every placement path on every target, fetch the page four ways:
1. directly from the target;
2. through the injector with no plan;
3. through the injector in the neutral arm;
4. through the injector in the instruction arm.

Require:
- (1) and (2) byte-identical;
- (3) and (4) identical to (2) outside the recorded insertion spans;
- the same status, the same Content-Type and cookie flags, and no change to CSP, SRI, redirects or absolute URLs;
- Content-Length and the encoding consistent with the body.

The results go into the self-test report as a table.

- [ ] **Steps:** failing tests with a fake target that varies each property → implement → gates → commit `feat(selftest): differential-equivalence check for the injector` → push.

### Task 6: Tokenisation-safe tags (L7). After Task 4.

**Files:**
- Modify: `control/core/tokens.py` (`new_tag()` draws two words from a frozen list of 2048 common lowercase English words plus two digits, joined by a hyphen, for example `river-candle-42`; `TAG_PATTERN` updated), every tag regex user (`control/core/tags.py`, the labeller, the injector), and `schemas/`.
- Create: `control/core/wordlist.txt` (frozen, hashed into the code with a test). Words must not include any banned study word.
- Test: `tests/core/test_tokens.py`, plus the existing tag tests.

**Behaviour:**
- The tag space is 2048² × 100, about 4.2e8. That is enough for per-run tags, and a retry redraws on collision within an experiment.
- Every M1a test that builds tags by hex pattern must be updated.

- [ ] **Steps:**
  1. Write failing tests:
     - the format;
     - no banned words;
     - draws are unique across 10⁵;
     - tags survive JSON, HTML-entity and URL encoding in `find_tags`.
  2. Implement.
  3. Run the gates.
  4. Commit `feat(tags): tokenisation-safe word tags`, then push.

### Task 7: CISPA VM bring-up and acceptance (I3)

**Files:**
- Modify:
  - `deploy/hosts.example.yml` (a `cispa1` entry: `isolation: sysbox`, `gpu: true`);
  - `deploy/ansible/` (run the sysbox and nvidia roles on the VM profile);
  - `docs/DEPLOYMENT.md` (§0.6 with the CISPA record).
- No secrets and no host addresses are committed; `deploy/hosts.yml` stays local.

**Steps (with the user, on the VM):**
1. `./deploy/bootstrap.sh cispa1`.
2. `./deploy/release.sh cispa1 --tag <M2 tag>`.
3. `labctl models pull` for the chosen models.
4. `labctl doctor` passes: GPU visible, Sysbox running, Docker 29.
5. `labctl selftest` passes on all three targets. That covers containment (internet, LAN, the host, and a cell trying Ollama directly), and the stub-model run plus one real-model smoke run through the gateway.
6. Record the results in DEPLOYMENT §0.6, commit and push.

This is register item I3: it verifies Sysbox with Docker 29 on the real host.
