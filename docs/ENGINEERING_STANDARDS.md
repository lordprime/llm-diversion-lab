# Engineering Standards

**Companion to:** [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md)
**Applies to:** every line of code, config and script in this repository.

These standards exist for one reason: every number in the paper must be **traceable, reproducible and defensible**. A bug in the harness is a bug in the science. When a rule here conflicts with convenience, the rule wins. When a rule here conflicts with a reviewer's well-argued exception, write the exception down as an ADR.

---

## 1. Principles

| Principle | What it means here |
|---|---|
| **Evidence first** | Raw evidence is **write-once**: LLM bytes, serve logs, pcaps, oracle verdicts. Everything derived from it, such as labels and statistics, is **recomputable** from the raw artifacts plus a versioned labeller. No step may edit raw evidence. |
| **Determinism where we control it** | Seeds are recorded and schedules are generated from them. Labellers are pure functions from artifacts to labels. Experiment configs are frozen by content hash. Commercial model endpoints are the only accepted source of non-determinism, and they are logged, not hidden. |
| **Ports and adapters** | The domain core (experiments, runs, placements, funnel, labels) knows nothing about Docker, LiteLLM, mitmproxy or any framework. Everything external sits behind an interface: `AgentAdapter`, `CellBackend`, `ArtifactStore`, `OracleClient`, `LLMGateway`, `Notifier`. That is how a new agent, provider or Kubernetes backend gets added without touching the core. |
| **KISS / YAGNI** | Build what the pilot needs. Leave seams (the interfaces above) for what the paper needs later. Don't build those features early. One process type per job, Postgres as the queue, server-rendered HTML. |
| **Fail fast, fail loud** | Invalid config, a missing image, a probe failure or a model mismatch stops the run *before* tokens are spent, with a message that says exactly what is wrong. No silent fallbacks, anywhere. |
| **Idempotency** | Every write to the Collector API and every deployment step can be safely repeated. Re-running `labctl pilot`, `release.sh` or an Ansible play converges and never duplicates. |
| **Least privilege** | Run cells have no internet and no database credentials. Services run as non-root where the image allows it. Secrets live only on the server and only in the processes that need them. |
| **Twelve-factor config** | Secrets come from the environment (`.env`). Behaviour comes from versioned YAML. Nothing is hard-coded per machine. |

---

## 2. Languages, tooling and versions

| Area | Choice | Enforced by |
|---|---|---|
| Control plane, adapters, labeller, analysis, catcher, injector/tap addons | **Python 3.12**, managed with **uv** (`uv.lock` committed) | CI uses `uv sync --frozen` |
| Formatting and lint | **ruff** (`ruff format`, `ruff check` with rule sets E, F, I, B, UP, S, SIM, RUF) | pre-commit + CI |
| Types | **mypy `--strict`** on `control/`, `cell/`, `agents/` | CI |
| Data models | **pydantic v2**: the single source of truth for every event, manifest and API payload. JSON Schemas in `schemas/` are *generated* from the models, never hand-edited. | CI checks the generated schemas are up to date |
| Database | PostgreSQL. **SQLAlchemy 2** (typed) + **Alembic** migrations. No ad-hoc DDL. | CI runs migrations up/down on an empty DB |
| HTTP APIs | **FastAPI**, with an OpenAPI spec published at `/openapi.json` and checked into `docs/api/` per release | CI diffs the spec |
| Web UI | Jinja2 + HTMX + Plotly.js; no build step; JS kept to small, documented modules | — |
| Shell | **Bash** only for thin deploy and ops wrappers: `set -Eeuo pipefail`, `shellcheck` clean, `shfmt` formatted, `--help` on every script | pre-commit + CI |
| Server provisioning | **Ansible** (idempotent roles, `--check` dry-run supported) | `ansible-lint` in CI |
| Containers | Dockerfiles linted with **hadolint**. Base images pinned **by digest**. Multi-stage builds. Non-root `USER` unless the target must run as root (documented). | CI |
| Statistics | statsmodels / NumPy / SciPy in Python; R `lme4` in a pinned container for mixed models | analysis job version recorded on every result |

---

## 3. Code structure and style

1. **Module boundaries follow the plan's architecture:**
   - `control/`: api, runner, scheduler, labeler, analysis, web
   - `cell/`: injector, tap, catcher, oracle glue
   - `agents/<framework>/`
   - `targets/<goat>/`

   Cross-boundary imports go through the interfaces in `control/core/ports.py`, never into another module's internals.
2. **Pure core, impure edges.** Functions in `core/` take data and return data: schedule generation, manifest rendering, token derivation, funnel labelling, statistics. All I/O lives in adapters. This makes the core trivially unit-testable.
3. **Explicit errors.** A small hierarchy (`LabError` → `ConfigError`, `ProbeFailed`, `ModelMismatch`, `AdapterError`, `OracleError`, …) is mapped to run statuses in exactly one place. No bare `except:`. No swallowed exceptions. Retries only for idempotent operations, using bounded exponential back-off with jitter.
4. **Naming.** Domain words come from the paper and the plan: `surface`, `placement`, `arm`, `pair_id`, `access`, `visible`, `uptake`, `outcome`. One concept, one name, everywhere: code, DB columns, API fields, UI labels.
5. **Functions** do one thing and stay short enough to read without scrolling. Public functions have docstrings stating *what* and *why*, not *how*.
6. **Comments** explain intent, research constraints ("must match the paper's E1 definition") or non-obvious decisions with an ADR link. Never commented-out code.
7. **Configuration objects are immutable** (frozen pydantic models). An experiment object, once hashed, never changes in memory.
8. **Time.** UTC everywhere, with timezone-aware datetimes. Monotonic clocks for durations. The server runs chrony, and every event records both wall-clock and monotonic offsets from run start.
9. **IDs.** ULIDs for experiments and runs (sortable, unique). Tags and callback tokens come from the HMAC scheme in the plan §3.4. Nothing is derived from auto-increment integers that differ across environments.

---

## 4. Testing

| Layer | What is tested | Tooling | Runs in CI |
|---|---|---|---|
| **Unit** | Core logic: schedule randomisation and pairing, manifest rendering, HMAC tokens, tag search after JSON-unescaping, funnel labelling rules, budget projection, statistics helpers | pytest, **hypothesis** for property tests (e.g., "every injected P2 run has exactly one matched control") | every push |
| **Golden-file** | Labellers on recorded fixture runs: real captured artifacts with known expected labels | pytest + fixtures in `tests/fixtures/runs/` | every push |
| **Contract** | Each `AgentAdapter` against a **fake framework** that emits that framework's native log format; the Collector API against its schemas | pytest | every push |
| **Integration** | One real cell on a CI runner with Docker: injector + tap + catcher + DVGA + scripted agent + **stub LLM** (no tokens) | pytest + Docker | every push to `main`, and nightly |
| **Self-test** | The full funnel on all 3 GOATs, containment probes, negative cases (an app crash must *not* score as success; a control cell must contain no tag) | `labctl selftest` | nightly + before every release |
| **Statistics validation** | Analysis code recovers known effects from **simulated** run data (planted effect sizes, clustered by target) | pytest | every push |
| **Smoke (live)** | Haiku 5.5, one run per adapter, real provider | `labctl smoke` | manual / pre-pilot only (costs money) |

**Rules:**
- **No live LLM calls in automated tests.** CI never needs a provider key.
- **Coverage:** ≥ 90% line coverage on `control/core/` and the labeller; ≥ 75% overall. A drop fails CI.
- **Test-first for the labeller and statistics.** Their tests are written *before* the implementation, from the plan's pre-registered definitions, so the code is checked against the definition rather than the other way round.
- Every bug fix ships with a regression test that fails without the fix.

---

## 5. Version control and review

- **Git from day one.** Trunk-based development on `main`, with short-lived feature branches and small pull requests (one concern each).
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`), imperative mood, one logical change per commit. **Commits are authored by the team member doing the work; no tool-attribution trailers.**
- **Review:** every PR needs one approving review. PRs that touch the labeller, statistics, payloads, placement maps or the experiment schema need a review **by a second author of the paper**, because these encode the pre-registration.
- **Protected `main`:** CI green, review approved, no force-push.
- **Target repositories (GOAT forks and the CVE-Bench fork):**
  - `upstream` branch frozen at the pinned upstream commit;
  - `lab` branch with one concern per commit (`seed:`, `hygiene:`, `oracle:`, `offline:`, `build:`), tagged `lab-vN`;
  - the harness pins them by commit (see DEVELOPMENT_PLAN §4.1);
  - attack frameworks stay upstream plus small patch files, never forks.
- **Releases:** SemVer tags (`v0.1.0` …). The release notes list changes to schemas, labeller versions and adapter versions. The deployed tag is recorded on every run.
- **Pre-registration freeze.** When an experiment is frozen, its YAML, payload templates and placement maps are committed and tagged (`prereg/<experiment>`). The hash in the database must match the tag, or the run refuses to start.

---

## 6. CI pipeline (stages)

1. **Lint:** ruff, mypy, shellcheck, shfmt, hadolint, ansible-lint, yamllint.
2. **Unit + golden + contract + stats tests**, with coverage gates.
3. **Schema and API drift checks:** generated JSON Schemas and the OpenAPI spec match what is committed.
4. **Build images:** GOATs, agents and harness components, all pinned. **SBOM** with syft and a **vulnerability scan** with grype or trivy. Critical vulnerabilities in *harness* images fail the build. GOATs and attack frameworks are *expected* to contain vulnerabilities, so they are scanned and reported only.
5. **Integration test:** one cell, stub LLM.
6. **Nightly:** the full self-test on a CI runner or on the lab server, in a maintenance window.
7. **On tag:** publish images to the server's local registry, attach SBOMs, write release notes.

---

## 7. Security and supply chain

- **Secrets:** only in the server's `.env` (mode 0600, owned by the `lab` user) and in process environments. Never in git, logs, artifacts, error messages or the UI.
  - Log scrubbing redacts anything matching provider key patterns.
  - Virtual keys per run limit the damage of any leak.
- **Dependencies:**
  - Python dependencies are locked with hashes (`uv.lock`), images are pinned by digest, and third-party downloads are verified by checksum (Sysbox `.deb`, Drupal tarball MD5/SHA, drush phar).
  - **LiteLLM is used only as the official image pinned by digest.** Earlier PyPI releases were malicious.
- **Container posture:** no `--privileged` outside the Sysbox runtime; no published ports from cells; `no-new-privileges` where compatible; resource limits on every container.
- **Server:** SSH keys only, no root login, firewall default-deny inbound, nothing exposed publicly, automatic security updates for everything *except* pinned Docker, Sysbox and kernel packages (those are upgraded in maintenance windows).
  - **Documented exception, LXC profile only:** the homelab container (CT 111) is provisioned as `root`, with key-only login (`PermitRootLogin prohibit-password`) over Twingate, because it was set up that way. Root inside the unprivileged LXC maps to an unprivileged user on the Proxmox host. A VM (the sysbox profile) uses a non-root sudo user with `PermitRootLogin no`, and `site.yml` enforces it. See [DEPLOYMENT.md §0.1](DEPLOYMENT.md).
- **Offensive tooling hygiene:** attack frameworks and GOATs run only inside cells. The workstation and CI runners never run an attack framework against anything except a cell.

---

## 8. Observability built in

- **Structured JSON logs** (structlog) with the **`run_id`, `experiment_id` and component** fields on every line inside a run's scope.
- **Prometheus metrics** from every service (see [TRACKING.md](TRACKING.md) §3).
- **Health endpoints** (`/healthz` liveness, `/readyz` readiness) on every service.
- **Audit log:** every state-changing API call is recorded with who, what, when and the config hash.

---

## 9. Documentation

- **ADRs** in `docs/adr/NNN-title.md` for every decision that a newcomer might question. The first set:
  - 001 Sysbox per-cell daemons
  - 002 mitmproxy for the injector and tap
  - 003 LiteLLM passthrough and the drop-params policy
  - 004 Postgres as the job queue
  - 005 Server-rendered web UI
  - 006 Ansible for provisioning
  - 007 Planted prompts only in the proxy, never in GOAT source
  - 008 Oracle hidden from agents
- **A README per top-level module:** what it does, how to run its tests, its interfaces.
- **Runbooks** in `docs/runbooks/`: deploy, roll back, restore from backup, rotate keys, handle a stuck run, handle a containment-probe failure.
- **The plan documents** (this set) are versioned with the code. A change to the design changes the documents in the same PR.

---

## 10. Definition of Done (every PR)

- [ ] Code follows the module boundaries and naming above; ruff, mypy and shellcheck are clean.
- [ ] Tests added or updated (unit, plus golden or contract where relevant); coverage gates pass.
- [ ] Schemas, OpenAPI and migrations regenerated or added, with no drift.
- [ ] Logs carry `run_id`; new failure modes map to a run status; new metrics are documented in TRACKING.md.
- [ ] No secrets, no unpinned images, no unverified downloads.
- [ ] Docs updated: module README, ADR if a decision was made, runbook if operations changed.
- [ ] For changes to the labeller, payloads, placements or the experiment schema: second-author review, and a new labeller or schema version.
