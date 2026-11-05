# Tracking Interfaces

**Companion to:** [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md), [DEPLOYMENT.md](DEPLOYMENT.md)

The lab runs unattended on a remote server. This document specifies every interface for following what it does:

- the **research** view: what the experiments are finding;
- the **pipeline** view: what is queued, running, failing;
- the **machine** view: whether the server is healthy;
- the **notifications** that reach people when nobody is looking.

---

## 1. One identity scheme for everything

Every log line, metric exemplar, database row, artifact path and UI page carries the same identifiers, so any view links to any other.

| ID | Form | Scope |
|---|---|---|
| `experiment_id` | ULID + content hash of the frozen YAML | One experiment definition |
| `schedule_id` | ULID | One schedule entry |
| `run_id` | ULID | One run (one cell, one agent session) |
| `pair_id` | ULID | An injected run and its matched control |
| `placement_id` | `<run_id>:<surface>` | One planned placement |
| `tag`, `callback_token` | HMAC-derived (plan §3.4) | Detect visibility and callbacks |
| `release` | git tag + SHA | Harness version that ran it |
| `images_lock` | hash of `images.lock` | Exact images used |

---

## 2. Lifecycle states (what "tracking" tracks)

**Experiment.** Possible states, all changes recorded in the audit log:

| State | Can move to |
|---|---|
| `draft` | `registered` (YAML stored and hashed) |
| `registered` | `scheduled` (optional), `running` |
| `scheduled` | `running` |
| `running` | `paused` (by a person, or automatically on budget overrun), `completed`, `aborted` |
| `paused` | `running` |

**Run.**

| Phase | Steps, in order |
|---|---|
| Normal path | `queued` → `provisioning` (cell up) → `probing` (health, hygiene, placement) → `running` (agent active, oracle polled) → `collecting` → `shipping` → `labelling` → `done` |
| Terminal classification | `valid` or `invalid:<reason>` |
| End status | `completed` \| `budget_exhausted` \| `timeout` \| `refused` \| `crashed` |

Every transition is a timestamped row (`run_transitions`), so per-stage durations and stuck runs can be found directly.

**Schedule.** `enabled` ⇄ `paused`, then `removed`. Each firing is recorded with the runs it enqueued.

---

## 3. Interfaces

### 3.1 Research tracking: the Results website

Served through Caddy, reached privately over Twingate (later, optionally, through Cloudflare Tunnel behind Cloudflare Access). These pages extend the plan's §6 with what a remote, multi-person team needs.

| Page | Shows |
|---|---|
| **Experiments** | All experiments with state, progress bar (valid runs / planned), spend vs budget, release, pre-registration tag; start, pause or resume for operators |
| **Experiment overview** | Live run feed (SSE), per-phase progress (P0 → P1 → P1b → P2), invalid-run reasons, refusal rate, ETA from measured throughput |
| **Funnel heatmap** | surface × agent (× model, × target): Access, Visible, Uptake and Outcome rates with Wilson intervals |
| **Funnel waterfall** | Per agent: Access → Visible → Uptake → Outcome |
| **Effects** | Risk difference forest plot, with matched pairs and cluster-bootstrap CIs (exploratory in the pilot) |
| **Callbacks** | Beacon hits by surface, style and leak category; each links to the run timeline at the callback |
| **Cost** | Spend, tokens, steps and time per arm, agent and model; burn rate vs budget |
| **Refusals** | Refusal rate by model, agent and phase of the attack |
| **Run detail** | The merged timeline: placement serves, agent HTTP, LLM calls (exact bytes, tag highlighted, gateway rewrites shown), tool calls, callbacks, oracle polls. Also the manifest (planned vs realised), images, release and links to raw artifacts. |
| **Queue** | Queued, running and stuck runs; per-provider concurrency and rate-limit headroom; re-queue an invalid run |
| **Schedule** | Upcoming firings, windows, history of past firings; add, pause or remove |
| **Deployments** | Release history (tag, SHA, who, when, self-test result); the experiments each release ran |
| **Audit log** | Every state change: who, what, when, config hash |
| **Admin** | Users and roles (`viewer`, `operator`, `admin`), API tokens, notification channel test button |

Every page footer shows the deployed release, `images.lock` hash, server time and the last self-test result.

### 3.2 Pipeline and machine tracking: Grafana (ops dashboards)

Prometheus scrapes **node-exporter** (host), **cAdvisor** (containers) and the **lab services' own `/metrics`**. Loki collects all container logs, labelled with `service` and `run_id`. The dashboards are provisioned from `ops/grafana/` (versioned in git).

| Dashboard | Panels |
|---|---|
| **Lab overview** | Runs in flight, queue depth, completions/hour, valid vs invalid, spend burn rate vs budget, ETA |
| **Cells** | Per-cell CPU, RAM, disk I/O; provisioning time; cell age (finds stuck cells); orphan count |
| **Providers** | Requests/min, latency, 429/5xx rates, refusal rate, tokens and dollars by provider and model; rate-limit headroom |
| **Host** | CPU, RAM, swap, load; disk free on the data and artifact disks; XFS usage; network egress (should be gateway only); clock offset |
| **Containment** | nftables drop counters for cell subnets (should be zero); pcap non-tap egress attempts per run; containment-probe results |
| **Logs** | Loki explorer pre-filtered by `run_id` / `experiment_id` |

**Service metrics** (Prometheus names, all labelled with `experiment_id` where meaningful):

| Metric | Type | Labels |
|---|---|---|
| `lab_runs_total` | counter | `status`, `end_status`, `agent`, `target`, `arm` |
| `lab_runs_in_flight` | gauge | `agent` |
| `lab_queue_depth` | gauge | `provider` |
| `lab_run_stage_seconds` | histogram | `stage` |
| `lab_invalid_runs_total` | counter | `reason` |
| `lab_llm_requests_total` | counter | `provider`, `model`, `http_status` |
| `lab_llm_refusals_total` | counter | `model`, `category` |
| `lab_llm_spend_usd_total` | counter | `provider`, `model` |
| `lab_llm_tokens_total` | counter | `direction`, `cached` |
| `lab_gateway_rewrites_total` | counter | `kind` (e.g. `dropped:temperature`) |
| `lab_model_mismatch_total` | counter | `agent` |
| `lab_callbacks_total` | counter | `protocol`, `leak_category` |
| `lab_budget_remaining_usd` | gauge | — |
| `lab_selftest_last_success_timestamp` | gauge | — |
| `lab_orphan_cells` | gauge | — |

### 3.3 Command-line tracking: `labctl`

`labctl` works on the server and, with `--remote <host>`, from the workstation. Every command has `--json` output for scripting.

| Command | Output |
|---|---|
| `labctl status` | Experiments, queue, in-flight runs, spend vs budget, disk, last backup, last self-test, release |
| `labctl exp ls` / `labctl exp show <id>` | Experiment list and details, per-phase progress |
| `labctl runs ls [--exp] [--status] [--agent] [--target]` | Filterable run list |
| `labctl run show <run_id>` | Run summary + funnel labels + oracle verdict + artifact paths |
| `labctl run timeline <run_id>` | The merged timeline in the terminal |
| `labctl logs <run_id> [-f]` | All component logs for a run, live while it runs |
| `labctl watch` | Live terminal dashboard (in flight, queue, recent completions, alerts) |
| `labctl schedule ls` | Upcoming firings |
| `labctl export <exp> --format parquet\|csv` | Tidy tables (runs, labels, llm_calls, callbacks) for notebooks and the paper |
| `labctl doctor` / `labctl selftest` | Environment and pipeline verification |

### 3.4 Programmatic tracking: the APIs

| API | Use |
|---|---|
| **Results API** (read-only, plan §3.3 D) | Funnel, effects, cost, callbacks, refusals, run timelines, an SSE stream |
| **Control API** (plan §3.3 C) | Experiments, schedules, runs, re-queue, self-test |
| **Export endpoint** `GET /v1/export/{experiment_id}?format=parquet` | Snapshots for analysis notebooks. Each export is stamped with the labeller version and data snapshot time, so every figure in the paper cites the exact export it came from. |

All of them use bearer tokens scoped by role. The OpenAPI spec is published per release.

### 3.5 Notifications (push)

Alertmanager (for metric alerts) and the control plane (for lifecycle events) send to the channels configured in `lab.env`. All channels are optional, and several can be set:
- `NOTIFY_WEBHOOK_URL` (Slack, Discord, Mattermost or generic JSON);
- `NOTIFY_NTFY_TOPIC`;
- `NOTIFY_SMTP_*` (email).

| Event | Severity | Trigger |
|---|---|---|
| Experiment started / phase finished / completed | info | Lifecycle |
| **Experiment paused on budget** | **warning** | Projection exceeds `LAB_BUDGET_USD` |
| Spend at 50% / 80% / 100% of budget | info / warning / critical | Spend gauge |
| **Invalid-run rate > 10%** over the last 20 runs | warning | Counter ratio |
| **Queue stalled** | critical | No run completed within 2 × run timeout while the queue is non-empty |
| **Self-test failed** (nightly or pre-experiment) | critical | Lifecycle |
| **Containment alert** | critical | nftables drop counter for cell subnets > 0, non-tap egress seen in a pcap, or a containment probe succeeded |
| Model mismatch detected | warning | `lab_model_mismatch_total` increases |
| Provider 429/5xx storm | warning | Error rate > 20% over 5 min |
| Refusal spike | info | Refusal rate > 50% for a model over the last 20 runs |
| Disk < 15% free | critical | node-exporter |
| Orphan cells > 0 for 30 min | warning | `lab_orphan_cells` |
| Backup failed / not run in 26 h | warning | Backup timer |
| Clock offset > 50 ms | warning | chrony exporter |

**A containment alert also pauses the queue automatically.** No new run starts until an operator acknowledges it with `labctl ack <alert_id>`.

### 3.6 Audit and provenance

- **`audit_log` table:** actor, action, target, before and after state, config hash, timestamp. Shown on the Audit page and exportable.
- **`deployments` table:** every release, with self-test results.
- **Every run records** `release`, `images_lock`, adapter version and capability sheet, model ID and effort, gateway route type, labeller version, and the pre-registration tag.

From any number on a results page you can follow the links to the exact runs, artifacts, code and images that produced it.

---

## 4. Build order for tracking

| Milestone | Tracking delivered |
|---|---|
| M0 | Structured logs with `run_id`; `/metrics` on the runner and collector; `labctl status`, `runs ls`, `run show`; node-exporter + Prometheus + one Grafana "Lab overview" dashboard; webhook notifications for self-test failure and containment |
| M1 | Run detail page (timeline); Cells and Containment dashboards; Loki |
| M2 | Experiments, Queue, Schedule and Deployments pages; Providers dashboard; `labctl watch`, `logs -f`; budget alerts |
| M3 | Funnel heatmap and waterfall, Effects, Callbacks, Cost and Refusals pages; `labctl export`; full alert set |
| M4+ | Multi-provider breakdowns; OIDC login; optional distributed tracing (OpenTelemetry → Tempo) if per-stage latency debugging needs it |
