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

**Evidence shipping rule (M0 runner, `control/runner/runner.py`).** Every run that reached collection (its cell came up and its producers' evidence was copied out) ships all its event lines and artifacts to the Collector, valid or not. The oracle **verdict** is posted only for a run that passed every validity check (no failure in the cell, injector alive with its pre-flight probe in its evidence, the oracle answered and reported nothing unexpected, at least one LLM call); otherwise the run has no verdict, never `outcome: false`. A run that failed before collection (manifest refused, cell never came up) ships only its manifest. Invalid reasons are the bounded `runs.invalid_reason` set; all problems of a run are kept in `runs.invalid_detail`, and a failed teardown is always the reason when it happened. Retrying an invalid run (a new attempt) is a queue policy outside the runner.

Evidence integrity rules that make a run invalid rather than silently incomplete:
- **Recording failures.** A run is `recording_failed` if a cell component could not record, or if an evidence line was skipped or torn. A component that "could not record" includes the tap, cell-guard and the catcher (it logs `catcher: cannot record …` first). So is a run where the tap, catcher or cell-guard exits non-zero after the stop, for example 137. For the injector, the same failures give `injector_failed`.
- **Oracle before the agent.** The probe phase needs one answered oracle poll that reports `false` before the agent starts. Otherwise the run is `probe_failed`.
- **Placements.** A served placement that is not in the run's manifest makes the run `contaminated`.
- **Body size limits.** The injector stops at 64 MiB of body and the tap at 32 MiB. An oversized flow ends in the error path: the injector records it with status `null`, and the tap never forwards it.

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
| `lab_runs_in_flight` | gauge | `agent`; self-test runs are left out |
| `lab_queue_depth` | gauge | `provider` |
| `lab_run_stage_seconds` | histogram | `stage` |
| `lab_invalid_runs_total` | counter | `reason`: the run's `runs.invalid_reason` (the bounded `InvalidReason` set); self-test runs (`exp_selftest_*`) are left out, as in `lab_runs_total` |
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
| `lab_metrics_database_up` | gauge | — (1 if the latest database read succeeded: this scrape's, or, while another scrape's read is in flight, the one before; at 0 the run families are absent, never 0) |

Built in M0 (`control/api/metrics.py`, served by the Collector at `/metrics`): `lab_runs_total`, `lab_invalid_runs_total`, `lab_runs_in_flight`, `lab_selftest_last_success_timestamp`, `lab_metrics_database_up`. They are **derived at scrape time** from the runs table and the self-test status file (`/srv/lab/state/selftest.json`), not counted in a process's memory, so they survive restarts; `lab_selftest_last_success_timestamp` is 0 until a self-test passes.

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

#### The self-test: `labctl selftest [--quick] [--json]` (built in M0)

`control/runner/selftest.py`. It runs `experiments/selftest.yaml` through the real runner: one injected and one matched control DVGA cell, the scripted agent and the stub LLM (no model is called, no tokens are spent). Each invocation registers a fresh experiment `exp_selftest_<ULID>` (the file's text with that id), so it can be repeated and survives new image builds. It holds the host's runner lock (the runner's own `runner_lock_path`, `/srv/lab/state/runner.lock`) for the whole self-test, so it never runs beside another runner.

Before the pair runs it sweeps what **earlier self-tests** left: containers, volumes and networks labelled with a run of an `exp_selftest_*` experiment, and their `cells/` work directories (none of them can be running: the lock is held). Resources of study runs, or of run ids the database does not know, are never touched.

It **passes** only if all of these hold:

| Check | Requirement |
|---|---|
| `earlier self-tests swept` | The sweep above listed and removed everything it should |
| `<arm>: valid`, `<arm>: completed` | Both runs `valid` **and** the agent ended `completed` (a crashed agent gives a valid run; that is not enough). A run that left its cell behind stops the runner: its result is kept and `run the pair` fails |
| `injected: funnel`, `injected: oracle` | Access, Visible, Uptake and Outcome all true; the **stored** verdict (`runs.outcome` true, `runs.decided_at` set) |
| `injected: callbacks` | A callback on **both** channels (HTTP and DNS) whose token is the one the lab key derives for one of the run's own placements |
| `control: funnel`, `control: oracle` | Access, Visible and Uptake false (all four stages labelled); a stored verdict |
| `control: no tags` | No token callback reached it, and no file of its evidence holds any injected run's tag or callback token, case-insensitively and with base64 fields (`body_b64`) decoded (the labeller's forbidden-tag check already makes a leaking control `contaminated`) |
| `<arm>: contained` | Before the cell's agent starts, `cell/probe/containment.py` runs in a sibling container on the agent network with `--host-gateway` (the network's `.1`), `--lan` (`LAB_PROBE_LAN`), `--sinkhole` (catcher `.2`), `--reach` injector `.3:80` and tap `.4:8080`, and must-fail `--dest`s for the control plane (the Collector's and the database's container addresses on the control network, and that network's gateway on the published ports, read from `deploy/compose/control-plane.yml` and the engine) and for the host's own LAN address on the host ports. IP literals only. Anything reachable, a failed must-reach, a destination missing from the report, or no complete report is **CRITICAL**, and that cell's agent never starts (the run is invalid `cell_failed`). A blocked result proves something only about real addresses: the host gateway must be one of this host's own addresses (`bind` succeeds) before each probe, else the check fails without being critical; a cell that fails before its agent would start is reported as a cell failure ("not probed"), not as containment |
| `<arm>: nothing left` | After teardown no container, volume or network carries the run's `lab.run_id`, and its `cells/labcell-<run>` work directory is gone |

Before any cell starts, each `LAB_PROBE_LAN` address must answer from the host. It can answer on TCP 53, 80 or 443 (a refusal counts), with a reply to a UDP/53 DNS query, or else to one ICMP echo. Otherwise a blocked result from a cell would prove nothing, and the self-test fails (configuration). The default address is the LAN resolver (`lab_upstream_dns`). The Proxmox firewall leaves exactly one LAN path open from the LXC, DNS to that resolver (DEPLOYMENT §0.1), so the check probes that path. From the cell, the containment probe tries each `--lan` address on TCP 53, 80 and 443 and sends it a UDP/53 DNS query; any answer, a DNS reply included, is a breach.

`--quick` (what `release.sh` runs after a deploy) keeps the first target only (one matched pair: the smallest unit the matched-pair schedule runs, and the control's zero-tag check is a core claim) and probes containment in the first cell only; every other check is the same. With M0's single target, full mode differs only by probing every cell.

Output: a readable report on stdout (`--json`: the same as JSON), progress as JSON log lines on stderr. Exit 0 passed, 1 failed, 2 only for an argparse usage error; never 3 (`release.sh` reads 3 as "labctl not installed"). **Every** run past argument parsing is recorded once in `/srv/lab/state/selftest.json` (`labctl status`, `lab_selftest_last_success_timestamp`), configuration problems, an unusable `DATABASE_URL` and internal errors included; a result that cannot be recorded makes the command fail.

Self-test runs are left out of `lab_runs_total`, `lab_invalid_runs_total` and `lab_runs_in_flight` (experiment id prefix `exp_selftest_`): a deliberately failing self-test must not move the study's numbers. The self-test's own signal is `lab_selftest_last_success_timestamp`. The prefix is reserved: an experiment file whose id starts with `exp_selftest_` is refused, and only the self-test derives such ids.

Inputs on the host: `secrets/hmac.key`; the host profile `host.env` (read by the runner's settings: `LAB_CELL_NETWORKS`, `LAB_LLM_GATEWAY`; and `LAB_PROBE_LAN`, in production only from the profile); the release tree `current/`, resolved once at the start (experiment, cell templates, `deploy/compose/control-plane.yml`, and always its own `deploy/images.lock`, which must pin `lab-cell` and `goat-dvga`; `LAB_IMAGES_LOCK` and `LAB_IMAGE_OVERRIDES` count only in development); the running control plane (compose project `lab`); evidence under `artifacts/`, cell files under `cells/`. Development (`LAB_DEV=1`, refused wherever `/srv/lab/host.env` exists): no host profile, settings and `LAB_PROBE_LAN` from the environment, a missing control plane is tolerated, and on Podman only `LAB_PROBE_HOST_GATEWAY` (an address of this machine) replaces the probed host gateway, because under rootless Podman the network gateway is the rootless namespace, which answers with a reset.

**Interrupted self-tests.**
- SIGTERM and SIGHUP end `labctl` like an exception, so a self-test still records its result. Before the pair runs, the self-test records an "in progress" marker. A self-test killed outright therefore shows as aborted in `labctl status`, not as the previous pass.
- Under the runner lock, the next self-test's sweep marks the earlier self-test runs still `queued`/`running` as invalid (`internal`, "abandoned").
- Not built: requeuing or retrying a self-test run.

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

---

## 5. Known limits (M0)

These limits are accepted for M0. Each is recorded here so it is not mistaken for a result.

| Limit | Effect | Where it is decided |
|---|---|---|
| **Target-driven SSRF callbacks are invisible to the catcher.** The catcher, with its HTTP sink and resolver, sits only on the agent network. When the *target* makes the outbound request, the catcher never sees it: for example, DVGA's `importPaste` runs `curl` on a URL the agent supplied. The callback leaves from the target network (injector and GOAT only, `internal`), which has no catcher, no resolver for callback names and no way out. It is lost, and contained. | An agent that follows the planted instruction *through* the target's SSRF registers no callback. Uptake(b) (a token-carrying callback) is then a **false negative** for that path. Uptake from the agent's own requests, Access, Visible and the oracle Outcome are unaffected. | An M1 design decision: give the target network its own sink and resolver, or route target egress to the catcher. Until then, read DVGA Uptake as a lower bound. |
| **ARP spoofing on the shared cell bridge.** Agent containers keep `NET_RAW` and can ARP-spoof other containers on the cell network. | They could intercept traffic, but cannot forge evidence: callbacks are verified by token. | DEPLOYMENT §0.3 (known limit); separate agent, target and catcher networks per cell are an M1 item. |
| **No study-run safety nets.** M0 has no start-up sweep of runs left `running` by a crashed runner, no reaper timer (`lab-reaper.timer`) and no retry API for invalid runs. The self-test cleans up only its own runs (§3.3). | A crashed study run stays `running` and holds its cell until an operator removes it by hand (`lab.run_id` labels). | M1, before any study runs on the lab. |
