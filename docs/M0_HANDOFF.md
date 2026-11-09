# M0 handoff: where work stands and how to continue

Updated on 2026-11-09. Plan: `docs/superpowers/plans/2026-11-07-m0-skeleton.md` (17 tasks).
The detailed ledger with every ruling and review is kept locally in `.superpowers/sdd/2026-11-07-m0-skeleton/progress.md` (git-ignored). This file is the summary.

## 1. State of `main`

**Every M0 code task is merged and pushed** (head `ab6ef9b` before the final fix pass): Tasks 1–16, the hardening batch H, the docs batch D and the CI image jobs. Only Task 17 is left, the acceptance run on the real host (CT 111).

| Task | What it delivers |
|---|---|
| 1–11 | Repo scaffolding, models and event contract, Postgres and migrations, the Collector API, the funnel labeller, injector, tap, catcher, stub LLM, and the DVGA and CVE-Bench fork changes |
| 12 | The DVGA GOAT image. Its oracle answers only on a root-only Unix socket. |
| 13 | cell-guard, the deny-by-default Docker socket proxy |
| 14a | Experiment config, the matched-pair scheduler, the manifest, payload and token rendering |
| 14b | The runner (cell lifecycle, oracle polling, shipping, labelling), the compose cell backend, `deploy/compose/cell.dvga.yml`, the `lab-cell` image, the scripted agent, and migrations 0004–0005 |
| 15a | The containment probe, scrape-time Prometheus metrics, and structlog redaction |
| 15b-1 | labctl (`doctor`, `status`, `runs ls`, `run show`), the control-plane compose with pinned Postgres, the per-release control image `lab/control:<tag>`, labctl installed per release with a pinned host uv, and a DB password generated on the host |
| 15b-2 | `labctl selftest`: the self-test pair with the containment probe and end-to-end checks (TRACKING §3.3), and `LAB_PROBE_LAN` in the host profile |
| 16 | The Ansible LXC bootstrap, the fail-closed nftables firewall, and the release, rollback and secrets scripts |
| H, D | The hardening batch and the docs batch |
| CI | `build-images.yml` builds and smoke-tests `goat-dvga`, `lab-cell` and `control`, and pushes them to `ghcr.io/lordprime/<name>` |

The forks' `lab` branches are pushed: CVE-Bench at `9304c0e`, DVGA at `c587128`.

Tests: about 2,800 passed when 15b-2 merged. That count includes the self-test pair end to end in real cells on rootless Podman, where a real `labctl selftest --quick` passed 14/14. Check the Actions tab for the latest CI result before you build images.

## 2. The final review and its fix pass (in progress)

Four reviewers checked the whole branch, one per area: control plane, runner and self-test, cell components, and deploy/CI. None found a Critical. The fixes run as three parallel fixers on local worktrees, which the controller merges into `main` when they are done (plan: `.superpowers/sdd/2026-11-07-m0-skeleton/final-fix-plan.md`).

| Fixer | Area | Main changes |
|---|---|---|
| F1 | control plane, runner, self-test | Migration 0006 widens the method and qtype columns, and the Collector neutralises NUL characters. An unknown placement makes a run `contaminated`. The `exp_selftest_` prefix is reserved. Errors are redacted. There is one answered oracle poll before the agent starts. Torn or skipped evidence and a non-clean component exit make a run `recording_failed`. SIGTERM and SIGHUP are recorded, and stale self-test rows are swept. Self-test runs are left out of `lab_runs_in_flight`. The self-test's LAN check also covers port 53. |
| F2 | cell components | The catcher logs `catcher: cannot record …` on a recording failure, which invalidates the run. cell-guard allows only listed query keys per operation (no `checkpoint`/`checkpoint-dir`). Body limits: injector 64 MiB, tap 32 MiB. The probe adds TCP 53 and a UDP/53 query to its LAN checks. |
| F3 | deploy, CI, docs | The rollback swap never drops the former live database, and the manual swap is one transaction. `bootstrap --check` skips the uv download. Docker keeps overlay2 (containerd snapshotter off) and is pinned to **29.8**, because the repository no longer carries 29.1.x. CI holds a read-only token. The quickstarts match the release flags, and the docs cover public GHCR packages, a Known limits section (TRACKING §5) and the Task 17 runbook. |

## 3. What's left, in order

1. **Merge the final fix pass** (F1, F2, F3) into `main`. Run the full gates (§5) on the merged result and push. CI must be green.
2. **Build and pin the images (you).**
   - Run `build-images.yml` on `main`. All three jobs must be green.
   - **Make the three GHCR packages public**: `goat-dvga`, `lab-cell`, `control`. They hold no secrets. The host never logs in to a registry, so private packages fail to pull with `unauthorized`. Check each one with an anonymous pull by digest (DEPLOYMENT §0.5).
   - Paste the `lab-cell` (`infra`) and `goat-dvga` (`target`) entries into `deploy/images.lock`. Commit, then tag `v0.1.0`.
   - Until these pins exist, a release needs `--skip-selftest`, and Task 17 cannot complete. The control image needs `--allow-build` until the compose file switches to the pinned digest, which is a separate reviewed change.
3. **Task 17 on CT 111**: follow [`docs/TASK17_RUNBOOK.md`](TASK17_RUNBOOK.md) (P0–P8, with a pass criterion for every step). State on 2026-11-09:
   - **Done:**
     - SSH to `root@192.168.1.145` works.
     - The kernel modules are persisted on the Proxmox host (`/etc/modules-load.d/llm-lab.conf`).
     - Snapshot `pre-m0` is taken.
     - `deploy/hosts.yml` exists. Its `lab1` vars carry `docker_ce_minor: "29.8"`, which is now also the role default.
   - **First bootstrap:** it failed closed at "Check a usable docker-ce version exists". Docker's noble repository now lists 29.5.2–29.9.3, with containerd.io 2.4.x. This is fixed by the 29.8 pin. Re-run it from runbook step 7.
   - **The Proxmox firewall for CT 111 is not configured.** Task 17 goes ahead without it, because cell containment rests on the in-LXC layers that P5 checks. Enabling it is recommended before any study run (decision below).

## 4. Decisions still open for you

- **Target-driven SSRF callbacks are invisible to the catcher** (a new design seam; TRACKING §5).
  - The catcher sits only on the agent network. When an agent drives DVGA's `importPaste` SSRF, the *target* makes the outbound request, from the internal target network, so no callback is recorded.
  - Uptake(b) is then a false negative on DVGA's signature vulnerability.
  - The M1 options are a sink and resolver on the target network, or routing target egress to the catcher. Until then, DVGA Uptake is a lower bound.
- **Enable the Proxmox firewall on CT 111** (DEPLOYMENT §0.1): inbound 22/443 from the Twingate connector only, and outbound with no LAN except DNS to the resolver. The self-test's LAN check is designed for this layout. It probes resolver:53.
- **When to switch the control plane to the pinned `control` image**, which drops `--allow-build`.
- **Study-run safety nets for M1:** a start-up sweep of runs a crashed runner left `running`, a reaper timer, and a retry API for invalid runs. None exists in M0 (TRACKING §5).
- **Deferred minor items from the final review**, each with a later home:
  - multipath-route gateways in the firewall role check (H(2));
  - a root-owned release tree;
  - per-release image pruning;
  - tag-pinned actions in `ci.yml` (`build-images.yml` is SHA-pinned);
  - pinning the BuildKit syntax frontend;
  - the Python patch pin (3.12.13 on the host vs. the image);
  - the gitleaks licence;
  - 15b-1 M4/M5 (hatchling hash pin, rollback to a pre-.venv release).
- Earlier open items:
  - DVGA branding and logo;
  - the upstream note text seeded into about 540 pastes;
  - the size of a keyword-less search response (about 3,000 pastes, about 1 MB);
  - RedAmon's defence-off arm;
  - DEVELOPMENT_PLAN.md §10, decision 1 (budget) and decisions 4–7, 9 and 10.

## 5. Working rules that carry over

- **Commits:** every commit has a single author, with no `Co-Authored-By` line and no mention of an AI.
- **Never commit:** `.superpowers/`, `docs/paper/`, `deploy/hosts.yml`, secrets, or the lab HMAC key. The key must never enter a cell.
- **Executable bits:** this checkout has `core.filemode=false`. Add executable bits with `git update-index --chmod=+x <file>`, and check that `git ls-files -s` shows 100755.
- **Gates:**
  - `LAB_REQUIRE_TOOLS=1 uv run pytest -q`; shellcheck, shfmt and ansible-lint run inside `tests/deploy`;
  - `uv run ruff check .`;
  - `uv run ruff format --check .`;
  - `uv run mypy control cell agents`;
  - some tests need `uv sync --all-extras` (mitmproxy).
- **gitleaks:** synthetic test values go in the allow-list in `.gitleaks.toml`.
- **Timing tests:** keep inputs at or below `MAX_INPUT_CHARS`. Use `_assert_fast` (best of 3, with a 3 s limit) and the retrying scaling check.
- **Third-party attack frameworks:** never run them on the workstation.
