# M0 handoff: where work stopped and how to continue

Stopped on 2026-11-07. Plan: `docs/superpowers/plans/2026-11-07-m0-skeleton.md` (17 tasks).
The detailed ledger with every ruling and review is local only, in `.superpowers/sdd/2026-11-07-m0-skeleton/progress.md` (git-ignored); this file is the summary.

## 1. State of `main` (pushed, head `692cb73`)

Done, reviewed and merged: Tasks 1–13, 14a, 15a and 16, plus two batches of follow-up fixes.

| Task | What it delivers |
|---|---|
| 1–11 | Repo scaffolding, models and event contract, Postgres and migrations 0001–0003, Collector API, funnel labeller, injector, tap, catcher, stub LLM, DVGA and CVE-Bench fork changes |
| 12 | DVGA GOAT image. The oracle answers only on a root-only Unix socket. `build-images.yml` builds it, and `deploy/images.lock` pins it. |
| 13 | cell-guard, the deny-by-default Docker socket proxy. It went through 4 rounds of fixes. |
| 14a | Experiment config, matched-pair scheduler, manifest, payload and token rendering |
| 15a | Containment probe, scrape-time Prometheus metrics, structlog redaction. It went through 5 rounds plus a final patch. |
| 16 | Ansible LXC bootstrap, fail-closed nftables firewall, release, rollback and secrets scripts |
| H | Hardening batch: a re-runnable rollback swap, a 59-byte DB name check, strict cell-network validation, the cell-guard health-check floor, and `passcode`/`PWD` handling in log redaction |
| D | Docs batch: the planning docs now describe the Unix-socket oracle, and CVE-Bench is credited in the support scripts |

The CVE-Bench fork's `lab` branch is pushed at `9304c0e`, and the DVGA fork's `lab` branch at `c587128`.

Tests: about 2,370 pass locally. The latest CI run, on `0d8804e`, had one timing failure; it is fixed in `300afb1`. CI has not been confirmed green on the newest `main` (`692cb73`). Check the Actions tab first when you resume.

## 2. Work in progress: NOT merged, local worktrees only

These branches exist only on this machine, under `.claude/worktrees/`. They are not pushed. Don't delete them.

### Task 14b: runner, cell lifecycle, scripted agent
- Branch `worktree-agent-a1d2b9663c546fba7`, commits `656c842..7ae0da8`, based on `4358e80`.
- **Status:** implemented. About 2,424 tests pass. The self-test pair ran end to end in real cells on local rootless Podman. The injected run hit all 4 funnel stages, with token-verified HTTP and DNS callbacks. The control run hit only Outcome. Nothing was left behind.
- **Review:** not done. The two Opus reviewers (containment, and correctness) were stopped before they reported. Run the reviews again from the start, using the review package `.superpowers/sdd/2026-11-07-m0-skeleton/review-14b.diff`.
- **Adds:**
  - `control/runner/{cell_spec,compose_backend,runner}.py`
  - `agents/scripted/`
  - `deploy/compose/cell.dvga.yml`
  - the `lab-cell` image (`cell/Dockerfile`)
  - migrations 0004 (cell-guard decision events) and 0005 (`runs.invalid_reason`)
- **Known open points (from its report):**
  - DNS callbacks through Docker's embedded resolver on internal networks are unverified; Task 17 must check them.
  - The `lab-cell` image needs a CI build and an `images.lock` entry.
  - There is no claim lease or reaper for runs left behind by a crashed runner.
  - A crashed agent still counts as a VALID run.

### Task 15b-1: labctl, control-plane compose, Collector image
- Branch `worktree-agent-a5fd4369cecc989fb`:
  - `ac1e6db`: labctl and metrics.
  - `76998fc`: compose. Both are reviewed, with changes requested.
  - `e3b615e`: the **WIP** of fix round 1, stopped mid-round. It is uncommitted-quality and untested.
- **Status:** review 1 asked for changes. Fix round 1 was partly done.
- **Required fixes** (full rulings in `.superpowers/sdd/2026-11-07-m0-skeleton/task-15b1-review-1.md`, also copied into that worktree):
  - **C1:** give each release its own image tag, `lab/control:${LAB_RELEASE_TAG}`. Rollback must use the previous tag. Otherwise rollback runs the new migration on the restored database.
  - **C2:** mount `/srv/lab/db/pgdata` directly as the Postgres data directory. Otherwise Postgres cannot initialise under the `lab:lab 0700` `/srv/lab/db`.
  - **I1:** the base role must create `/srv/lab/state`.
  - **I2:** bootstrap generates `LAB_DB_PASSWORD` once on the host, and `secrets.sh` never overwrites it.
  - **I3:** install labctl per release from the release tree with a pinned host `uv`. `/usr/local/bin/labctl` follows `current`. Never give the containers the Docker socket.
  - **Minors:**
    - a usage error for an unparsable `DATABASE_URL`;
    - doctor requires `lab_metrics_database_up 1`;
    - a DB `connect_timeout` and serialized scrapes;
    - status reads the self-test file relative to `LAB_ROOT`;
    - doctor checks that `lab.env` is root-owned with mode 0600;
    - pin `hatchling`;
    - the DEPLOYMENT.md and TRACKING.md updates.

## 3. What's left, in order

1. **Finish 15b-1.**
   - Continue from WIP `e3b615e`: finish C1, C2, I1–I3 and the minors.
   - Run `LAB_REQUIRE_TOOLS=1 uv run pytest -q`, ruff, `ruff format --check` and mypy.
   - Squash the WIP commit, then get a scoped re-review.
2. **Review 14b.** Run the two reviews again (containment and secrets; runner correctness and evidence), then fix rounds.
3. **Merge 14b and 15b-1 into `main`.** Expect overlaps in:
   - `control/api/metrics.py`: 15b-1 rewrote it. Point `lab_invalid_runs_total` at `runs.invalid_reason` through `repo.invalid_runs_by_reason`.
   - `deploy/images.lock`: both add entries (`lab-cell`, `postgres`).
   - `pyproject.toml` and `uv.lock`: re-run `uv lock`.

   Then add a `lab-cell` (and control image) job to `.github/workflows/build-images.yml`.
4. **Task 15b-2: `labctl selftest`.**
   - Runs one injected and one control DVGA cell with the scripted agent.
   - Both runs must be VALID with end_status COMPLETED.
   - The injected run must reach 4/4 stages, with callbacks on both channels and the oracle true.
   - The control run must have no tags anywhere.
   - Runs the containment probe with `--sinkhole <catcher .2>`, `--reach <target .3>,<tap .4>`, `--host-gateway` and `--lan`.
   - Records the result with `record_selftest_result`.
   - Wire it into `_cmd_selftest` in `control/cli/main.py`. Never exit 3, because release.sh reads 3 as "labctl not installed".
5. **Final whole-branch review** on Opus, then one fix pass. The pass covers these parked items:
   - **Rollback swap:** wrap the manual swap message in BEGIN/COMMIT, and have SWAP_DB drop `_old` only when the live name exists.
   - **Firewall role:** check the gateways of multipath routes (`nexthops[]`).
   - **Docs:** fix the cell-guard docstring's claim about cleanup by mounts, and the "Oracle sidecar" row label in DEVELOPMENT_PLAN.md.
   - **`images.lock`:** split the control-plane images from the cell-guard allow-list.
   - **Log-redaction residuals:** they are listed in `task-15a-adjudication.md` (all over-masking or rare shapes).
6. **Task 17 on CT 111: needs the homelab and you.**
   - **You, on the Proxmox host:** load `nft_fib_inet nft_log nf_log_syslog nft_limit nft_ct nft_compat xt_comment` and persist them in `/etc/modules-load.d/llm-lab.conf`. Start CT 111. Give SSH access back (root@192.168.1.145 over Twingate).
   - **Then:** `deploy/bootstrap.sh`, `deploy/secrets.sh`, `deploy/release.sh`, and `labctl doctor` / `selftest` on the host.
   - **Verify there:**
     - a spoofed-source packet from a cell is dropped (rpf);
     - cells cannot resolve outside names;
     - DNS callbacks reach the catcher on Docker;
     - `pg_restore --list` exit codes through `compose exec -T`;
     - the rollback swap on real Postgres (13 or later);
     - `up --wait` with the exited migrate one-shot;
     - the exact `containerd.io` revision;
     - that `DOCKER-USER` survives Docker's first start;
     - that Docker refuses to start when the firewall fails to load.

Expected effort for steps 1–5: about 3–5 hours of agent time. Step 6 takes 1–2 hours once the host is up.

## 4. Decisions still open for the team (they don't block steps 1–5)

- DVGA branding and logo ("DAMN VULNERABLE GRAPHQL APPLICATION").
- The odd upstream note text that is seeded into about 540 pastes.
- Response size: a keyword-less search returns about 3,000 pastes (about 1 MB).
- RedAmon's defence-off arm.
- DEVELOPMENT_PLAN.md §10: decision 1 (budget) and decisions 4–7, 9 and 10.

## 5. Working rules that carry over

- **Commits:** every commit has a single author, with no `Co-Authored-By` line and no mention of an AI.
- **Never commit:** `.superpowers/`, `docs/paper/`, secrets, or the lab HMAC key. The key must never enter a cell.
- **Executable bits:** this checkout has `core.filemode=false`. Add executable bits with `git update-index --chmod=+x <file>` and check that `git ls-files -s` shows 100755.
- **Gates:**
  - `LAB_REQUIRE_TOOLS=1 uv run pytest -q`
  - `uv run ruff check .`
  - `uv run ruff format --check .`
  - `uv run mypy control cell agents`
  - Some tests need `uv sync --all-extras` (mitmproxy).
- **gitleaks:** synthetic test values go in the allow-list in `.gitleaks.toml`.
- **Timing tests:** keep inputs at or below `MAX_INPUT_CHARS`. Use `_assert_fast` (best of 3, with a 3 s limit) and the retrying scaling check.
- **Third-party attack frameworks:** never run them on the workstation.
