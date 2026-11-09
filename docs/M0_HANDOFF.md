# M0 handoff: where work stands and how to continue

Updated on 2026-11-09 (M0 complete). Plan: `docs/superpowers/plans/2026-11-07-m0-skeleton.md` (17 tasks).
The detailed ledger with every ruling and review is kept locally in `.superpowers/sdd/2026-11-07-m0-skeleton/progress.md` (git-ignored). This file is the summary.

## 1. State of `main`

**M0 is complete.** Every code task (1–16, with the hardening batch H, the docs batch D and the CI image jobs) is merged and pushed, and Task 17, the acceptance run on the real host CT 111, passed on 9 Nov 2026. CT 111 runs release `v0.1.0` (`a151c93`).

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
| H, D | The hardening batch and the docs batch, then the final four-area review and its fix pass (F1–F3) |
| CI | `build-images.yml`: a `plan` job picks one image tag per run (an optional `version` input, a `lab-v*` git tag, or `sha-<commit>`); a `goat` matrix builds every `targets/<name>/Dockerfile` through that GOAT's own `ci/` scripts; `lab-cell` and `control` follow. All push to `ghcr.io/lordprime/<name>` (public packages). |
| 17 | The acceptance run on CT 111: release, full self-test, containment, rollback drill and reboot. The results are in DEPLOYMENT §0.5. |

The forks' `lab` branches are pushed: CVE-Bench at `9304c0e`, DVGA at `c587128`.

## 2. Pinned images

`deploy/images.lock` pins `goat-dvga` (`sha256:577635ad…`) and `lab-cell` (`sha256:2194b498…`) from the build of `72c2758`. The `control` image of that build (`sha256:ed5bcae2…`) is public but not pinned yet: the control-plane compose still builds `lab/control:<tag>` on the host, so releases use `--allow-build`.

**To ship new images:**
1. Run *build-images* with a version (e.g. `v0.2.0`).
2. Paste the job summaries' entries into `images.lock`.
3. Commit, and tag the repository with the same version.
4. Run `./deploy/release.sh lab1 --tag v0.2.0 --allow-build`.

The release self-test then checks the new images in real cells.

## 3. Follow-ups left by Task 17

- **Protect pinned images from `docker image prune`.** Images pulled by digest are untagged, so a prune deletes them (DEPLOYMENT §0.5). Option: `release.sh` gives each one a local tag, e.g. `lab-pinned/<name>:<digest prefix>`.
- **Juice Shop and Drupal 7600 GOAT images** (M1): each needs a Dockerfile, its `ci/build.sh`, `ci/check.sh` and `ci/expect_tools`, an oracle grader and its hygiene patches. Then build-images picks it up on its own.
- **GitHub Actions upkeep:** `actions/checkout@v4`, `setup-uv@v5` and `gitleaks-action@v2` target Node 20, which runners now force onto Node 24. `ubuntu-latest` moved to Ubuntu 26 on 19 Oct 2026.
- **A cosmetic leftover on CT 111:** Ubuntu's empty accept-only `table inet filter` is still loaded.

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
