# M1a (GOAT platforms): status on 25 Nov 2026

Plan: `docs/superpowers/plans/2026-11-24-m1a-goat-platforms.md`. Each task has its own branch. A task is merged into `m1a/goat-platforms` once it passes review and CI. The detailed ledger is kept locally in `.superpowers/sdd/2026-11-24-m1a-goat-platforms/progress.md`, which git ignores.

| Task | Branch (head) | State | Next step |
|---|---|---|---|
| 1 Dual-verdict oracle contract | `m1a/t1-dual-verdict` | **Merged** | — |
| 2 Latch + DVGA retrofit | `m1a/t2-latch-dvga` (433a928) | **Merged** | — |
| 3 Juice Shop image | `m1a/t3-juice-shop-image` (fed4a86) | **Merged** | — |
| 4 Juice Shop oracle | `m1a/t4-juice-shop-oracle` (7410f7e) | **Merged** | — |
| 5 Drupal 8.5.0 image | `m1a/t5-drupal-image` (e86be6a) | **Merged** | — |
| 6 Drupal oracle | `m1a/t6-drupal-oracle` (89aafd6) | **Merged** | Mechanism: a `www-data` descendant of the pinned subreaper wrapper (no interactive-shell exclusion). |
| 7 Injector surfaces P2–P6, P8 | `m1a/t7-injector-surfaces` (69e21ac) | **Merged** | — |
| E1 Run telemetry (phase 2) | `m2/e1-run-telemetry` (f27c3ed) | **Merged** | — |
| 8 Placement maps, three-target self-test | `m1a/t8-selftest-three-targets` | In review | Frozen maps per target, P7 and P2 paths probed on the built images, the self-test on all three targets with the reset-after-success check; the `labcell-` prefix and `secret_*_canary` volumes renamed (`c-`, `secret_svc_a..c`). |
| 9 Release and CT 111 acceptance | not started | — | Run the full self-test on CT 111. Check that v0.1.0 verdict files (which lack `effect`) re-post after the upgrade. |

Decisions made during this phase are recorded in the ledger. Among them:
- E7: record both verdicts.
- The latch path is `/var/lib/svcstate`.
- Migration numbering: the first branch merged keeps its numbers. Task 1 has 0007 and 0008, so Task 7's migration becomes 0009.
- Telemetry agent counts are labelled `inferred` unless an adapter supplies them.

Phases 2 (simulation engine, Ollama route, CISPA deployment) and 3 (agents and the open-weight campaign) still need their own plans. Inputs for them:
- `docs/OLLAMA_SUPPORT_AUDIT.md`.
- The CISPA layout: one PVE VM runs everything, with Ollama as a digest-pinned container on the NVIDIA runtime and an H100 or H200 GPU.
