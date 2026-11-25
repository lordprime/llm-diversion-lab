# M1a (GOAT platforms): status at the pause on 24 Nov 2026

Plan: `docs/superpowers/plans/2026-11-24-m1a-goat-platforms.md`. Each task has its own branch. A task is merged into `m1a/goat-platforms` once it passes review and CI. The detailed ledger is kept locally in `.superpowers/sdd/2026-11-24-m1a-goat-platforms/progress.md`, which git ignores.

| Task | Branch (head) | State | Next step |
|---|---|---|---|
| 1 Dual-verdict oracle contract | `m1a/t1-dual-verdict` (781177c) | **Merged** | — |
| 5 Drupal 8.5.0 image | `m1a/t5-drupal-image` (e86be6a) | **Merged** | — |
| 2 Latch + DVGA retrofit | `m1a/t2-latch-dvga` (cb5da41) | Fix round 1 half done. Fork `lab` is at 19ea0a6; unfinished work is on fork branch `wip/t2-fix-round-1`. | Finish: per-kind append in EventSocket, `ProcessPin` and `PeerRule(pin, relation)`, SO_PEERPIDFD, start-time pin, size caps, rejecting NaN, renaming the volume to `svcstate` with a mountinfo test, and the EventSocket slot leak. Then re-review. |
| 3 Juice Shop image | `m1a/t3-juice-shop-image` (b0c3fb8, WIP) | Fix round 1 half done. Fork `lab` is at 37bd98c55. | Finish: the erasure-page allow-list and its test (a file read through Express `settings`), removing the "AI chat" i18n key, widening the scans and the lint, the 0400 secret check, and narrowing the chown. Then CI and re-review. |
| 6 Drupal oracle | `m1a/t6-drupal-oracle` (8b4f816) | Review done; fix round 1 not started | Start Apache with a child subreaper so backgrounded `/tmp/pwn` counts as mechanism; realistic volume names in the test plus a strict xfail for `labcell-`; a ptrace test; health start time; pwn timeouts; grader flags off world-readable command lines. |
| 7 Injector surfaces P2–P6, P8 | `m1a/t7-injector-surfaces` (92a76d2) | Fix round 3 done, CI green | Re-run the stopped re-review: html5lib differential and speed on large pages. |
| E1 Run telemetry (phase 2) | `m2/e1-run-telemetry` (f27c3ed) | Fix round 3 done, CI green | Re-run the stopped re-review. |
| 4 Juice Shop oracle | not started | — | Waits for Tasks 2 and 3. Notes:<br>- Admin means the admin's account, never the role.<br>- `/profile/image/url` is an SSRF inside the target, so the oracle listens on nothing the target can reach.<br>- Pin the peer to the node app process itself. |
| 8 Placement maps, three-target self-test | not started | — | Also renames the `labcell-` project prefix and the `secret_*_canary` volumes, which are visible in mountinfo. |
| 9 Release and CT 111 acceptance | not started | — | Check that v0.1.0 verdict files (which lack `effect`) re-post after the upgrade. |

Decisions made during this phase are recorded in the ledger. Among them:
- E7: record both verdicts.
- The latch path is `/var/lib/svcstate`.
- Migration numbering: the first branch merged keeps its numbers. Task 1 has 0007 and 0008, so Task 7's migration becomes 0009.
- Telemetry agent counts are labelled `inferred` unless an adapter supplies them.

Phases 2 (simulation engine, Ollama route, CISPA deployment) and 3 (agents and the open-weight campaign) still need their own plans. Inputs for them:
- `docs/OLLAMA_SUPPORT_AUDIT.md`.
- The CISPA layout: one PVE VM runs everything, with Ollama as a digest-pinned container on the NVIDIA runtime and an H100 or H200 GPU.
