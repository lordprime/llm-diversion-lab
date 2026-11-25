# Resume checkpoint, 25 Nov 2026

All work is pushed. `main` holds everything that has passed review and CI. The detailed ledgers, with every ruling, deferred minor and probe, are in `.superpowers/sdd/*/progress.md`, which git ignores. Each has a "PAUSE 2026-11-25" section.

## On `main` (3e2741d)

| Work | What it is |
|---|---|
| M1a Task 1 | Dual-verdict oracle contract (effect and mechanism from a latched done v2) |
| M1a Task 2 | Event-driven oracle latch and peer pinning; DVGA retrofit |
| M1a Task 3 | Juice Shop GOAT image (hygiene, content pack, offline) |
| M1a Task 4 | Juice Shop oracle (admin-session effect, login-injection mechanism) |
| M1a Task 5 | Drupal 8.5.0 GOAT image (CVE-2018-7600) |
| M1a Task 6 | Drupal oracle (execution-event effect, web-server-descendant mechanism) |
| M1a Task 7 | Injector surfaces P2–P8 with a browser-rule tokenizer and a pre-registered offset |
| Telemetry | Per-run calls, agents, context, tokens, tool calls and reasoning from captured traffic |
| M2 Task 3 | Telemetry in the runner, store, API and the results export |
| M2 Task 2 | Ollama service on the NVIDIA runtime, admin-only model pulls, containment checks |

## In progress (pushed on their own branches)

| Work | Branch (head) | Next step |
|---|---|---|
| M1a Task 8 (placement maps, three-target self-test) | `m1a/t8-selftest-three-targets` (10d2a10) | Fix round 1 is done and CI is green. Re-run the stopped re-review, then merge. |
| M1a Task 9 (CT 111 release and acceptance) | — | With the user. Build images with a version, then pin goat-juice-shop and goat-drupal-7600 in `deploy/images.lock`. The release now runs the full three-target self-test; `--quick-selftest` is opt-in. |
| M2 Task 1 (model gateway) | `m2/t1-gateway` (c746047, WIP) | Finish fix round 2: an exact structure count before refusing (413, not 403), a per-peer connection cap, and a nonzero exit. Then review and merge. |
| M3 Task 1 (adapter base and capability sheets) | `m3/t1-adapter-base` (no commits yet) | Start it again: new files only. |

## After that

- **M2 Tasks 4–6:** three arms, the equivalence check and word tags, after M1a Task 8 merges.
- **M2 Task 7:** CISPA VM bring-up, with the user.
- **M3 Tasks 2–9:** five adapters, the campaign runner, the results package and the open-weight campaign.

Plans: `docs/superpowers/plans/2026-11-24-m1a-goat-platforms.md`, `2026-11-25-m2-engine-ollama.md` and `2026-11-25-m3-adapters-open-weight-campaign.md`.
