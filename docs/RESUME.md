# Resume checkpoint, 26 Nov 2026

All work is pushed. `main` holds everything that has passed review and CI. The detailed ledgers are in `.superpowers/sdd/*/progress.md`, which git ignores. Each has a "PAUSE 2026-11-26" section with every ruling, deferred minor and probe. A branch whose head is a `wip:` commit is an unreviewed checkpoint, and its tests may fail.

## On `main` (008d532)

| Work | What it is |
|---|---|
| M1a Tasks 1–8 | Dual-verdict oracles; the latch; the DVGA, Juice Shop and Drupal GOATs; injector surfaces P2–P8; placement maps and the three-target self-test |
| Telemetry, M2 Tasks 2–3 | Per-run telemetry in the runner and the export; the Ollama service on the NVIDIA runtime |
| M3 Task 1 | Adapter base and capability sheets: structured side channels that block a run until resolved, a per-run handle, and both exit signals recorded |

## In progress (pushed on their own branches)

| Work | Branch (head) | Next step |
|---|---|---|
| M2 Task 1 (model gateway) | `m2/t1-gateway` (04a3d4c, CI green) | Fix round 3 is done. Its re-review was stopped: run it again, then merge, with the migration renumbered to 0012. |
| M2 Task 4 (three arms) | `m2/t4-three-arms` (d6e65ed) | Fix round 1 looks committed but was not reported. Check it, run a scoped re-review, then merge (migration 0011). After that come Tasks 5 and 6. |
| M3 Task 1b (agent image CI lane) | `m3/t1b-agent-image-ci` (WIP) | Finish the stub model, `smoke.sh` (including `--docker` through cell-guard and `--worker-image`) and the self-check. |
| M3 Task 1c (cell-guard) | `m3/t1c-cellguard-archive` (WIP) | Archive routes for owned containers; forced ExtraHosts; `LAB_SCRATCH_VOLUME`. |
| M3 Tasks 2–6 (adapters) | `m3/t2-strix`, `m3/t3-pentagi`, `m3/t4-redamon`, `m3/t6-pentestgpt` (WIP); `m3/t5-hackingbuddygpt` (56b4b49) | Finish each adapter on the CI lane. hackingBuddyGPT is ready for review. |
| M1a Task 9 (CT 111 release) | — | With the user. |

## After that

- M2 Task 7: CISPA VM bring-up, with the user. It includes the full RedAmon kali image and the Ollama smoke runs for each adapter.
- M3 Tasks 7–9: the campaign runner, the results package and the open-weight campaign.

Plans: `docs/superpowers/plans/2026-11-24-m1a-goat-platforms.md`, `2026-11-25-m2-engine-ollama.md` and `2026-11-25-m3-adapters-open-weight-campaign.md`.
