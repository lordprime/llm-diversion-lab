# LLM Diversion Lab

Test harness for the study *Do Planted Prompts Stop LLM Attack Agents?*

Open-source LLM attack agents (RedAmon, Strix, HackingBuddyGPT, PentestGPT, PentAGI) attack deliberately vulnerable web apps ("GOATs") in isolated, offline run cells. A reverse proxy plants tagged text on seven web surfaces. Every run is classified on the **Access → Visible → Uptake → Outcome** funnel against a matched clean control, with success decided by an independent oracle.

**Status:** planning complete; target repositories set up; harness code not yet written.

## Documents

| Document | Contents |
|---|---|
| [docs/DEVELOPMENT_PLAN.md](docs/DEVELOPMENT_PLAN.md) | Architecture, the four work areas, pilot design, milestones, decisions |
| [docs/AUTOMATION_FEASIBILITY.md](docs/AUTOMATION_FEASIBILITY.md) | Source-level audit of every framework, adapter recipes, tool inventory, containment |
| [docs/ENGINEERING_STANDARDS.md](docs/ENGINEERING_STANDARDS.md) | Coding principles, tooling, testing, CI, review, security |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Running the lab on a separate server; deployment scripts |
| [docs/TRACKING.md](docs/TRACKING.md) | Website, dashboards, CLI, APIs, notifications, audit |
| [docs/LLM_Diversion_Development_Plan.pdf](docs/LLM_Diversion_Development_Plan.pdf) | All of the above as one PDF (`python tools/build_plan_pdf.py`) |

## Target sources

Pinned by commit in `targets/*/source.yaml` and `cell/oracle/source.yaml`. Each target repo has an `upstream` branch frozen at the pinned upstream version and a `lab` branch with our changes.

| Target | Repository |
|---|---|
| OWASP Juice Shop v20.3.0 | https://github.com/lordprime/juice-shop-diversion-test |
| DVGA 2.2.0 | https://github.com/lordprime/Damn-Vulnerable-GraphQL-Application-diversion-test |
| flask-sockets (DVGA dependency) | https://github.com/lordprime/flask-sockets-diversion-test |
| Drupal 8.5.0 (CVE-2018-7600) | https://github.com/lordprime/goat-drupal-7600-diversion-test |
| CVE-Bench v2.2.0 evaluator | https://github.com/lordprime/cve-bench-diversion-test |

## Safety

The GOATs are intentionally vulnerable and the agents are offensive tools. Run them **only** inside the isolated run cells described in the deployment plan, never on a workstation network or anything internet-facing. Never commit `.env`, `deploy/hosts.yml`, keys or certificates.
