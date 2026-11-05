# Deployment: Running the Lab on a Separate Server

**Companion to:** [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md), [AUTOMATION_FEASIBILITY.md](AUTOMATION_FEASIBILITY.md)
**Status:** plan and script specification. The scripts are specified precisely enough to implement directly, but they are not written yet.

---

## 1. Topology

```
  WORKSTATION                         LAB SERVER (Ubuntu 24.04, bare metal)                BACKUP TARGET
  ───────────                         ─────────────────────────────────────                ─────────────
  git, uv, ansible                    Caddy (private iface, TLS, auth) ─► website / APIs / Grafana
  deploy/*.sh  ──── SSH (keys) ─────► Ansible-managed host: Docker 29 + Sysbox + nftables
  labctl --remote ── HTTPS+token ───► Control plane (systemd → compose):                  restic repo
  browser ───── tunnel / VPN ───────►   Postgres · Collector/Control/Results API          (S3 or SSH)
                                        runner workers · scheduler · LiteLLM gateway ──► LLM providers
                                        local registry · Prometheus/Grafana/Loki         (only egress
                                      Run cells (Sysbox, no internet) ×N                  besides builds)
                                      nightly: backup ─────────────────────────────────►
```

There are three machines (the second and third can be the same box):

| Machine | Role | What runs there |
|---|---|---|
| **Workstation** (developer laptop or desktop) | Write code, run unit tests, deploy, watch | git, uv, Ansible (via pipx), the deploy scripts, `labctl` **in remote mode**, a browser |
| **Lab server** (Ubuntu 24.04 bare metal, spec in [AUTOMATION_FEASIBILITY.md §6.1](AUTOMATION_FEASIBILITY.md)) | Build images, run the control plane, run cells | Docker 29 + Sysbox 0.7.1, the control-plane stack (Postgres, APIs, runner, scheduler, LiteLLM gateway, website), the **ops stack** (Prometheus, Grafana, Loki, node-exporter, cAdvisor), a **local image registry**, Caddy as the private reverse proxy, backups |
| **Backup target** (any S3-compatible bucket or SSH host) | Off-machine copies | restic repository holding Postgres dumps and run artifacts |

### Network

| Path | Rule |
|---|---|
| **Inbound to the lab server** | SSH (key-only) and the private access channel. **Nothing is public.** |
| **Outbound from the lab server** | The LLM gateway → provider APIs; the *build phase* → registries, PyPI, npm, GitHub, ftp.drupal.org, archive.debian.org; apt; the backup target |
| **Run cells** | Never outbound. The containment rules in [AUTOMATION_FEASIBILITY.md §4](AUTOMATION_FEASIBILITY.md) apply unchanged. |

**Private access channel (decision for the team):**

| Option | Notes |
|---|---|
| **(a) SSH tunnel** | Zero setup; `./deploy/tunnel.sh`. **Default.** |
| **(b) WireGuard** | Self-hosted; good for a multi-person team |
| **(c) Tailscale** | Easiest for a team, but adds a third-party coordination service |

Whichever is chosen, the website, the APIs and Grafana are reached **only** through Caddy on the private interface, with authentication.

---

## 2. What changes because the server is separate

| # | Change | Plan section affected |
|---|---|---|
| 1 | **`labctl` becomes client/server.** The CLI runs on the server *or* on the workstation (`labctl --remote lab1 …`) against the Control API over HTTPS with an API token. Every command works either way. | Plan §3.3 C, §5 |
| 2 | **Web UI, APIs and Grafana are behind Caddy with auth**, bound to the private interface (or localhost + SSH tunnel). They are no longer "localhost-only on the laptop". Roles: `viewer`, `operator` (start, pause, schedule), `admin` (tokens, deploys). | Plan §6 |
| 3 | **Secrets live only on the server:** `/srv/lab/secrets/lab.env`, mode 0600, owner `lab`. They are pushed once with `deploy/secrets.sh` and never stored on the workstation after the push (the script reads them from the prompt or a file and doesn't keep a copy). | Plan §5.1 |
| 4 | **Images are built on the server** in a separate build phase. The host has internet, the cells don't. Images are pushed to the server's local registry (`127.0.0.1:5000`) and pinned in `images.lock`. CI can build and push instead, using the same registry over the private channel. | Feasibility §6.2 |
| 5 | **Services are managed by systemd** (wrapping `docker compose`), restart automatically, and survive reboot. On start, the runner **reconciles**: it finds cells left over from a crash, records those runs as `invalid: host_restart`, reaps the cells and re-queues the runs. | Plan §5.4 |
| 6 | **Pinned system packages.** Docker, containerd, Sysbox and the kernel are apt-pinned so unattended upgrades can't change them mid-experiment. They are upgraded only through `deploy/upgrade-host.sh` in a maintenance window, followed by a self-test. | Feasibility §6.1 |
| 7 | **Time sync (chrony)** is mandatory, because the evidence ordering across injector, tap, catcher and pcap depends on it. `labctl doctor` fails if clock offset > 50 ms. | Plan §3.1 |
| 8 | **Remote observability and alerts:** nobody is watching the box, so the server pushes notifications (see [TRACKING.md](TRACKING.md)). | new |
| 9 | **Storage layout and backups:** XFS data volume, reflink golden roots, artifact retention, nightly restic backups, and a restore drill before the pilot. | new |
| 10 | **Release tracking:** the deployed release tag + git SHA is recorded on every run and shown on every page footer. | Plan §5.5 |
| 11 | **Orphan reaping:** a systemd timer removes cells, networks and volumes whose run is no longer `running` (identified by the `lab.run_id` label). | Plan §5.4 |

---

## 3. Server layout

```
/srv/lab/
  releases/<tag>/          # unpacked release trees (code, compose files, configs)
  current -> releases/<tag>
  secrets/lab.env          # 0600 lab:lab  (provider keys, budgets, notify URLs)
  secrets/ca/              # lab CA for the callback catcher's TLS (generated on first run)
  secrets/hmac.key         # callback-token key (generated on first run)
  db/                      # Postgres data (control plane)
  registry/                # local image registry storage
  golden/<images.lock-hash>/docker/   # golden inner /var/lib/docker per image set
  cells/<run_id>/          # per-run reflink clone + run volume (deleted after shipping)
  artifacts/               # write-once run artifacts (separate disk recommended)
  ops/                     # prometheus, grafana, loki data
  backups/                 # local staging for restic
```

**Disks:**
- **Data disk** (NVMe, XFS `ftype=1,reflink=1`) holds `/var/lib/docker`, `/var/lib/sysbox`, `/srv/lab/{golden,cells,registry,db}`.
- **Artifact disk** (larger, can be slower) holds `/srv/lab/artifacts`.

---

## 4. Deployment scripts (specification)

All scripts live in `deploy/`.

**Common rules:**
- They are Bash wrappers with `set -Eeuo pipefail`, are `shellcheck` clean, and support `--help`.
- They are **idempotent**: re-running converges, and they never destroy data unless an explicit `--yes-destroy-…` flag is given.
- They read the target from `deploy/hosts.yml`.
- They print a one-line summary on success, and on failure the failing step plus a pointer to the relevant runbook.

### 4.1 `deploy/hosts.yml` (copied from `hosts.example.yml`)

```yaml
lab1:
  address: 10.0.0.20          # or a DNS name on the private network
  ssh_user: admin             # sudo-capable user for provisioning
  data_disk: /dev/nvme1n1     # formatted only with --format-data-disk
  artifact_disk: /dev/sda     # optional
  access: ssh-tunnel          # ssh-tunnel | wireguard | tailscale
  backup_repo: s3:https://…/lab-backups   # restic repository URL
  max_parallel_cells: 6
```

### 4.2 Scripts

| Script | Purpose | What it does, in order | Target time |
|---|---|---|---|
| **`bootstrap.sh <host> [--format-data-disk]`** | Turn a fresh Ubuntu 24.04 install into a lab server | 1. Check the workstation has `ansible` (installs it with pipx if missing). 2. Run `ansible/site.yml` against the host (roles in §4.3). 3. Generate the lab CA and HMAC key on the server if absent. 4. Start the registry and ops stack. 5. Run `labctl doctor` remotely and print the report. | ≤ 20 min |
| **`secrets.sh <host> [--from-file path]`** | Install or rotate provider keys and settings | 1. Prompt for (or read) each variable in `.env.example`: required (`ANTHROPIC_API_KEY`, `LAB_BUDGET_USD`) and optional (other providers, `NOTIFY_*`). 2. Validate the format of each value (shows variable **names** only, never values). 3. Write `secrets/lab.env` atomically over SSH (mode 0600). 4. Reload the gateway. 5. Make one zero-cost test call per provider (a model list request) and report OK or failed. | ≤ 2 min |
| **`release.sh <host> --tag vX.Y.Z [--drain]`** | Deploy a version | 1. Refuse if the git tree is dirty or the tag is missing. 2. `git archive` the tag and copy it to `releases/<tag>` (rsync, checksummed). 3. If an experiment is running: **refuse**, or with `--drain` pause the queue and wait for in-flight runs to finish. 4. Run DB migrations (Alembic) with a pre-migration `pg_dump`. 5. `labctl build --changed-only` on the server: rebuild only images whose inputs changed, push to the local registry, update `images.lock` and the golden roots. 6. Swap the `current` symlink and restart the services. 7. `labctl selftest --quick` (one target, no tokens). 8. On failure: **automatic rollback** to the previous symlink + DB restore from step 4, then exit non-zero. 9. Record the deployment (tag, SHA, who, when) in the `deployments` table. | ≤ 10 min (warm caches) |
| **`rollback.sh <host> [--to vX.Y.Z]`** | Return to a previous release | Swap the symlink back, run down-migrations to that release's schema (or restore the pre-migration dump), restart, run the self-test | ≤ 5 min |
| **`build.sh <host> [--all]`** | Rebuild images without a release (e.g. a GOAT content-pack change) | `labctl build` on the server; prints the new `images.lock` diff | varies (first full build: ~1–2 h, RedAmon and Kali images dominate) |
| **`status.sh <host>`** | Quick health | Services up, queue depth, runs in flight, spend vs budget, disk free, last backup time, deployed tag | seconds |
| **`tunnel.sh <host>`** | Private access without a VPN | `ssh -N -L 8443:127.0.0.1:8443` (Caddy: website, API, Grafana on one port) and prints the URLs | seconds |
| **`logs.sh <host> [service\|--run <run_id>] [-f]`** | Read logs | journald or Loki query by service or by `run_id` | seconds |
| **`backup.sh <host>` / `restore.sh <host> --snapshot <id>`** | Off-machine copies | `pg_dump` + artifacts → restic. A nightly systemd timer runs the same thing. Restore is documented and **drilled once before the pilot**. | depends on size |
| **`reap.sh <host>`** | Clean up orphans by hand (a timer also does this) | Remove cells, networks and volumes labelled `lab.run_id` whose run isn't running | seconds |
| **`upgrade-host.sh <host>`** | Planned upgrade of the pinned Docker, Sysbox or kernel | Refuse during experiments → unpin → upgrade → reboot if needed → re-pin → `labctl doctor` + full self-test | ≤ 30 min |

### 4.3 Ansible roles (`deploy/ansible/`)

| Role | Responsibilities |
|---|---|
| `base` | Updates; packages (git, jq, curl, tcpdump, chrony, nftables, restic, python3.12, uv); create the `lab` user; SSH hardening (keys only, no root login); fail2ban; unattended security upgrades with apt pins for docker-ce, containerd, sysbox and linux-image |
| `storage` | Check (and, only with `--format-data-disk`, create) XFS with `ftype=1,reflink=1`; fstab entries; `/srv/lab` tree with ownership |
| `docker` | Docker CE 29.x from Docker's apt repo (pinned minor, **never 29.1.0**); compose plugin ≥ 2.24; `/etc/docker/daemon.json` (data-root on the XFS disk, log rotation, `live-restore`, default address pools that don't overlap the cell subnets) |
| `sysbox` | Download the Sysbox 0.7.1 `.deb`, **verify its SHA-256**, install, and check `sysbox-runc --version` |
| `sysctl` | `vm.max_map_count=262144` (Neo4j), higher `fs.inotify.*`, `kernel.pid_max`, `net.ipv4.ip_forward=1` |
| `firewall` | nftables: inbound default-drop except SSH (+ WireGuard if chosen); in the `DOCKER-USER` chain, **drop all forwarding from cell subnets except to the LLM gateway IP:port**; log drops (rate-limited) for the containment report |
| `access` | One of ssh-tunnel (no-op), WireGuard (keys + peer config) or Tailscale (install + join with an auth key supplied interactively) |
| `caddy` | Reverse proxy on the private interface only: website, Control/Results API and Grafana under one TLS origin; internal CA or Tailscale certificates; basic auth for the pilot (OIDC later) |
| `registry` | `registry:2` bound to 127.0.0.1:5000, storage in `/srv/lab/registry` |
| `ops` | Prometheus (scrapes node-exporter, cAdvisor and lab services), Grafana with the provisioned dashboards from [TRACKING.md](TRACKING.md), Loki + promtail (container logs, labels incl. `run_id`), Alertmanager → notification webhook |
| `lab` | systemd units: `lab-control.service` (compose stack: Postgres, APIs, runner workers, scheduler, gateway, website), `lab-reaper.timer`, `lab-backup.timer`, `lab-selftest.timer` (nightly, in the maintenance window) |

### 4.4 The fresh-server quickstart

```
cp deploy/hosts.example.yml deploy/hosts.yml     # set address, disks, access method
./deploy/bootstrap.sh lab1 --format-data-disk     # provision (≈20 min)
./deploy/secrets.sh lab1                          # paste ANTHROPIC_API_KEY + budget
./deploy/release.sh lab1 --tag v0.1.0             # deploy, build images, self-test
./deploy/tunnel.sh lab1                           # open https://localhost:8443
labctl --remote lab1 pilot                        # or: ssh lab1 'labctl pilot'
```

Beyond that, the user only fills in `.env` values. Everything else is scripted, idempotent and verified by `labctl doctor` and the self-test.

---

## 5. Operating rules

- **Maintenance window** (configurable; default Sunday 03:00–05:00 server time): nightly self-test, backups, image garbage collection. Host upgrades happen only here.
- **No deploys during a running experiment.** `release.sh` refuses unless `--drain` is given. An experiment's runs all use one release; the experiment records it and refuses to resume on a different release unless it is explicitly re-registered.
- **Artifact retention:**
  - raw artifacts are kept for the life of the paper and backed up;
  - pcaps older than 90 days can be compressed to `.pcap.zst`;
  - nothing is deleted automatically.
- **Disk guard:** the runner stops claiming new runs below 15% free on either disk and raises an alert.
- **Key rotation:** `secrets.sh` at any time. Per-run virtual keys mean rotation never interrupts in-flight runs.
- **Disaster recovery:** a new server plus `bootstrap.sh`, `restore.sh` and `release.sh` gets back to the last backup. This is drilled before the pilot.
