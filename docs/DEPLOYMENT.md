# Deployment: Running the Lab on a Separate Server

**Companion to:** [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md), [AUTOMATION_FEASIBILITY.md](AUTOMATION_FEASIBILITY.md)
**Status:** plan and script specification. The scripts are specified precisely enough to implement directly, but they are not written yet.

---

## 0. Deployment target: an unprivileged LXC on the Proxmox homelab (decided 5 Nov 2026)

The lab runs in a dedicated **unprivileged LXC container on the team's Proxmox server**, because the server can't spare the resources for a VM.
- **Private access** goes through **Twingate**.
- **Anything made public later** goes through **Cloudflare Tunnel with Cloudflare Access** in front.

The bare-metal/VM design in the rest of this document stays as the **upgrade path** if the lab moves to stronger hardware. This section overrides it where they differ.

| Area | Bare-metal/VM design | **LXC design (current)** |
|---|---|---|
| Per-run isolation | Sysbox: its own Docker daemon per run cell | **One Docker daemon inside the LXC.** Each run cell is its own compose project on isolated internal networks. Agents that start containers get a **cell-guard** socket proxy instead of the real Docker socket (§0.3). Sysbox can't run in an unprivileged LXC. |
| Outer boundary | Host nftables | The **unprivileged LXC** (root inside maps to an unprivileged user on the Proxmox host), the **Proxmox firewall on the container** (internet only, never the home LAN), and nftables inside the LXC |
| Storage | XFS disk with reflink golden roots per cell | The LXC's root disk on Proxmox storage. All cells share one image store, so there are no per-cell image copies and much less disk is needed. |
| Kernel settings | Set by Ansible | Set once on the Proxmox host (§0.1) |
| Private access | SSH tunnel / WireGuard / Tailscale | **Twingate**: SSH, the website and Grafana as Twingate resources |
| Public access (later) | Not planned | **Cloudflare Tunnel** (`cloudflared` in the LXC → Caddy), **behind Cloudflare Access** (email allow-list). Never expose GOATs, run cells, Prometheus, or any API without login. |

**What is weaker, stated plainly:** all run cells share one Docker daemon and one kernel.
- **Where an escape lands:** a container escape lands inside the unprivileged LXC, not on the homelab host, and the Proxmox firewall still blocks the home LAN.
- **What it could reach:** an escaped run could see other runs in progress.
- **Mitigations:**
  - agents never touch the real Docker socket (cell-guard);
  - no privileged containers;
  - default AppArmor and seccomp profiles are kept;
  - containment probes run in every self-test;
  - parallelism is capped.
- **Reporting:** the paper's methods section reports this setup.

### 0.1 Create the container (once, on the Proxmox host)

**Proxmox version:** **PVE 9.1 or later.**
- Docker inside unprivileged LXCs broke after the runc/containerd fix for CVE-2025-52881 (November 2025: `permission denied` on `net.ipv4.ip_unprivileged_port_start`). Community reports say newer `lxc-pve` in PVE 9.1 fixes it.
- The stopgaps found in forums are pinning `containerd.io` to 1.7.28, which gives up the CVE fix, or `lxc.apparmor.profile: unconfined`, which removes AppArmor confinement. **Neither is used by default.** The Ansible `docker` role detects the failure and stops with this explanation; the containerd pin is applied only if `allow_containerd_pin: true` is set in `hosts.yml`, and the run records it.

| Setting | Value |
|---|---|
| Template | Ubuntu 24.04 standard (`pveam update && pveam available \| grep ubuntu-24.04`) |
| Type | **Unprivileged** (never privileged) |
| Features | `nesting=1,keyctl=1` |
| CPU / RAM | See §0.4 |
| Swap | 4–8 GB |
| Root disk | ≥ 400 GB on fast storage (ZFS ≥ 2.2 or LVM-thin) |
| Network | Static IP on the LAN bridge, **`firewall=1`** on the NIC |
| Start at boot | Yes |

```
pct create <CTID> <template-storage>:vztmpl/<ubuntu-24.04-template>.tar.zst \
  --hostname llm-lab --unprivileged 1 --features nesting=1,keyctl=1 \
  --cores 8 --memory 32768 --swap 8192 --rootfs <storage>:400 \
  --net0 name=eth0,bridge=vmbr0,ip=<static-ip>/24,gw=<gateway>,firewall=1 \
  --onboot 1 --ostype ubuntu
```

**Proxmox host settings (once):**
- `vm.max_map_count=262144` in `/etc/sysctl.d/99-llm-lab.conf`, recommended for RedAmon's Neo4j. An unprivileged container cannot set it itself.
- **If the storage is ZFS:** ZFS ≥ 2.2 is required for Docker's overlay2 driver inside the LXC (`zfs version`). One community report describes an unprivileged-LXC file-permission problem on PVE 9.0 with ZFS 2.3.4; M0 checks for it.

**Proxmox firewall for the container** (enable the firewall at datacenter and container level):

| Direction | Rule |
|---|---|
| Inbound | Allow TCP 22 and 443 **only from the Twingate connector's IP**. Drop everything else. |
| Outbound | Allow DNS to the LAN resolver. **Drop** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 and 100.64.0.0/10. Allow everything else: provider APIs, registries, Cloudflare. |
| IPv6 | Drop inbound. Outbound: drop the LAN `/64`, `fe80::/10` and `fc00::/7`. IPv6 is also disabled inside the container (§0.5). |

Docker's internal cell networks live *inside* the container's network namespace, so this firewall never interferes with traffic inside a cell. `labctl doctor` checks it from inside the LXC by trying to reach a LAN address, which must fail, and a provider API, which must succeed.

**Access for the operator and for automation:** create a sudo user in the container, add the operator workstation's SSH public key, and add the container's port 22 (and later 443) as a Twingate resource.

### 0.2 What the Ansible roles do differently

Selected with `isolation: lxc` in `hosts.yml`.

| Role | LXC behaviour |
|---|---|
| `storage` | No disk formatting. Checks free space and that Docker uses `overlay2`; fails with guidance otherwise. |
| `sysbox` | Skipped |
| `docker` | Same pinned Docker CE. Starts a test container to detect the CVE-2025-52881 breakage and stops with guidance (see §0.1). |
| `sysctl` | Applies only settings an unprivileged container may change. Host-only settings are **verified**, not set. |
| `firewall` | nftables inside the LXC (the cell-subnet egress rules in `DOCKER-USER`) as before. The Proxmox-level firewall is the manual step in §0.1, verified by `labctl doctor`. |
| `access` | Twingate: nothing to install in the container; the connector runs elsewhere on the LAN |
| `caddy` | Unchanged: listens on the container's IP, port 443, reachable over Twingate |
| `cloudflared` *(new, off by default)* | Tunnel from the LXC to Caddy for the website and Grafana hostnames only. **Cloudflare Access is required** on every hostname; the role refuses to enable a hostname without an Access policy reference. |
| `cell-guard` images | Built and pinned like every other harness image |

### 0.3 cell-guard (new component)

**Agents never get the real Docker socket.** Each cell whose agent starts containers (Strix; PentAGI in Wave 2) gets its own **cell-guard**: a small validating proxy on a Unix socket. It is mounted where the agent expects `docker.sock`, or set as `DOCKER_HOST`. The runner alone uses the real socket.

It is **deny by default** and allows only the following:

| Request | Rule |
|---|---|
| Create a container | **Image:** must be in the `images.lock` allow-list. **Forced:** the network is the cell's internal network; label `lab.run_id`; memory, CPU and PID limits. **Denied:** privileged, host network/PID/IPC/user namespace, devices, bind mounts outside the cell's scratch volume, capabilities beyond `NET_RAW`/`NET_ADMIN`, unconfined seccomp or AppArmor. |
| Start, stop, kill, wait, remove, inspect, logs, attach, exec | Only on containers carrying this cell's `lab.run_id` |
| List or inspect images | Allowed (read-only). Pull, build, push and import are denied. |
| Networks and volumes | List or inspect own only. Volume create gets a forced label. Network create and connect are denied. |
| Everything else (swarm, plugins, system prune, events of other containers, …) | Denied |

- **Logging:** every request is logged as allowed or denied into the run's evidence. A denial is a containment signal: it shows on the Containment dashboard, and an attempted escape pattern triggers the containment alert.
- **Streams:** it must pass HTTP connection upgrades through, for attach and exec streams.
- **Build plan:** built in M0 with tests. Existing pieces (`mikesir87/docker-socket-proxy`, the OPA Docker authorization plugin) are evaluated first as a base.
- **Who needs it:** HackingBuddyGPT, PentestGPT and RedAmon's minimal stack never need the socket.

### 0.4 Sizing and parallelism

**Per-cell memory** (no Sysbox overhead):

| Cell | RAM (estimate, measured in M2) |
|---|---|
| HackingBuddyGPT + GOAT + proxies + catcher | ~2–3 GB |
| Strix (Kali sandbox + Chromium) + GOAT + proxies | ~5–7 GB |
| RedAmon minimal stack + GOAT + proxies | ~11–13 GB |
| Control plane + monitoring (always on) | ~5–6 GB |

| LXC size | Parallel cells (planning) |
|---|---|
| 8 cores / 32 GB | 2 (RedAmon one at a time) |
| 16 cores / 64 GB | 4–5 |

**Disk:** about 100 GB of images (RedAmon alone ~70 GB) plus artifacts (plan 100–200 GB for the pilot), so a **400 GB** root disk.

The runner sets `LAB_MAX_PARALLEL` and a per-agent concurrency cap from these numbers. It **never starts a cell that would exceed the LXC's free memory**; it waits instead.

### 0.5 The lab container as built (checked 5 Nov 2026)

**Container 111 `node-03-research` on node `Homelab-IC3`:**

| Check | Result |
|---|---|
| Proxmox / kernel | PVE 9.2.25, kernel 7.0.14-25-pve: past the CVE-2025-52881 Docker-in-LXC fix |
| Container type | Unprivileged (uid map `0 → 100000`), `nesting=1,keyctl=1` |
| OS | Ubuntu 24.04 LTS |
| CPU | **4 threads visible.** The host is an AMD PRO A10-9700E (4 cores), so the configured 5 cores are capped at 4. |
| RAM / swap | 8.2 GiB / 8.0 GiB |
| Disk | 300 GB ZFS subvolume (ZFS 2.4.4) |
| overlay2 prerequisites | Overlay mount on the ZFS rootfs works; nested user namespaces work |
| Netfilter | `nft` and `iptables` present |
| Time | Clock synchronised by the host (the container can't run its own NTP, and doesn't need to; `labctl doctor` checks the synchronised flag) |
| Docker | Not installed yet (the bootstrap installs it) |
| Outbound IPv4 | **Broken: no default route** (`net0` has no `gw=`). Fixed on the host with `gw=192.168.1.1`. |
| Outbound IPv6 | Works through a public IPv6 prefix from the ISP router. **Disabled for the lab** (see below). |
| Locale | Only `C`/`C.UTF-8` exist; bootstrap sets `LANG=C.UTF-8` |

**Changes these results force:**

1. **IPv6 off in the lab container.** The LAN hands out globally routable IPv6 addresses, which would bypass IPv4-only firewall rules in both directions.
   - The `sysctl` role sets `net.ipv6.conf.all.disable_ipv6=1` inside the container, which is allowed because it is a per-network-namespace setting.
   - The Proxmox firewall rules in §0.1 also get IPv6 equivalents: drop inbound, and drop outbound to the LAN `/64`, `fe80::/10` and `fc00::/7`.
   - Everything the lab needs is reachable over IPv4.
2. **Images are built in CI, not on the lab container.** A 4-core 2017 low-power CPU would take a very long time for the Angular build of Juice Shop and the Kali-based agent images.
   - **GitHub Actions** builds every image on each `lab-vN` tag. The repos are public, so the runners are free.
   - It pushes them to **GHCR** with SBOMs. The lab container only **pulls by digest** (`images.lock`).
   - `labctl build` on the server stays as a fallback.

   This replaces call (p) in the plan.
3. **One run cell at a time by default** (`max_parallel_cells: 1`). The second slot is opened only for HackingBuddyGPT cells once M2 has measured real CPU and memory use.

### 0.6 Final runs on CISPA hardware (decided 5 Nov 2026)

| Environment | Used for | Profile |
|---|---|---|
| Homelab LXC (CT 111) | Development and testing: M0–M2, self-tests, agent smoke runs, measuring each agent's footprint | `isolation: lxc`, one cell at a time |
| **CISPA hardware** | **The pilot (M3) and every experiment whose data goes into the paper** | **A VM on CISPA's Proxmox platform** with `isolation: sysbox` (the stronger per-cell-daemon design in §1–§4 and the feasibility study §4). Slurm WDR nodes with rootless Podman later, only if more scale is needed. |

Nothing in the harness is specific to either environment: the same release tag, `images.lock` and scripts deploy to both, selected by the host entry in `hosts.yml`.

Data from homelab runs is development data only and is never mixed into paper results.

**What CISPA offers (from the IT research portal, 5 Nov 2026; detail pages are login-gated and still to be read):**

| Service | Fit for this lab |
|---|---|
| **Proxmox virtualisation platform** ("custom environments") | **Preferred.** A CISPA VM is the environment this plan was written for: root, Docker, Sysbox per-cell daemons, and the control plane on the same machine. Target size for the pilot: 32 cores, 128 GB RAM, 1–2 TB disk. |
| **Slurm HPC**, especially the `wdr-01…13` nodes | **Scale-out later, if needed.** The WDR nodes have 64 cores / 128 threads, 2 TB RAM, no GPUs, a dedicated DFN egress, and are meant for web and network research. Slurm usually means no root and no Docker daemon. A `SlurmPodmanBackend` would run cells as **rootless Podman pods** inside Slurm jobs, with the control plane on the VM. That needs rootless Podman with user namespaces; Apptainer or Enroot alone share the host network and **cannot contain run cells**. |
| **AI/LLM gateway (LiteLLM)** covering Anthropic, OpenAI, Google Vertex/Gemini and others | **Candidate upstream for model traffic.** Chain: agent → our tap → **our** LiteLLM gateway (per-run virtual keys and budgets) → **CISPA gateway** → provider. The upstream is set per environment, and the homelab keeps calling providers directly. |

**Conditions for using the CISPA LLM gateway** (each checked before any paper run):
1. It must offer the **native Anthropic Messages route** (`/v1/messages` passthrough). An OpenAI-style translation would break signed thinking blocks and tool blocks for agents that use the Anthropic SDK.
2. We need to know whether Claude is served **directly by Anthropic or through Vertex/Bedrock**. That changes model IDs, the available features and refusal behaviour, so it is recorded on every run.
3. **No silent model aliasing or fallbacks** on their side. The tap's model assertion catches this, but it would invalidate runs.
4. Its rate limits and budgets are shared with the institute, so they set the pilot's concurrency.
5. Its logging and retention policy, and approval for offensive-security prompts on institutional accounts.

**To clarify with CISPA IT before M3:**
1. **A VM on the Proxmox platform:** size, root, Docker and Sysbox allowed, lifetime and renewal, and outbound access to GHCR and the model APIs (directly or through a proxy).
2. **Approval** to run contained offensive-security agents. Attack traffic never leaves the VM; only model API calls go out.
3. **Access** to the VM (VPN, SSH bastion), which replaces Twingate for that host.
4. **Data:** where run artifacts may be stored and backed up.
5. **The LLM gateway questions** above.
6. **Only if scaling to Slurm later:** the container runtime on the `wdr` nodes, user namespaces, maximum walltime, node-local scratch, and whether WDR jobs can reach the control-plane VM.

### 0.7 Quickstart for the LXC

```
cp deploy/hosts.example.yml deploy/hosts.yml   # address, ssh_user, isolation: lxc, access: twingate
./deploy/bootstrap.sh lab1                      # no disk formatting in the LXC profile
./deploy/secrets.sh lab1                        # paste ANTHROPIC_API_KEY + budget
./deploy/release.sh lab1 --tag v0.1.0           # deploy, build images, self-test
# then open https://<lxc-ip> over Twingate
labctl --remote lab1 pilot
```

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
  address: 10.0.0.20          # the LXC's IP, reachable over Twingate
  ssh_user: admin             # sudo-capable user for provisioning
  isolation: lxc              # lxc (current) | sysbox (VM / bare metal)
  access: twingate            # twingate | ssh-tunnel | wireguard | tailscale
  allow_containerd_pin: false # see §0.1; only as a documented stopgap
  cloudflare_tunnel: false    # public website/Grafana via Cloudflare Access (later)
  backup_repo: s3:https://…/lab-backups   # restic repository URL
  max_parallel_cells: 2
  # sysbox profile only:
  # data_disk: /dev/nvme1n1   # formatted only with --format-data-disk
  # artifact_disk: /dev/sda
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
