# Deployment: Running the Lab on a Separate Server

**Companion to:** [DEVELOPMENT_PLAN.md](DEVELOPMENT_PLAN.md), [AUTOMATION_FEASIBILITY.md](AUTOMATION_FEASIBILITY.md)
**Status:** plan and script specification. The M0 deploy scripts and the Ansible roles for the LXC profile are written (`deploy/`, tested by `tests/deploy/test_scripts.py`). Anything marked **not built in M0** is still design only.

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
- `vm.max_map_count=262144` in `/etc/sysctl.d/99-llm-lab.conf`, recommended for RedAmon's Neo4j. An unprivileged container cannot set it itself. The `sysctl` role only verifies it (and `fs.inotify.*`), and warns if it is low.
- Kernel modules for the container's firewall, which an unprivileged container may not autoload: `nft_fib_inet`, `nft_log`, `nf_log_syslog`, `nft_limit`, `nft_ct`, `nft_compat`, `xt_comment`, and `xt_tcpudp` on kernels where it is a separate module (on recent kernels it is part of `x_tables`). List them in `/etc/modules-load.d/llm-lab.conf` (§0.2). The `firewall` role checks for them before loading any rule and names any that are missing; without them `lab-firewall.service` fails and Docker does not start.
- Optional: `net.netfilter.nf_log_all_netns=1`, so the container's rate-limited firewall drop logs (prefix `lab-drop`) reach the kernel log. Without it, the drop counters still work. Task 17 checks which applies on CT 111.
- Do not boot the host with `ipv6.disable=1`: the cell compose files set `net.ipv6.*` sysctls, so container creation would fail (closed) and no cell could run. IPv6 is turned off per namespace instead (§0.5).
- **If the storage is ZFS:** ZFS ≥ 2.2 is required for Docker's overlay2 driver inside the LXC (`zfs version`). One community report describes an unprivileged-LXC file-permission problem on PVE 9.0 with ZFS 2.3.4; M0 checks for it.

**Proxmox firewall for the container** (enable the firewall at datacenter and container level):

| Direction | Rule |
|---|---|
| Inbound | Allow TCP 22 and 443 **only from the Twingate connector's IP**. Drop everything else. |
| Outbound | Allow DNS to the LAN resolver. **Drop** 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 and 100.64.0.0/10. Allow everything else: provider APIs, registries, Cloudflare. |
| IPv6 | Drop inbound. Outbound: drop the LAN `/64`, `fe80::/10` and `fc00::/7`. IPv6 is also disabled inside the container (§0.5). |

Docker's internal cell networks live *inside* the container's network namespace, so this firewall never interferes with traffic inside a cell. `labctl doctor` (built: control/cli/doctor.py) checks the database and schema head, the Collector's `/healthz` and `/metrics`, the Docker socket, `host.env` (`LAB_CELL_NETWORKS`), `lab.env`'s mode and owner and `lab-cell-egress check`. It does **not yet** check the Proxmox firewall or the clock-sync flag; that check, still to be built, is to try a LAN address from inside the LXC, which must fail, and a provider API, which must succeed.

**Access for the operator and for automation:** add the operator workstation's SSH public key to `root`'s `authorized_keys` in the container, and add the container's ports 22 and 443 as Twingate resources.
- **Documented exception (LXC profile only):** the container is provisioned as `root`, with key-only login, because CT 111 was set up with root SSH over Twingate. Root inside the unprivileged container maps to an unprivileged user on the Proxmox host.
- The `base` role first proves a key-only login works from the workstation, and only then turns off password login (`PermitRootLogin prohibit-password`).
- A VM (the sysbox profile, §0.6) keeps the standard rule: a non-root sudo user (`ssh_user: admin`) and `PermitRootLogin no`. `site.yml` refuses `ssh_user: root` there.

### 0.2 What the Ansible roles do differently

Selected with `isolation: lxc` in `hosts.yml`.

| Role | LXC behaviour |
|---|---|
| `storage` | No disk formatting (`--format-data-disk` is refused). Checks free space on `/` (≥ 50 GB by default) and that Docker uses `overlay2`; fails with guidance otherwise. |
| `sysbox` | Skipped (and refuses to run in an LXC) |
| `docker` | Same pinned Docker CE (one minor, never 29.1.0, apt-held, installed without Recommends). Starts a local test container to detect the CVE-2025-52881 breakage and stops with guidance (see §0.1). |
| `sysctl` | Applies only settings an unprivileged container may change (`net.ipv6.conf.{all,default}.disable_ipv6=1`, `net.ipv4.ip_forward=1`). Host-only settings are **verified**, not set. |
| `firewall` | See below. Runs **before** `docker`. |
| `access` | Twingate: nothing to install in the container; the connector runs elsewhere on the LAN |
| `caddy` | Listens on the container's IP, port 443 only, reachable over Twingate. `tls internal` (Caddy's own CA). Basic auth, with the login generated on the host (`/srv/lab/secrets/web-basic-auth`). Routes: `/api/*` → API, `/grafana*` → Grafana, everything else → website. Upstreams are on `127.0.0.1` and set as variables. |
| `cloudflared` *(off by default)* | **Not built in M0**: a stub that refuses to run when `cloudflare_tunnel: true`. Design: a tunnel from the LXC to Caddy for the website and Grafana hostnames only. **Cloudflare Access is required** on every hostname; the role refuses to enable a hostname without an Access policy reference. |
| `cell-guard` images | Built and pinned like every other harness image |

**The `firewall` role (fails closed).** nftables inside the LXC, in two layers.
- **Matching cells.** Cells are matched by **ingress interface as well as by source address**.
  - Every cell network is a Docker bridge named `labc<short-id>` (`com.docker.network.bridge.name`, at most 15 characters; set by the runner, Task 14b), with a subnet inside `lab_cell_networks`.
  - Agents keep `NET_RAW` because they need raw scans, so a source address alone could be forged. The interface match is the control.
1. **First layer.** Table `inet lab_host`, loaded by `lab-firewall.service`. A drop-in makes `docker.service` `Requires=` and `After=` this unit, so Docker never starts without it. The unit has no stop action: with `live-restore`, cells outlive a stop, so the table stays until reboot. The distribution's `nftables.service` is masked, because it flushes the whole ruleset.
   - Its prerouting chain (priority raw) runs a strict reverse-path check on `labc*` bridges: a source that would not route back out of the same bridge is dropped as forged.
   - Its input chain accepts loopback, then drops IPv6 and anything from a `labc*` bridge or a cell address. It then accepts only established/related traffic, ICMP, SSH and 443.
   - Its forward chain drops forwarded IPv6.
   - From a `labc*` bridge, the forward chain accepts only two kinds of traffic: traffic to another `labc*` bridge within the cell networks, and traffic to the LLM gateway, if one is configured. It drops everything else from a cell bridge, and any cell source address seen on another interface.
2. **Second layer.** The same policy as `-i labc+` and `-s <cell net>` rules in `DOCKER-USER`.
   - Like the first layer, it lets traffic within the cell networks (bridge to bridge) and to the gateway go on to Docker's own isolation rules.
   - It is re-applied whenever Docker starts, and `lab-cell-egress check` compares it line by line with the expected rules.
- **Logging and the shared variable:**
  - Drops are counted and logged at a limited rate (prefix `lab-drop`).
  - The cell networks are one variable (`lab_cell_networks`), also exported as `LAB_CELL_NETWORKS` in `/srv/lab/host.env` for the runner.
- **DNS.** `daemon.json` sets `dns` to `lab_upstream_dns`, a required, non-loopback resolver (on CT 111 the gateway, 192.168.1.1).
  - Docker's embedded DNS then forwards a cell's queries from the cell's own namespace, where the forward chain drops them.
  - With a loopback resolver (systemd-resolved's 127.0.0.53), dockerd would forward them from the host's namespace, around the firewall, so the role refuses one.
  - Task 17 checks that cells cannot resolve external names.
- **Proxmox host modules.** An unprivileged container may not autoload kernel modules, so the Proxmox host must have the modules the rules use: `nft_fib_inet` (fib; `nft_fib_ipv4`/`nft_fib_ipv6` come as dependencies), `nft_log` + `nf_log_syslog` (log), `nft_limit`, `nft_ct`, and for the DOCKER-USER rules `nft_compat`, `xt_comment` and `xt_tcpudp` (where it is a separate module). Put them in `/etc/modules-load.d/llm-lab.conf` on the host. The role checks `/sys/module` (and `modules.builtin`) first and stops with the names of missing modules. If one is missing anyway, `lab-firewall.service` fails and Docker does not start (closed).
- **Applying a changed ruleset** by hand: `systemctl reload lab-firewall` replaces the table atomically. Do not `restart` it: that also restarts Docker, through its `Requires=`.
- The Proxmox-level firewall is the manual step in §0.1. `labctl doctor` does not verify it yet (see §0.1).

### 0.3 cell-guard (new component)

**Agents never get the real Docker socket.** Each cell whose agent starts containers (Strix; PentAGI in Wave 2) gets its own **cell-guard**: a small validating proxy on a Unix socket. It is mounted where the agent expects `docker.sock`, or set as `DOCKER_HOST`. The runner alone uses the real socket.

It is **deny by default** and allows only the following:

| Request | Rule |
|---|---|
| Create a container | **Image:** must be an `images.lock` entry with `role: agent` (never a target, the harness `lab-cell` or a control-plane image); pinned to its digest. **Forced:** the network is the cell's internal network; labels `lab.run_id=<run>` and `lab.origin=cellguard`; memory, CPU and PID limits; the cell resolver as the only DNS server; the cell name prefix on the container name. **Names:** every network alias and the hostname must start with the cell prefix (`<run id lowercased>-`), so an agent container can never publish a cell service name (`target`, `tap`, `catcher`). **Denied:** privileged, host network/PID/IPC/user namespace, devices, any host-path (bind) mount (the only persistent mount is the cell's scratch named volume, without subpath), capabilities beyond `NET_RAW`, unconfined seccomp or AppArmor, agent-chosen DNS servers/search/options, extra hosts entries, links, domain name, MAC address, static endpoint addresses, any log driver or log options (the daemon's driver applies), top-level `Volumes` (unlabelled anonymous volumes; use `Mounts`), reserved labels (`lab.*`, `com.docker.*`). |
| Start, stop, kill, wait, remove, inspect, logs, attach, exec | Only on containers carrying both `lab.run_id=<run>` and `lab.origin=cellguard`, i.e. created through this cell's guard. Runner-created infrastructure (agent, target, oracle, the cell-guard container) never carries `lab.origin=cellguard` and is untouchable. |
| List or inspect images | Allowed (read-only). Pull, build, push and import are denied. |
| Networks and volumes | List or inspect own only. Volume create gets the forced labels and name prefix. Network create and connect are denied. |
| Everything else (swarm, plugins, system prune, events of other containers, …) | Denied |

- **Logging:** every request is logged as allowed or denied into the run's evidence. A denial is a containment signal: it shows on the Containment dashboard, and an attempted escape pattern triggers the containment alert.
- **Streams:** it must pass HTTP connection upgrades through, for attach and exec streams.
- **Callback DNS:** callback capture relies on the cell network being internal, with the catcher's resolver as the only DNS server reachable from it. The forced DNS server only sets the upstream of the daemon's embedded resolver; root in an agent container can rewrite its own `/etc/resolv.conf`, so the forced setting is not a boundary on its own.
- **Container logs:** agents cannot choose a log driver, so the daemon's default applies. The LXC's `daemon.json` sets a bounded, rotated file driver, never the host journal (the docker role sets `"log-driver": "json-file"` with `max-size`/`max-file` from `docker_log_max_size`/`docker_log_max_file`).
- **Build plan:** built in M0 with tests. Existing pieces (`mikesir87/docker-socket-proxy`, the OPA Docker authorization plugin) are evaluated first as a base.
- **Who needs it:** HackingBuddyGPT, PentestGPT and RedAmon's minimal stack never need the socket.
- **Known limit (accepted for M0): ARP spoofing on the cell bridge.** Agent containers keep `NET_RAW` (Docker's default; agents need raw scans), so on the shared cell network an agent container can ARP-spoof another container on that network (for example to intercept traffic meant for the target or the catcher). `NET_ADMIN` and static IP/MAC addresses are denied, so it cannot simply take over another container's address. Evidence integrity does not rest on the network: the catcher verifies every callback's token against the run manifest, and a spoofed callback cannot carry a valid token for another run. Separate agent, target and catcher networks per cell are an M1 design item.

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
| Time | Clock synchronised by the host (the container can't run its own NTP, and doesn't need to; `labctl doctor` is to check the synchronised flag; not built yet) |
| Docker | Not installed yet (the bootstrap installs it) |
| Outbound IPv4 | **Broken: no default route** (`net0` has no `gw=`). Fixed on the host with `gw=192.168.1.1`. |
| Outbound IPv6 | Works through a public IPv6 prefix from the ISP router. **Disabled for the lab** (see below). |
| Locale | Only `C`/`C.UTF-8` exist; bootstrap sets `LANG=C.UTF-8` |

**Changes these results force:**

1. **IPv6 off in the lab container.** The LAN hands out globally routable IPv6 addresses, which would bypass IPv4-only firewall rules in both directions.
   - The `sysctl` role sets `net.ipv6.conf.all.disable_ipv6=1` (and `default`) inside the container, which is allowed because it is a per-network-namespace setting. The firewall also drops all forwarded IPv6.
   - Hosts booted with `ipv6.disable=1` cannot run cells: the cell compose files set `net.ipv6.*` sysctls, so container creation fails closed.
   - The Proxmox firewall rules in §0.1 also get IPv6 equivalents: drop inbound, and drop outbound to the LAN `/64`, `fe80::/10` and `fc00::/7`.
   - Everything the lab needs is reachable over IPv4.
2. **Images are built in CI, not on the lab container.** A 4-core 2017 low-power CPU would take a very long time for the Angular build of Juice Shop and the Kali-based agent images.
   - **GitHub Actions** builds every image on each `lab-vN` tag. The repos are public, so the runners are free.
   - It pushes them to **GHCR** with SBOMs. The lab container only **pulls by digest** (`images.lock`).
   - `labctl build` on the server stays as a fallback.

   This replaces call (p) in the plan.

   **Built today** (`.github/workflows/build-images.yml`, no SBOMs yet): one job per image, each pushing `ghcr.io/lordprime/<name>`.

   | Job / name | Dockerfile, build context | `images.lock` role | Checked before the push |
   |---|---|---|---|
   | `goat-dvga` | `targets/dvga/Dockerfile`, the two fork checkouts pinned in `targets/dvga/source.yaml` and `cell/oracle/source.yaml` | `target` | tools, file modes, nothing grader-related readable by the app user, `tests/targets/test_dvga_image.py` |
   | `lab-cell` | `cell/Dockerfile`, the repository root (root `.dockerignore` allow-list) | `infra` | runs as 10001:10001; every in-cell module imports; `mitmdump`, `uvicorn`; `/evidence` 10001 0750; no control-plane code beyond `control/core` |
   | `control` | `deploy/compose/control.Dockerfile`, the repository root (`control.Dockerfile.dockerignore`) | `control` | runs as 10001:10001; `python -m control.api --help` and `python -m control.cli.migrate --help`; the Alembic head is found; no in-cell code, mitmproxy or pytest |

   Every job pins its actions by commit SHA, checks out with `persist-credentials: false` and holds only `contents: read` and `packages: write` (`tests/deploy/test_build_images_workflow.py` checks these). The workflow never edits `images.lock`.

   **Building and pinning a digest:**
   1. Trigger the workflow: push a `lab-vN` tag (e.g. `git tag lab-v1 && git push origin lab-v1`; the image tag is then `lab-v1`), or run it by hand (`gh workflow run build-images.yml --ref main`, or *Actions → build-images → Run workflow*; the image tag is then `sha-<12 hex>`).
   2. Each job reads the pushed digest from `docker image inspect` (`RepoDigests`), checks it is `sha256:` + 64 hex, and writes a ready `images.lock` entry to its job summary and to the `<name>-digest` artifact (`gh run download <run-id> -n lab-cell-digest`).
   3. Paste the entry into `deploy/images.lock` (replacing an older entry of the same name) with its `name`, `image` (the repository, no tag), `digest`, `expect_tools` and `role`: `goat-dvga` → `target`, `lab-cell` → `infra`, `control` → `control`. cell-guard lets an agent start only `role: agent` images, so none of these three can be started from inside a cell.
   4. Commit it for review, then tag the release: `release.sh` pulls every `images.lock` entry by digest.

   The control-plane compose file still builds `lab/control:<tag>` from the release tree; switching its `migrate` and `collector` to the pinned `control` image (and dropping `--allow-build`) is a separate reviewed change.
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
| **Oak Proxmox cluster**: VMs on request through a Jira form; any CPU/RAM/disk/OS; **full root** plus hypervisor-console access; research use only; `qemu-guest-agent` required; ports reachable over the CISPA VPN are declared in the request | **Chosen.** A CISPA VM is the environment this plan was written for: root, Docker, Sysbox per-cell daemons, and the control plane on the same machine. Target size for the pilot: 32 cores, 128 GB RAM, 1–2 TB disk. |
| **Slurm HPC**, especially the `wdr-01…13` nodes | **Scale-out later, if needed.** The WDR nodes have 64 cores / 128 threads, 2 TB RAM, no GPUs, a dedicated DFN egress, and are meant for web and network research. Slurm usually means no root and no Docker daemon. A `SlurmPodmanBackend` would run cells as **rootless Podman pods** inside Slurm jobs, with the control plane on the VM. That needs rootless Podman with user namespaces; Apptainer or Enroot alone share the host network and **cannot contain run cells**. |
| **AI/LLM gateway (LiteLLM)** covering Anthropic, OpenAI, Google Vertex/Gemini and others | **Candidate upstream for model traffic.** Chain: agent → our tap → **our** LiteLLM gateway (per-run virtual keys and budgets) → **CISPA gateway** → provider. The upstream is set per environment, and the homelab keeps calling providers directly. |

**The Oak VM request (as submitted):**

| Field | Value |
|---|---|
| CPU | 32 cores, CPU type `host`; nested virtualisation if available (only for the KVM-per-cell fallback) |
| RAM | 128 GB |
| Disks | 100 GB OS disk + **1.5 TB second disk left unformatted** (we format it XFS with reflink for Docker, Sysbox and artifacts) |
| OS | Ubuntu Server 24.04 LTS; pre-installed `qemu-guest-agent` and `openssh-server` only (everything else via our Ansible) |
| Ports over VPN | tcp/22 (SSH), tcp/443 (website, API, Grafana behind Caddy with login) |
| Outbound | HTTPS to model APIs, GHCR, Docker Hub, PyPI, npm, GitHub, ftp.drupal.org, archive.debian.org; nothing inbound from outside CISPA |
| End date | 31.08.27 (covers USENIX Security '27 Cycle 2 artifact evaluation) |

**Kubernetes/ArgoCD platform:** not used for run cells. They need privileged or Sysbox runtimes and per-run network isolation, which a shared cluster is unlikely to allow. It could host the control plane later.

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
cp deploy/hosts.example.yml deploy/hosts.yml   # lab1: 192.168.1.145, root, isolation: lxc, access: twingate
./deploy/bootstrap.sh lab1                      # Ansible via uvx; no disk formatting in the LXC profile
./deploy/secrets.sh lab1                        # ANTHROPIC_API_KEY + LAB_BUDGET_USD
                                                #   (M0: a placeholder key with --no-test-calls)
./deploy/release.sh lab1 --tag v0.1.0           # deploy, pull images by digest, self-test
                                                #   (--allow-build only as a fallback)
./deploy/tunnel.sh lab1                         # Twingate: prints the URLs; no tunnel needed
# then open https://<lxc-ip>/ over Twingate; login: ssh root@<lxc-ip> cat /srv/lab/secrets/web-basic-auth
ssh root@<lxc-ip> labctl doctor                # labctl is installed per release (§4.2);
                                                #   `labctl --remote` and `pilot` are not built yet
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
| **Workstation** (developer laptop or desktop) | Write code, run unit tests, deploy, watch | git, uv, Ansible (run by the scripts with `uvx --from ansible-core==2.22.0`; nothing installed globally), the deploy scripts, `labctl` **in remote mode**, a browser |
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
| **(a) SSH tunnel** | Zero setup; `./deploy/tunnel.sh` (`access: ssh-tunnel`). The default for a VM. The LXC uses **Twingate** (§0), where `tunnel.sh` only prints the URLs. |
| **(b) WireGuard** | Self-hosted; good for a multi-person team |
| **(c) Tailscale** | Easiest for a team, but adds a third-party coordination service |

Whichever is chosen, the website, the APIs and Grafana are reached **only** through Caddy on the private interface, with authentication.

---

## 2. What changes because the server is separate

| # | Change | Plan section affected |
|---|---|---|
| 1 | **`labctl` becomes client/server.** The CLI runs on the server *or* on the workstation (`labctl --remote lab1 …`) against the Control API over HTTPS with an API token. Every command works either way. **In M0** labctl runs on the server only (installed per release, §4.2); `--remote` and the Control API token are **not built**. | Plan §3.3 C, §5 |
| 2 | **Web UI, APIs and Grafana are behind Caddy with auth**, bound to the private interface (or localhost + SSH tunnel). They are no longer "localhost-only on the laptop". Roles: `viewer`, `operator` (start, pause, schedule), `admin` (tokens, deploys). | Plan §6 |
| 3 | **Secrets live only on the server:** `/srv/lab/secrets/lab.env`, mode 0600, owner `lab`. They are pushed once with `deploy/secrets.sh` and never stored on the workstation after the push (the script reads them from the prompt or a file and doesn't keep a copy). | Plan §5.1 |
| 4 | **Images are built on the server** in a separate build phase. The host has internet, the cells don't. Images are pushed to the server's local registry (`127.0.0.1:5000`) and pinned in `images.lock`. CI can build and push instead, using the same registry over the private channel. | Feasibility §6.2 |
| 5 | **Services are managed by systemd** (wrapping `docker compose`), restart automatically, and survive reboot. On start, the runner **reconciles**: it finds cells left over from a crash, records those runs as `invalid: host_restart`, reaps the cells and re-queues the runs. **In M0** `release.sh` starts the control plane with `docker compose up -d --wait` (compose project `lab`), and containers restart through their compose restart policy. The `lab` role's systemd units and timers are **not built in M0**. | Plan §5.4 |
| 6 | **Pinned system packages.** Docker, containerd, Sysbox and the kernel are held (`dpkg` hold) and blocklisted for unattended upgrades, so they can't change mid-experiment. They are upgraded only through `deploy/upgrade-host.sh` (**not built in M0**) in a maintenance window, followed by a self-test. | Feasibility §6.1 |
| 7 | **Time sync** is mandatory, because the evidence ordering across injector, tap, catcher and pcap depends on it. `labctl doctor` fails if clock offset > 50 ms. A VM runs chrony (installed by `base`). An LXC uses the Proxmox host's clock and cannot run its own NTP, so `labctl doctor` is to check the synchronised flag (neither clock check is built yet). | Plan §3.1 |
| 8 | **Remote observability and alerts:** nobody is watching the box, so the server pushes notifications (see [TRACKING.md](TRACKING.md)). | new |
| 9 | **Storage layout and backups:** XFS data volume, reflink golden roots, artifact retention, nightly restic backups, and a restore drill before the pilot. | new |
| 10 | **Release tracking:** the deployed release tag + git SHA is recorded on every run and shown on every page footer. | Plan §5.5 |
| 11 | **Orphan reaping:** a systemd timer removes cells, networks and volumes whose run is no longer `running` (identified by the `lab.run_id` label). | Plan §5.4 |

---

## 3. Server layout

```
/srv/lab/
  host.env                 # host profile, not secret (isolation, LAB_CELL_NETWORKS, containerd pin, ...)
  releases/<tag>/          # unpacked release trees (code, compose files, configs) + RELEASE (tag, commit, sha256)
  releases/<tag>/.venv/    # labctl for that release (uv sync --frozen from its uv.lock, host uv + Python)
  releases/.state/         # rollback target and pending pre-migration dump of the release in progress
  current -> releases/<tag>
  deployments.jsonl        # one line per deploy or rollback (M0; the deployments table comes later)
  secrets/lab.env          # 0600 lab:lab  (provider keys, budgets, notify URLs; written by secrets.sh;
                           #   LAB_DB_PASSWORD is generated once by bootstrap.sh and always kept)
  secrets/hmac.key         # callback-token key, 32 random bytes (generated once by bootstrap.sh)
  secrets/web-basic-auth   # Caddy login, root 0600 (generated once by bootstrap.sh)
  secrets/ca/              # lab CA for the callback catcher's TLS (generated by the catcher on first run)
  db/                      # lab:lab 0700 (base role)
  db/pgdata/               # Postgres data directory (PostgreSQL ≥ 13, image pinned in images.lock),
                           #   mounted as the db container's data directory; created by release.sh,
                           #   owned by postgres (uid 999) after the first start; never managed by Ansible
  state/                   # 0755: selftest.json, the last self-test result (read-only in the Collector)
  cells/<run_id>/          # per-run state (sysbox profile: reflink clone + run volume); deleted after shipping
  artifacts/               # write-once run artifacts (separate disk recommended)
  ops/                     # prometheus, grafana, loki data
  backups/                 # pre-migration dumps; local staging for restic
  registry/                # sysbox profile only, not built in M0 (the LXC pulls from GHCR)
  golden/<images.lock-hash>/docker/   # sysbox profile only, not built in M0
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
- Shared code lives in `deploy/lib.sh`. Steps that run on the host are real scripts in `deploy/remote/`, shipped over SSH. Secret values and release archives travel on stdin, never in argv.

### 4.1 `deploy/hosts.yml` (copied from `hosts.example.yml`)

```yaml
lab1:                         # the LXC profile (CT 111)
  address: 192.168.1.145      # the LXC's IP, reachable over Twingate
  ssh_user: root              # LXC exception: root, key only (§0.1)
  ssh_port: 22                # optional, default 22
  isolation: lxc              # lxc (current) | sysbox (VM / bare metal)
  access: twingate            # twingate | ssh-tunnel | wireguard | tailscale (the last two not built in M0)
  allow_containerd_pin: false # see §0.1; only as a documented stopgap
  cloudflare_tunnel: false    # public website/Grafana via Cloudflare Access (later; stub in M0)
  max_parallel_cells: 1       # §0.5
  # backup_repo: s3:https://…/lab-backups   # accepted, but backups are not built in M0
  # vars: {lab_llm_gateway_address: …}      # optional extra Ansible variables

cispa1:                       # the sysbox profile (a VM, §0.6), not usable in M0
  address: 192.0.2.20
  ssh_user: admin             # non-root sudo user; root login is off
  isolation: sysbox
  access: ssh-tunnel
  max_parallel_cells: 4
  # data_disk / artifact_disk: not built in M0 (refused as unknown keys)
```

The scripts validate every host entry: an unknown key, a bad type or a bad value stops them before anything runs. `bootstrap.sh` turns the entry into an Ansible inventory.

### 4.2 Scripts

| Script | Purpose | What it does, in order | Target time |
|---|---|---|---|
| **`bootstrap.sh <host> [--check] [--format-data-disk] [--skip-doctor]`** | Turn a fresh Ubuntu 24.04 install into a lab server | 1. Validate the host in `hosts.yml` and render an Ansible inventory. 2. Run `ansible/site.yml` against the host with `uvx --from ansible-core==2.22.0 ansible-playbook` (nothing installed globally; `--check` is a `--check --diff` dry run). The roles are in §4.3; they generate the HMAC key, the web login and `LAB_DB_PASSWORD` (in `lab.env`) on the server if absent, and install a pinned `uv` and labctl's Python. 3. Run `labctl doctor` remotely and print the report; if labctl is not installed yet, warn and continue. `--format-data-disk` is refused in the LXC profile and not built for the sysbox profile. *Not built in M0:* starting the registry and ops stack. | ≤ 20 min |
| **`secrets.sh <host> [--from-file path] [--validate-only] [--no-test-calls]`** | Install or rotate provider keys and settings | 1. Prompt for (or read) each variable in `.env.example`: required (`ANTHROPIC_API_KEY`, `LAB_BUDGET_USD`) and optional (other providers, `NOTIFY_*`). Enter keeps the host's current value. 2. Validate each value against the type tag in its `.env.example` comment (shows variable **names** only, never values). 3. Write `secrets/lab.env` atomically over SSH (mode 0600, owner `lab`). Values travel on stdin, and an `END <count>` marker must arrive before the file is replaced. `LAB_DB_PASSWORD` is not operator-supplied: bootstrap.sh generates it once on the host; every write carries it over unchanged and a value for it is refused (Postgres keeps the password it was initialised with). 4. Recreate the control-plane services whose environment changed. 5. Make one zero-cost test call per provider (a model-list request) from the server and report OK or failed (`--no-test-calls` for M0's placeholder key). | ≤ 2 min |
| **`release.sh <host> --tag vX.Y.Z [--allow-build] [--skip-selftest]`** | Deploy a version | 1. Refuse if the git tree is dirty or the tag is missing; the tag must contain `deploy/compose/control-plane.yml` and a fully pinned `deploy/images.lock`. 2. If run cells are in flight (containers labelled `lab.run_id`): **refuse**. 3. `git archive` the tag and stream it over SSH into `releases/<tag>`, verified by SHA-256. A tag that moved to another commit is refused. 4. Pull every `images.lock` image by digest, plus the control-plane images, which must all be pinned by digest. `--allow-build` builds on the server instead, as a fallback only: images are built in CI (§0.5). Images that are pulled must still be pinned. **Until CI publishes a pinned control-plane image, every release needs `--allow-build`**: the Collector/migrate image is built from the release tree and tagged per release, `lab/control:<tag>` (release.sh sets `LAB_RELEASE_TAG` on every compose call, so a rollback starts the previous release's own image, never the failed release's migrate). Then install labctl for the tag into `releases/<tag>/.venv` with the host's pinned uv (`uv sync --frozen --no-dev`); `/usr/local/bin/labctl` links to `current/.venv/bin/labctl`, so activating or rolling back switches labctl too. A labctl that cannot be installed stops the release before anything changes. 5. If the release has a `migrate` service: stop the app services (the database keeps running), take a `pg_dump`, then run `compose run --rm --no-deps migrate`. If a release is deployed but its database is not running, it refuses (no migration without a dump). 6. Swap the `current` symlink and restart the services (`compose up --wait`). 7. `labctl selftest --quick` (one target, no tokens), if labctl is installed. **Until Task 15b-2 lands, `labctl selftest` is a stub that exits 2, so releases need `--skip-selftest`** (otherwise they roll back). 8. On failure in 5–7: **automatic rollback**: stop the app services, check the dump (`pg_restore --list`), restore it into a scratch database `<db>_rb` (`CONNECTION LIMIT 0`, `--single-transaction --exit-on-error`), and only then swap it in, in one transaction: the live database is renamed to `<db>_old` and the scratch one into its place (so a database always exists under the live name, and the rollback can be run again), then `<db>_old` is dropped. The rollback needs **PostgreSQL ≥ 13** (`DROP DATABASE … WITH (FORCE)`), and `POSTGRES_DB` may be at most 59 bytes (so `<db>_rb` / `<db>_old` fit PostgreSQL's 63-byte names; `migrate` checks it before it stops anything). Then swap `current` back, start the previous release and exit non-zero. A bad dump or a failed restore drops the scratch copy and leaves the live database untouched. Any failure prints where `current` and the database stand, and the dump path. 9. Record the deployment (tag, SHA, who, when) in `/srv/lab/deployments.jsonl`; the `deployments` table comes with the control plane. *Not built in M0:* `--drain` (there is no queue pause yet). | ≤ 10 min (warm caches) |
| **Control-plane services** | `deploy/compose/control-plane.yml` (project `lab`) | `db` (Postgres, published on `127.0.0.1:5432` for labctl), `migrate` (one-shot `alembic upgrade head`), `collector` (Collector API and `/metrics`, published on `127.0.0.1:8100`; **not** behind Caddy, whose `127.0.0.1:8000` upstream is for the Control/Results API). Nothing binds anything but 127.0.0.1; the network is 172.31.231.0/24, outside the cell range. No container gets the Docker socket. | — |
| **`status.sh <host>`** | Quick health | Deployed tag; host profile; Docker version and storage driver; control-plane services; run cells in flight; queue and spend vs budget (via `labctl status` once installed); `lab.env` variable count, mode and owner; both firewall layers (`lab-cell-egress check`) and drop counters; disk free; memory. Last backup time is n/a in M0. Exits 1 when degraded. | seconds |
| **`tunnel.sh <host> [--local-port N]`** | Private access | With `access: twingate`: no tunnel, prints the URLs and where the web login is. With `access: ssh-tunnel`: `ssh -N -L 127.0.0.1:8443:<address>:443` to Caddy. | seconds |
| **`rollback.sh <host> [--to vX.Y.Z]`** *(not built in M0; `release.sh` rolls back on failure)* | Return to a previous release | Swap the symlink back, run down-migrations to that release's schema (or restore the pre-migration dump), restart, run the self-test | ≤ 5 min |
| **`build.sh <host> [--all]`** *(not built in M0; images are built in CI)* | Rebuild images without a release (e.g. a GOAT content-pack change) | `labctl build` on the server; prints the new `images.lock` diff | varies (first full build: ~1–2 h, RedAmon and Kali images dominate) |
| **`logs.sh <host> [service\|--run <run_id>] [-f]`** *(not built in M0)* | Read logs | journald or Loki query by service or by `run_id` | seconds |
| **`backup.sh <host>` / `restore.sh <host> --snapshot <id>`** *(not built in M0)* | Off-machine copies | `pg_dump` + artifacts → restic. A nightly systemd timer runs the same thing. Restore is documented and **drilled once before the pilot**. | depends on size |
| **`reap.sh <host>`** *(not built in M0)* | Clean up orphans by hand (a timer also does this) | Remove cells, networks and volumes labelled `lab.run_id` whose run isn't running | seconds |
| **`upgrade-host.sh <host>`** *(not built in M0)* | Planned upgrade of the pinned Docker, Sysbox or kernel | Refuse during experiments → unpin → upgrade → reboot if needed → re-pin → `labctl doctor` + full self-test | ≤ 30 min |

### 4.3 Ansible roles (`deploy/ansible/`)

| Role | Responsibilities |
|---|---|
`site.yml` runs the roles in this order: `base`, `storage`, `sysctl`, `firewall`, `docker`, then `sysbox` (sysbox profile only), `access`, `caddy`, and `cloudflared` (only with `cloudflare_tunnel: true`). The `firewall` role comes before `docker`, so Docker is never started without the host firewall. Pre-checks: Ubuntu 24.04; the LXC profile runs in an LXC guest; a VM is provisioned as a sudo user. The roles are `ansible-lint` clean (production profile) and support `--check`.

| Role | Responsibilities |
|---|---|
| `base` | See below |
| `storage` | Free-space check on `/` and the `overlay2` check (§0.2). *Sysbox profile, not built in M0:* check (and, only with `--format-data-disk`, create) XFS with `ftype=1,reflink=1`; fstab entries |
| `docker` | Docker CE 29.x from Docker's apt repo, pinned to one minor (`docker_ce_minor`, **never 29.1.0**). The keyring must hold exactly Docker's release key. Installed without Recommends and apt-held. Compose plugin ≥ 2.24. The key is downloaded to a candidate file and checked before it replaces the trusted keyring. `/etc/docker/daemon.json`: overlay2, log rotation, `live-restore`, IPv6 off, `dns` set to the non-loopback `lab_upstream_dns`, default address pools that don't overlap the cell subnets or the LAN; data-root on the XFS disk only in the sysbox profile. Then the CVE-2025-52881 container start test (§0.1) |
| `sysbox` | Download the Sysbox 0.7.1 `.deb`, **verify its SHA-256** (`sysbox_deb_sha256`, required), install, and check `sysbox-runc --version`. Refuses in an LXC |
| `sysctl` | Namespaced settings: IPv6 off, `net.ipv4.ip_forward=1`. Host-only settings (`vm.max_map_count=262144` for Neo4j, `fs.inotify.*`) are verified in the LXC and warn when low. *Setting them for the sysbox profile is not built in M0* |
| `firewall` | Fail-closed nftables in two layers (§0.2). Cells are matched by bridge name (`labc*`) and by source address. Strict reverse-path filtering on cell bridges catches forged sources. Layer 1: table `inet lab_host`, loaded by `lab-firewall.service`, which `docker.service` requires. Its input chain is default-drop except loopback, established, ICMP, SSH and 443, and it drops IPv6 and anything from a cell. Its forward chain drops forwarded IPv6 and cell egress. Layer 2: in the `DOCKER-USER` chain, **drop all forwarding from cell bridges and cell subnets, except between cell networks and to the LLM gateway IP:port**. Drops are counted, and logged at a limited rate, for the containment report |
| `access` | twingate and ssh-tunnel: nothing to install. WireGuard (keys + peer config) and Tailscale (install + join with an auth key supplied interactively): **not built in M0**, refused |
| `caddy` | Reverse proxy on the private address only (the LXC: its IP, port 443): website, Control/Results API and Grafana under one TLS origin; `tls internal`; basic auth for the pilot with a login generated on the host (OIDC later) |
| `cloudflared` | **Not built in M0**: a stub that refuses to run (§0.2) |
| `registry` | **Not built in M0** (the LXC pulls from GHCR): `registry:2` bound to 127.0.0.1:5000, storage in `/srv/lab/registry` |
| `ops` | **Not built in M0**: Prometheus (scrapes node-exporter, cAdvisor and lab services), Grafana with the provisioned dashboards from [TRACKING.md](TRACKING.md), Loki + promtail (container logs, labels incl. `run_id`), Alertmanager → notification webhook. Its host-side ports must be added to the firewall's input chain |
| `lab` | **Not built in M0**: systemd units: `lab-control.service` (compose stack: Postgres, APIs, runner workers, scheduler, gateway, website), `lab-reaper.timer`, `lab-backup.timer`, `lab-selftest.timer` (nightly, in the maintenance window) |

**`base`**
- Updates and packages: git, jq, curl, tcpdump, nftables, iptables, restic, openssl, rsync. chrony only on a VM. fail2ban only when not behind Twingate (all clients share the connector's IP).
- Locale `C.UTF-8`.
- Creates the `lab` user and the `/srv/lab` tree with ownership.
- Generates the HMAC key once, and `LAB_DB_PASSWORD` in `secrets/lab.env` once (256 bits, never regenerated). If `db/pgdata` is already initialised but `lab.env` has lost the password, it stops with recovery steps instead of generating one Postgres would reject.
- Creates `state/` (the self-test status) with the rest of the tree; never `db/pgdata`.
- Installs a pinned `uv` (release tarball checked against its SHA-256) on root's PATH and, with it, labctl's pinned Python 3.12 under `/opt/lab/python`.
- **SSH hardening.** Key-only login, turned on only after a key-only login is proven. `PermitRootLogin` depends on the profile: `prohibit-password` for the LXC (§0.1 exception), `no` on a VM.
- Unattended security upgrades, with docker-ce, containerd, sysbox and linux-image held and blocklisted.

### 4.4 The fresh-server quickstart

This is the VM / bare-metal (sysbox) path. The LXC quickstart is §0.7. `--format-data-disk` and the sysbox profile are **not built in M0**.

```
cp deploy/hosts.example.yml deploy/hosts.yml     # set address, sudo user, disks, access method
./deploy/bootstrap.sh cispa1 --format-data-disk   # provision (≈20 min); not built in M0
./deploy/secrets.sh cispa1                        # paste ANTHROPIC_API_KEY + budget
./deploy/release.sh cispa1 --tag v0.1.0           # deploy, pull images by digest, self-test
./deploy/tunnel.sh cispa1                         # access: ssh-tunnel → open https://localhost:8443
ssh cispa1 labctl doctor                          # `labctl --remote` and `pilot` are not built yet
```

Beyond that, the user only fills in `.env` values. Everything else is scripted, idempotent and verified by `labctl doctor` and the self-test (labctl doctor, status, runs ls and run show are built; `selftest` arrives with Task 15b-2; `--remote` and `pilot` are not built).

---

## 5. Operating rules

- **Maintenance window** (configurable; default Sunday 03:00–05:00 server time): nightly self-test, backups, image garbage collection. Host upgrades happen only here.
- **No deploys during a running experiment.** `release.sh` refuses while any run cell is in flight. `--drain` (pause the queue, wait for in-flight runs) is **not built in M0**. An experiment's runs all use one release; the experiment records it and refuses to resume on a different release unless it is explicitly re-registered.
- **Artifact retention:**
  - raw artifacts are kept for the life of the paper and backed up;
  - pcaps older than 90 days can be compressed to `.pcap.zst`;
  - nothing is deleted automatically.
- **Disk guard:** the runner stops claiming new runs below 15% free on either disk and raises an alert.
- **Key rotation:** `secrets.sh` at any time. Per-run virtual keys mean rotation never interrupts in-flight runs.
- **Disaster recovery:** a new server plus `bootstrap.sh`, `restore.sh` and `release.sh` gets back to the last backup. This is drilled before the pilot.
