# Task 17 runbook: first deployment to CT 111

**Companion to:** [DEPLOYMENT.md](DEPLOYMENT.md) (§0 the LXC profile, §4 the scripts), [TRACKING.md](TRACKING.md) (§3.3 the self-test), [M0_HANDOFF.md](M0_HANDOFF.md).

Task 17 is M0's acceptance run on the real host: the Proxmox container CT 111 (`192.168.1.145`). Work through the phases in order. Each step says what counts as a pass. If a step fails, stop there and record the output. A full reset is `pct rollback 111 pre-m0` (snapshot from step 1).

Task 17 is **complete** only when every step passes and the self-test runs for real (it was not skipped with `--skip-selftest`).

---

## P0 Proxmox host and access (the user does these)

1. **Host and container.**
   - `pveversion` is at least 9.1 (expected: 9.2.25).
   - `pct config 111` shows: `unprivileged: 1`, `features: nesting=1,keyctl=1`, `gw=192.168.1.1` and `firewall=1` on `net0`.
   - Take a snapshot: `pct snapshot 111 pre-m0`.
2. **Kernel modules** (an unprivileged container cannot load them itself; DEPLOYMENT §0.1).
   - Write `/etc/modules-load.d/llm-lab.conf` with `nft_fib_inet`, `nft_log`, `nf_log_syslog`, `nft_limit`, `nft_ct`, `nft_compat`, `xt_comment`, and `xt_tcpudp` if `modinfo xt_tcpudp` finds it (on recent kernels it is built into `x_tables`).
   - Load them with `modprobe`.
   - **Pass:** `lsmod` lists every one.
   - **Record:** `lsmod | grep br_netfilter` and `sysctl net.netfilter.nf_log_all_netns`.
3. **Proxmox firewall** for the container, as in DEPLOYMENT §0.1: inbound 22 and 443 from the Twingate connector only; outbound DNS to the resolver and nothing else on the LAN; the IPv6 rules.
   - The DNS exception is the one LAN path left open, so the self-test's LAN check probes `192.168.1.1:53`: from the host it must answer (TCP 53 or a UDP/53 DNS reply), from a cell it must not.
   - **State on 9 Nov 2026:** this Proxmox firewall is **not configured** on CT 111. Ruling: Task 17 goes ahead without it, because cell containment rests on the in-LXC layers (nftables and `DOCKER-USER`), and those are what P5 checks. Enabling it is recommended before any study run: it is defence in depth, and it limits the container's LAN egress to DNS. Until it is on, the LXC itself can reach the LAN; cells still cannot.
4. **Access.**
   - Add Twingate resources for `192.168.1.145`, ports 22 and 443.
   - Put the workstation's public key in the container's `/root/.ssh/authorized_keys`.
   - **Pass:** `ssh -o BatchMode=yes root@192.168.1.145 true` exits 0.

## P1 Workstation

5. **Clean tree and green CI.**
   - Merge the final fixes to `main`; `git status --porcelain` prints nothing.
   - `deploy/hosts.yml` exists (git-ignored; created from `hosts.example.yml` on 9 Nov 2026). Its `lab1` vars carry `docker_ce_minor: "29.8"`. That is now also the role default, so the override can stay or go.
   - `LAB_REQUIRE_TOOLS=1 uv run pytest -q`, then push.
   - **Pass:** CI is green on the pushed commit.
6. **Build and pin the images** (DEPLOYMENT §0.5).
   - Run the build-images workflow on `main` (*Actions → build-images → Run workflow*, or push a `lab-vN` tag). **Pass:** all three jobs (`goat-dvga`, `lab-cell`, `control`) are green.
   - Make the three GHCR packages public (*Package settings → Change visibility → Public*). **Pass:** an anonymous pull works for each one: `DOCKER_CONFIG=$(mktemp -d) docker pull ghcr.io/lordprime/lab-cell@sha256:…`.
   - Paste the `lab-cell` and `goat-dvga` entries from the job summaries into `deploy/images.lock`, with their roles (`lab-cell` → `infra`, `goat-dvga` → `target`). The `control` entry may be added too, but the control-plane compose file still builds `lab/control:<tag>` on the host until a separate change switches it.
   - `uv run pytest tests/deploy/test_images_lock.py`, commit, push, then `git tag -a v0.1.0 -m M0`.

## P2 Bootstrap

7. `./deploy/bootstrap.sh lab1`. **Pass:**
   - the play recap shows `failed=0`;
   - the output has `OK: a test container started and exited cleanly` (the CVE-2025-52881 check);
   - the egress check reports OK.
   - If the container start test fails, **stop**. Do not set `allow_containerd_pin`: its 1.7.28 pin dates from Docker 29.1, and the repository now ships containerd.io 2.4.x with Docker 29.8. Record the error.
8. Run it again. **Pass:** the recap shows `changed=0`.
9. **Checks on CT 111.** **Pass:** each of these holds.
   - `systemctl is-active lab-firewall lab-cell-egress docker caddy`: all four `active`.
   - `systemctl show docker -p Requires` includes `lab-firewall.service`.
   - `lab-cell-egress check` prints OK.
   - `docker info`: storage driver `overlay2`, not the containerd snapshotter (`daemon.json` sets `features.containerd-snapshotter: false`); server version `29.8.x` (the configured `docker_ce_minor`), never 29.1.0.
   - `jq .dns /etc/docker/daemon.json` prints `["192.168.1.1"]`.
   - `/srv/lab/host.env` has `LAB_CONTAINERD_PINNED=false` and `LAB_PROBE_LAN=192.168.1.1`.
   - `secrets/hmac.key`, `secrets/lab.env` and `secrets/web-basic-auth` are mode 600.
   - `sysctl net.ipv6.conf.all.disable_ipv6 net.ipv4.ip_forward`: both 1.
   - From the workstation: `curl -sk -o /dev/null -w '%{http_code}' https://192.168.1.145/` prints `401`.
   - From the LXC: `curl -m5 http://192.168.1.1/` fails (only once the Proxmox firewall of step 3 is on; record the result either way); `curl -sI https://api.anthropic.com` answers; `getent hosts example.com` resolves.
   - **Record:** `cat /proc/sys/net/bridge/bridge-nf-call-iptables` (if present) and `dpkg-query -W containerd.io` (the exact revision).

## P3 Secrets (stub LLM only, no real keys)

10. Install placeholder settings:
    ```
    ./deploy/secrets.sh lab1 --no-test-calls --from-file <(printf 'ANTHROPIC_API_KEY=sk-ant-placeholder-m0-stub\nLAB_BUDGET_USD=1\nLAB_MAX_PARALLEL=1\n')
    ```
    **Pass:**
    - the `set:` line names `ANTHROPIC_API_KEY`, `LAB_BUDGET_USD` and `LAB_MAX_PARALLEL`;
    - the output says `no release deployed yet`;
    - `grep -c '^LAB_DB_PASSWORD=' /srv/lab/secrets/lab.env` prints 1.

## P4 First release

11. `./deploy/release.sh lab1 --tag v0.1.0 --allow-build`. `--allow-build` is needed until the control image is pinned (DEPLOYMENT §4.2 step 4). Add `--skip-selftest` only if step 6 was not done; Task 17 is then **not** complete.
    - **Pass:** the output ends `OK: lab1 now runs v0.1.0 (…), self-test passed`.
    - **Watch:** this is the first real start of the control plane. No test starts it for real; the tests only check the compose config. Check that `compose up --wait` returns with the exited `migrate` one-shot, and that `db` and `collector` turn healthy.
12. `./deploy/status.sh lab1`. **Pass:** `SUMMARY: v0.1.0: OK, …`, with `db` and `collector` healthy.
13. `ssh root@192.168.1.145 labctl doctor`. **Pass:** every check is `[ OK ]`, and it exits 0.
14. A full self-test: `ssh root@192.168.1.145 labctl selftest`. **Pass:**
    - it passes, and `/srv/lab/state/selftest.json` records the pass;
    - the injected run's `callbacks` check passed. This is the first proof that **DNS callbacks reach the catcher through Docker's embedded resolver** on an internal network; 14b only showed it on Podman;
    - `docker ps -a`, `docker network ls` and `docker volume ls`, each with `--filter label=lab.run_id -q`, print nothing;
    - `/srv/lab/cells` is empty;
    - `lab_runs_in_flight` on the Collector's `/metrics` is 0.

## P5 Containment checks

15. The bootstrap's module pre-check (step 7) printed no missing modules.
16. **A throwaway cell network.**
    - Create it: `docker network create -o com.docker.network.bridge.name=labctest0 --subnet 10.231.254.0/24 labctest`. The subnet must be inside `lab_cell_networks`, and the bridge name must match `labc*`.
    - Run each check as `docker run --rm --network labctest <python image by digest from images.lock> …`.
    - **Pass:** each check fails (nothing answers), except where another result is stated.
    - (a) TCP to `1.1.1.1:443`.
    - (b) `getent hosts example.com`. Also, `/etc/resolv.conf` in the container holds only `nameserver 127.0.0.11`.
    - (c) UDP and TCP to `192.168.1.1:53` (the resolver: the LAN path the Proxmox firewall leaves open must be closed to cells).
    - (d) TCP to `10.231.254.1:22` (the host, through the bridge gateway).
    - (e) **Forged source.** Run `tcpdump -ni eth0 host 1.1.1.1` on the LXC. Then send raw IPv4/UDP packets to `1.1.1.1:53` with source `192.168.1.145`, and again with source `10.231.253.5`. **Pass:** the prerouting "forged source" counter (`nft list table inet lab_host`) goes up, and tcpdump shows nothing.
    - (f) The forward "cell egress" drop counter has gone up. **Record** whether `journalctl -k | grep lab-drop` shows anything. It does only with `nf_log_all_netns=1`.
    - Remove the network: `docker network rm labctest`.

## P6 Rollback drill

17. **Prepare:**
    - note the runs count: `psql … -c 'select count(*) from runs'` through `compose exec -T db`;
    - back up `/srv/lab/host.env`;
    - set `LAB_PROBE_LAN=192.0.2.1` in it. That is a TEST-NET address that never answers, so the self-test fails at configuration.
18. `git tag -a v0.1.1 -m drill v0.1.0^{}`, then `./deploy/release.sh lab1 --tag v0.1.1 --allow-build`. **Pass:**
    - non-zero exit, with `rolled back to the previous release`;
    - `database restored from …/pre-v0.1.1-*.dump`. This is the swap on real PostgreSQL 17: `<db>_rb` was renamed into place in one transaction;
    - `readlink /srv/lab/current` points to `releases/v0.1.0`;
    - the last line of `/srv/lab/deployments.jsonl` says `rolled-back`;
    - `psql -l` in the db container shows no `lab_rb` or `lab_old`;
    - the runs count is unchanged;
    - `labctl doctor` and `status.sh` are OK.
19. `compose exec -T db pg_restore --list </dev/null` exits non-zero. This confirms that `pg_restore --list` exit codes pass through `compose exec -T`, which the rollback's dump check relies on.
20. Re-run `./deploy/bootstrap.sh lab1`. **Pass:** the only change is `host.env`, and it matches the backup again. Then `labctl selftest --quick` passes.

## P7 Reboot

21. `pct reboot 111`, then wait for SSH. **Pass:**
    - `lab-firewall`, `lab-cell-egress` and `docker` are active;
    - `lab-cell-egress check` is OK, so the `DOCKER-USER` rules survived Docker's start at boot;
    - `status.sh` reports OK.
    - **Record** whether `lab-cell-egress` ran before Docker's first container start (`journalctl -b -u lab-cell-egress -u docker`).
22. **Fail-closed start:** confirm that Docker refuses to start when the firewall cannot load.
    - Run `systemctl stop docker lab-firewall`. Back up `/etc/lab/host.nft`, then add a syntax error to it, so `lab-firewall.service` (`nft --file /etc/lab/host.nft`) fails. Then run `systemctl start docker`.
    - **Pass:** `lab-firewall` fails and Docker stays down.
    - Restore the file from the backup, then `systemctl start lab-firewall docker`. **Pass:** `lab-cell-egress check` and `status.sh` are OK again. Re-running bootstrap would also restore the file.

## P8 Cleanup and record

23. Remove the drill's leftovers:
    - `releases/v0.1.1`;
    - the image `lab/control:v0.1.1`;
    - the `pre-v0.1.1` dump and the `host.env` backup;
    - the local tag `v0.1.1` (`git tag -d v0.1.1`; it was never pushed).
    - **Pass:** no `labctest` network and no `lab.run_id` resources are left.
24. **Record** in DEPLOYMENT §0.5 (a docs commit):
    - module state: `br_netfilter`, `nf_log_all_netns`, `bridge-nf-call-iptables`;
    - the Docker and `containerd.io` versions;
    - the storage driver;
    - whether `lab-drop` logs appear;
    - the reboot order;
    - the results of P5.

    Then set `docker_containerd_pin_version` in the docker role to the exact revision apt shows, or note that the stopgap no longer applies with containerd 2.x.

---

## Verify items this run closes

These come from the M0 reviews and could only be checked on the real host:

| Item | Step |
|---|---|
| Strict reverse-path filtering drops a forged source from a cell | 16e |
| Cells cannot resolve external names, and cannot reach the resolver on 53 | 16b, 16c |
| DNS callbacks reach the catcher through Docker's embedded resolver | 14 |
| `pg_restore --list` exit codes through `compose exec -T` | 19 |
| The rollback swap on real PostgreSQL (≥ 13) | 18 |
| `up --wait` with the exited `migrate` one-shot; the control plane's first real start | 11 |
| The exact `containerd.io` revision | 9, 24 |
| `DOCKER-USER` survives Docker's start at boot; `lab-cell-egress` order | 21 |
| Docker refuses to start without the firewall | 22 |
| `br_netfilter`, `nf_log_all_netns`, overlay2 with the containerd snapshotter off | 2, 9, 16f |
