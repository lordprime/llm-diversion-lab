#!/usr/bin/env bash
# Runs ON THE LAB HOST as root, shipped by lab_remote (deploy/lib.sh) for status.sh.
# Read-only. Prints a short health report; the last line is a one-line summary.
set -Eeuo pipefail

LAB=/srv/lab
ENV_FILE=$LAB/secrets/lab.env
problems=()

section() { printf '\n[%s]\n' "$1"; }

section release
tag=none
if [[ -L $LAB/current && -f $LAB/current/RELEASE ]]; then
	tag=$(sed -n 's/^tag=//p' "$LAB/current/RELEASE")
	sed 's/^/  /' "$LAB/current/RELEASE"
else
	echo "  no release deployed"
fi

section "host profile"
if [[ -f $LAB/host.env ]]; then
	sed 's/^/  /' "$LAB/host.env"
else
	echo "  $LAB/host.env missing (bootstrap not run?)"
	problems+=("not bootstrapped")
fi

section docker
if docker info >/dev/null 2>&1; then
	docker version --format '  server {{.Server.Version}}'
	docker info --format '  storage driver {{.Driver}}, {{.ContainersRunning}} containers running'
else
	echo "  Docker is not running"
	problems+=("docker down")
fi

section "control plane"
compose=$LAB/current/deploy/compose/control-plane.yml
if [[ -f $compose ]] && docker info >/dev/null 2>&1; then
	# The control-plane image is lab/control:<tag> (deploy/compose/control-plane.yml).
	LAB_RELEASE_TAG="$tag" docker compose --project-name lab --env-file "$ENV_FILE" -f "$compose" \
		ps --format '  {{.Service}}: {{.State}} {{.Health}}' || problems+=("compose ps failed")
else
	echo "  not deployed"
fi

section "run cells"
cells=0
if docker info >/dev/null 2>&1; then
	cells=$(docker ps --quiet --filter label=lab.run_id | wc -l)
fi
echo "  containers in flight (label lab.run_id): $cells"

section "queue and budget"
if command -v labctl >/dev/null 2>&1; then
	labctl status | sed 's/^/  /' || problems+=("labctl status failed")
else
	echo "  labctl not installed yet"
fi

section secrets
if [[ -f $ENV_FILE ]]; then
	printf '  lab.env: %s variables, mode %s, owner %s\n' \
		"$(grep -c '^[A-Z]' "$ENV_FILE")" "$(stat -c %a "$ENV_FILE")" "$(stat -c %U "$ENV_FILE")"
else
	echo "  lab.env missing (run secrets.sh)"
	problems+=("no secrets")
fi

section firewall
# Both layers: the nft table (input + forward drops) and the DOCKER-USER rules.
if /usr/local/sbin/lab-cell-egress check 2>&1 | sed 's/^/  /'; then
	nft list chain inet lab_host forward 2>/dev/null |
		awk '/counter packets/ && /drop/ {sub(/^[ \t]+/, ""); print "  forward drop: " $0}'
else
	problems+=("firewall")
fi

section disk
df -h --output=source,size,used,avail,pcent "$LAB" | sed 's/^/  /'
used=$(df --output=pcent "$LAB" | tail -1 | tr -dc '0-9')
((used <= 85)) || problems+=("disk ${used}% used")

section memory
free -h | sed 's/^/  /'

section backups
echo "  last backup: n/a (backup role not built in M0)"

if ((${#problems[@]})); then
	printf '\nSUMMARY: %s: DEGRADED (%s)\n' "$tag" "$(
		IFS=,
		echo "${problems[*]}"
	)"
	exit 1
fi
printf '\nSUMMARY: %s: OK, %s cell container(s) in flight, disk %s%% used\n' "$tag" "$cells" "$used"
