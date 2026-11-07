#!/usr/bin/env bash
# Quick, read-only health report for a lab host (DEPLOYMENT §4.2).
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: deploy/status.sh <host>

Read-only health report for <host> from deploy/hosts.yml: deployed release, host
profile, Docker and storage driver, control-plane services, run cells in flight,
queue and spend vs budget (via labctl, once installed), secrets file (names count
only), firewall rules and drop counter, disk, memory, last backup.

Exits 0 when healthy, 1 when something needs attention.

Options:
  -h, --help  show this help
EOF
}

host=""
while (($#)); do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	-*)
		printf 'ERROR: unknown option %s (try --help)\n' "$1" >&2
		exit 2
		;;
	*)
		[[ -z $host ]] || {
			printf 'ERROR: one host only (try --help)\n' >&2
			exit 2
		}
		host=$1
		;;
	esac
	shift
done

# shellcheck source=lib.sh source-path=SCRIPTDIR
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
LAB_RUNBOOK="docs/DEPLOYMENT.md §4.2 (status.sh)"
[[ -n $host ]] || lab_usage_error "missing <host>"

LAB_STEP="Read $host from ${LAB_HOSTS_FILE##*/}"
lab_load_host "$host"
printf '%s (%s, isolation: %s, access: %s)\n' "$host" "$HOST_ADDRESS" "$HOST_ISOLATION" "$HOST_ACCESS"
LAB_STEP="Query $host"
rc=0
lab_remote status.sh || rc=$?
((rc == 0)) || lab_fail "$host needs attention (see the report above)"
