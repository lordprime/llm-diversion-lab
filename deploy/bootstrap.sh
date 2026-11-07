#!/usr/bin/env bash
# Provision a lab host with Ansible, then run `labctl doctor` on it (DEPLOYMENT §4.2).
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: deploy/bootstrap.sh <host> [--check] [--format-data-disk] [--skip-doctor] [-v]

Turn a fresh Ubuntu 24.04 host (the CT 111 LXC, isolation: lxc) into a lab server:
runs deploy/ansible/site.yml against <host> from deploy/hosts.yml, then
`labctl doctor` on the host if labctl is installed (it arrives with release.sh).

Ansible is run with `uvx --from ansible-core==<pinned> ansible-playbook`; nothing is
installed globally on this workstation. Re-running converges; nothing is destroyed.

Options:
  --check             dry run: ansible-playbook --check --diff, no doctor
  --format-data-disk  sysbox profile only (not built in M0); refused for isolation: lxc
  --skip-doctor       do not run labctl doctor afterwards
  -v                  pass -v to ansible-playbook (repeatable)
  -h, --help          show this help

The web login (Caddy basic auth) is generated on the host on the first run:
  ssh <host> cat /srv/lab/secrets/web-basic-auth
EOF
}

host="" check=0 format_disk=0 doctor=1 verbose=()
while (($#)); do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	--check) check=1 ;;
	--format-data-disk) format_disk=1 ;;
	--skip-doctor) doctor=0 ;;
	-v) verbose+=(-v) ;;
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
LAB_RUNBOOK="docs/DEPLOYMENT.md §0.1 (container), §0.2 (roles), §4.2 (bootstrap.sh)"
[[ -n $host ]] || lab_usage_error "missing <host>"

lab_step "Read $host from ${LAB_HOSTS_FILE##*/}"
lab_require_cmd uvx
lab_load_host "$host"
if ((format_disk)) && [[ $HOST_ISOLATION == lxc ]]; then
	lab_fail "--format-data-disk: there is no disk formatting in the LXC profile (§0.2)"
fi

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
lab_render_inventory "$host" "$workdir/inventory.json"

lab_step "Run deploy/ansible/site.yml on $host ($HOST_ADDRESS, isolation: $HOST_ISOLATION)"
args=(-i "$workdir/inventory.json" "$LAB_DEPLOY_DIR/ansible/site.yml" "${verbose[@]}")
((check)) && args+=(--check --diff)
((format_disk)) && args+=(-e format_data_disk=true)
ANSIBLE_CONFIG=$LAB_DEPLOY_DIR/ansible/ansible.cfg \
	uvx --from "$LAB_ANSIBLE_CORE_SPEC" ansible-playbook "${args[@]}"

if ((check)); then
	lab_info "OK: $host dry run finished (--check); nothing was changed"
	exit 0
fi

doctor_result="skipped"
if ((doctor)); then
	lab_step "Run labctl doctor on $host"
	rc=0
	lab_remote doctor.sh || rc=$?
	case $rc in
	0) doctor_result="passed" ;;
	3)
		lab_warn "labctl is not installed on $host yet; deploy a release, then run 'labctl doctor' there"
		doctor_result="not available"
		;;
	*) lab_fail "labctl doctor reported problems (exit $rc)" ;;
	esac
fi

lab_info "OK: $host ($HOST_ADDRESS) provisioned: isolation=$HOST_ISOLATION access=$HOST_ACCESS, doctor $doctor_result"
