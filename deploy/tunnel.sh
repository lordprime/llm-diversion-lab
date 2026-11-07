#!/usr/bin/env bash
# Private access to a lab host's website, API and Grafana (DEPLOYMENT §1, §4.2).
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: deploy/tunnel.sh <host> [--local-port PORT]

With `access: twingate` (the LXC profile) there is nothing to open: the Twingate
client already routes to the host, and this prints the URLs to use.

With `access: ssh-tunnel` it runs `ssh -N -L 127.0.0.1:PORT:<address>:443` to
Caddy on the host and keeps it open until Ctrl-C (default PORT 8443).

WireGuard and Tailscale are not set up by the M0 roles; it prints a note.

Options:
  --local-port PORT  local port for the SSH tunnel (default 8443)
  -h, --help         show this help
EOF
}

host="" local_port=8443
while (($#)); do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	--local-port)
		[[ $# -ge 2 && $2 =~ ^[0-9]{2,5}$ ]] || {
			printf 'ERROR: --local-port needs a port number (try --help)\n' >&2
			exit 2
		}
		local_port=$2
		shift
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
LAB_RUNBOOK="docs/DEPLOYMENT.md §0 (Twingate), §1 (access channel)"
[[ -n $host ]] || lab_usage_error "missing <host>"
lab_load_host "$host"

login="the web login is on the host: ssh $HOST_SSH_USER@$HOST_ADDRESS cat /srv/lab/secrets/web-basic-auth"
case $HOST_ACCESS in
twingate)
	cat <<EOF
$host uses Twingate: no tunnel needed. With the Twingate client connected:
  website, API, Grafana  https://$HOST_ADDRESS/  (/api/, /grafana/; Caddy, internal CA)
  SSH                    ssh -p $HOST_SSH_PORT $HOST_SSH_USER@$HOST_ADDRESS
  $login
EOF
	;;
ssh-tunnel)
	printf 'Tunnel open: https://localhost:%s/ (Ctrl-C to close)\n  %s\n' "$local_port" "$login"
	exec "$LAB_SSH_BIN" -N -o ExitOnForwardFailure=yes -p "$HOST_SSH_PORT" \
		-L "127.0.0.1:$local_port:$HOST_ADDRESS:443" "$HOST_SSH_USER@$HOST_ADDRESS"
	;;
*)
	printf '%s uses %s, which the M0 roles do not set up; reach https://%s/ through it.\n' \
		"$host" "$HOST_ACCESS" "$HOST_ADDRESS"
	;;
esac
