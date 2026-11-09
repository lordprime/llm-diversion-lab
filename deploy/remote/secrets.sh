#!/usr/bin/env bash
# Runs ON THE LAB HOST as root, shipped by lab_remote (deploy/lib.sh) for secrets.sh.
#
#   names   print the variable NAMES present in lab.env (never values)
#   write   read "SET NAME=VALUE" / "KEEP NAME" lines and a final "END <count>" on
#           stdin; only a complete stream (END present, count matching) replaces
#           lab.env, atomically (temp file in the same directory, 0600 lab, rename)
#   reload  recreate the control-plane services whose environment changed
#   test    one zero-cost model-list call per configured provider
#
# Values arrive on stdin and are only ever written to lab.env or fed to curl through
# its config on stdin, so they never appear in argv, logs or messages.
set -Eeuo pipefail

# LAB_ROOT and LAB_OWNER are for the test suite only; on a host they are never set.
LAB=${LAB_ROOT:-/srv/lab}
ENV_FILE=$LAB/secrets/lab.env
LAB_USER=${LAB_OWNER:-lab}
# Generated on the host by bootstrap.sh (base role) and never sent by secrets.sh:
# every write carries them over unchanged, and a SET or KEEP of one is refused.
HOST_GENERATED=(LAB_DB_PASSWORD)

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

declare -A CUR=()
read_env() {
	local line
	[[ -f $ENV_FILE ]] || return 0
	while IFS= read -r line || [[ -n $line ]]; do
		[[ $line =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || continue
		CUR[${BASH_REMATCH[1]}]=${BASH_REMATCH[2]}
	done <"$ENV_FILE"
}

cmd_names() {
	local name
	read_env
	for name in "${!CUR[@]}"; do
		printf '%s\n' "$name"
	done | sort
}

host_generated() {
	local name
	for name in "${HOST_GENERATED[@]}"; do
		[[ $1 == "$name" ]] && return 0
	done
	return 1
}

cmd_write() {
	local tmp line name count=0 carried=0 ended=""
	[[ -d $LAB/secrets ]] || die "$LAB/secrets is missing: run bootstrap.sh first"
	read_env
	tmp=$(mktemp "$LAB/secrets/.lab.env.XXXXXX")
	# shellcheck disable=SC2064 # expand $tmp now: it is local to this function
	trap "rm -f '$tmp'" EXIT
	printf '# Written by deploy/secrets.sh at %s. Do not edit by hand.\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$tmp"
	while IFS= read -r line; do
		[[ -z $ended ]] || die "data after the END marker"
		case $line in
		"END "*)
			ended=${line#END }
			[[ $ended =~ ^[0-9]+$ ]] || die "malformed END line"
			continue
			;;
		"SET "*)
			line=${line#SET }
			[[ $line =~ ^[A-Z][A-Z0-9_]*=[^[:space:]]+$ ]] || die "malformed SET line"
			! host_generated "${line%%=*}" ||
				die "${line%%=*} is generated on the host (bootstrap.sh); secrets.sh never sets it"
			printf '%s\n' "$line" >>"$tmp"
			;;
		"KEEP "*)
			name=${line#KEEP }
			! host_generated "$name" ||
				die "$name is generated on the host (bootstrap.sh); it is always kept"
			[[ -v CUR[$name] ]] || die "$name: no current value on the server to keep"
			printf '%s=%s\n' "$name" "${CUR[$name]}" >>"$tmp"
			;;
		*) die "malformed input line" ;;
		esac
		count=$((count + 1))
	done
	[[ -n $ended ]] || die "input ended without the END marker (truncated?); lab.env unchanged"
	((ended == count)) || die "END says $ended variables but $count arrived; lab.env unchanged"
	for name in "${HOST_GENERATED[@]}"; do
		[[ -v CUR[$name] ]] || continue
		printf '%s=%s\n' "$name" "${CUR[$name]}" >>"$tmp"
		carried=$((carried + 1))
	done
	chown "$LAB_USER:" "$tmp"
	chmod 0600 "$tmp"
	sync "$tmp"
	mv -f "$tmp" "$ENV_FILE"
	trap - EXIT
	printf 'wrote %s: %d variables (+%d generated on the host, kept), mode 0600, owner %s\n' \
		"$ENV_FILE" "$count" "$carried" "$LAB_USER"
}

cmd_reload() {
	local compose=$LAB/current/deploy/compose/control-plane.yml tag
	if [[ ! -f $compose ]]; then
		echo "no release deployed yet: nothing to reload"
		return 0
	fi
	# The control-plane image is lab/control:<tag> of the release that is current.
	tag=$(readlink -f -- "$LAB/current")
	tag=${tag##*/}
	[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
		die "$LAB/current is not a release tree"
	LAB_RELEASE_TAG=$tag docker compose --project-name lab --env-file "$ENV_FILE" -f "$compose" \
		up -d --no-build --wait --wait-timeout 300
}

FAILED=0
# call LABEL URL HEADER...: GET URL with the headers passed through curl's config on
# stdin (printf is a builtin, so no header value reaches any process's argv).
call() {
	local label=$1 url=$2 header code
	shift 2
	code=$(
		for header in "$@"; do
			printf 'header = "%s"\n' "$header"
		done | curl --silent --output /dev/null --write-out '%{http_code}' \
			--max-time 20 --config - "$url"
	) || code=000
	if [[ $code == 200 ]]; then
		printf '  %-10s OK\n' "$label"
	else
		printf '  %-10s failed (HTTP %s)\n' "$label" "$code"
		FAILED=1
	fi
}

cmd_test() {
	local tested=0
	read_env
	echo "provider test calls (model list, no tokens spent):"
	if [[ -n ${CUR[ANTHROPIC_API_KEY]:-} ]]; then
		call anthropic https://api.anthropic.com/v1/models \
			"x-api-key: ${CUR[ANTHROPIC_API_KEY]}" "anthropic-version: 2023-06-01"
		tested=1
	fi
	if [[ -n ${CUR[OPENAI_API_KEY]:-} ]]; then
		call openai https://api.openai.com/v1/models \
			"Authorization: Bearer ${CUR[OPENAI_API_KEY]}"
		tested=1
	fi
	if [[ -n ${CUR[GEMINI_API_KEY]:-} ]]; then
		call gemini https://generativelanguage.googleapis.com/v1beta/models \
			"x-goog-api-key: ${CUR[GEMINI_API_KEY]}"
		tested=1
	fi
	if [[ -n ${CUR[OPENROUTER_API_KEY]:-} ]]; then
		call openrouter https://openrouter.ai/api/v1/key \
			"Authorization: Bearer ${CUR[OPENROUTER_API_KEY]}"
		tested=1
	fi
	((tested)) || echo "  (no provider keys configured)"
	return "$FAILED"
}

case ${1:-} in
names) cmd_names ;;
write) cmd_write ;;
reload) cmd_reload ;;
test) cmd_test ;;
*) die "usage: secrets.sh names|write|reload|test" ;;
esac
