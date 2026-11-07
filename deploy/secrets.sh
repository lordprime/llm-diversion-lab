#!/usr/bin/env bash
# Install or rotate the lab's provider keys and settings (DEPLOYMENT §4.2, §2 row 3).
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: deploy/secrets.sh <host> [--from-file PATH] [--validate-only] [--no-test-calls]

Writes /srv/lab/secrets/lab.env on <host> (mode 0600, owner lab) atomically over
SSH. The variables are exactly those in .env.example; each is checked against the
type in its comment. Only variable NAMES are ever printed, never values, and the
values are not stored on this workstation.

Without --from-file it prompts for each variable (keys and URLs are read without
echo). Pressing Enter keeps the value already on the host, or leaves an optional
variable unset. Variables not given are kept from the host's current lab.env.

Then it recreates the control-plane services whose environment changed and makes
one zero-cost call per configured provider (a model-list request) from the host.

Options:
  --from-file PATH  read NAME=VALUE lines from PATH (e.g. a password-manager export
                    piped through process substitution: --from-file <(...))
  --validate-only   check the values and print the names; contact nothing
  --no-test-calls   skip the provider test calls (e.g. a placeholder key in M0)
  -h, --help        show this help

Values: one line, no whitespace, quotes, backslashes, '$', '`' or '#'.
EOF
}

host="" from_file="" validate_only=0 test_calls=1
while (($#)); do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	--from-file)
		[[ $# -ge 2 ]] || {
			printf 'ERROR: --from-file needs a path (try --help)\n' >&2
			exit 2
		}
		from_file=$2
		shift
		;;
	--validate-only) validate_only=1 ;;
	--no-test-calls) test_calls=0 ;;
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
LAB_RUNBOOK="docs/DEPLOYMENT.md §4.2 (secrets.sh)"
[[ -n $host ]] || lab_usage_error "missing <host>"
export LC_ALL=C

TYPES=(secret usd int url email host port text)
NAMES=()
declare -A REQUIRED=() TYPE=() VALUES=() SERVER_HAS=()
ERRORS=()

# .env.example: each NAME= line is preceded by a comment carrying [required] or
# [optional] and one type tag from TYPES.
parse_env_example() {
	local line comment="" name t
	[[ -f $LAB_ENV_EXAMPLE ]] || lab_fail ".env.example not found"
	while IFS= read -r line || [[ -n $line ]]; do
		if [[ $line == '#'* ]]; then
			comment=$line
			continue
		fi
		if [[ $line =~ ^([A-Z][A-Z0-9_]*)=$ ]]; then
			name=${BASH_REMATCH[1]}
			NAMES+=("$name")
			REQUIRED[$name]=0
			[[ $comment != *'[required]'* ]] || REQUIRED[$name]=1
			for t in "${TYPES[@]}"; do
				[[ $comment != *"[$t]"* ]] || TYPE[$name]=$t
			done
			[[ -n ${TYPE[$name]:-} ]] || lab_fail ".env.example: $name has no type tag"
		fi
		comment=""
	done <"$LAB_ENV_EXAMPLE"
}

# check_value NAME VALUE: sets CHECK_ERROR to a message naming NAME (never VALUE).
check_value() {
	local name=$1 value=$2
	CHECK_ERROR=""
	if [[ ! $value =~ ^[[:graph:]]+$ ]]; then
		CHECK_ERROR="$name: must be printable ASCII without whitespace"
		return
	fi
	case $value in
	*[\"\'\\\$\`#]*)
		CHECK_ERROR="$name: must not contain quotes, backslashes, '\$', '\`' or '#'"
		return
		;;
	esac
	case ${TYPE[$name]} in
	secret)
		if ((${#value} < 8)); then
			CHECK_ERROR="$name: too short to be a key"
		elif [[ $name == ANTHROPIC_API_KEY && ! $value =~ ^sk-ant-[A-Za-z0-9_-]+$ ]]; then
			CHECK_ERROR="$name: not in the Anthropic key format (sk-ant-...)"
		elif [[ $name == OPENAI_API_KEY && ! $value =~ ^sk-[A-Za-z0-9_-]+$ ]]; then
			CHECK_ERROR="$name: not in the OpenAI key format (sk-...)"
		fi
		;;
	usd)
		if [[ ! $value =~ ^[0-9]+(\.[0-9]{1,2})?$ || ! $value =~ [1-9] ]]; then
			CHECK_ERROR="$name: not a positive amount in USD (e.g. 250 or 250.50)"
		fi
		;;
	int)
		if [[ ! $value =~ ^[1-9][0-9]{0,5}$ ]]; then
			CHECK_ERROR="$name: not a positive integer"
		elif [[ $name == LAB_MAX_PARALLEL ]] && ((value > HOST_MAX_PARALLEL_CELLS)); then
			CHECK_ERROR="$name: above max_parallel_cells ($HOST_MAX_PARALLEL_CELLS) for $HOST_NAME in hosts.yml"
		fi
		;;
	url)
		[[ $value =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?(/.*)?$ ]] ||
			CHECK_ERROR="$name: not an https:// URL"
		;;
	email)
		[[ $value =~ ^[^@]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]] ||
			CHECK_ERROR="$name: not an e-mail address"
		;;
	host)
		[[ $value =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] ||
			CHECK_ERROR="$name: not a host name"
		;;
	port)
		if [[ ! $value =~ ^[1-9][0-9]{0,4}$ ]] || ((value > 65535)); then
			CHECK_ERROR="$name: not a TCP port"
		fi
		;;
	text) ;;
	esac
}

load_file() {
	local line n=0 name
	[[ -r $from_file ]] || lab_fail "cannot read $from_file"
	while IFS= read -r line || [[ -n $line ]]; do
		n=$((n + 1))
		[[ -z $line || $line == '#'* ]] && continue
		if [[ ! $line =~ ^([A-Za-z_][A-Za-z0-9_]*)=(.*)$ ]]; then
			ERRORS+=("line $n of the values file: expected NAME=VALUE")
			continue
		fi
		name=${BASH_REMATCH[1]}
		if [[ ! -v TYPE[$name] ]]; then
			ERRORS+=("$name: not a variable in .env.example")
		elif [[ -v VALUES[$name] ]]; then
			ERRORS+=("$name: given twice")
		elif [[ -n ${BASH_REMATCH[2]} ]]; then
			VALUES[$name]=${BASH_REMATCH[2]}
		fi
	done <"$from_file"
}

prompt_all() {
	local name label value
	[[ -r /dev/tty ]] || lab_fail "no terminal to prompt on: use --from-file"
	for name in "${NAMES[@]}"; do
		label="$name [${TYPE[$name]}]"
		if [[ -v SERVER_HAS[$name] ]]; then
			label+=" (Enter keeps the current value)"
		elif ((REQUIRED[$name])); then
			label+=" (required)"
		else
			label+=" (optional, Enter leaves it unset)"
		fi
		while :; do
			if [[ ${TYPE[$name]} == secret || ${TYPE[$name]} == url ]]; then
				read -r -s -p "$label: " value </dev/tty
				printf '\n' >/dev/tty
			else
				read -r -p "$label: " value </dev/tty
			fi
			if [[ -z $value ]]; then
				if [[ -v SERVER_HAS[$name] ]] || ((! REQUIRED[$name])); then
					break
				fi
				printf '  %s is required\n' "$name" >/dev/tty
				continue
			fi
			check_value "$name" "$value"
			if [[ -z $CHECK_ERROR ]]; then
				VALUES[$name]=$value
				break
			fi
			printf '  %s\n' "$CHECK_ERROR" >/dev/tty
		done
	done
}

lab_step "Read .env.example and $host"
parse_env_example
lab_load_host "$host"

if ((! validate_only)); then
	lab_step "List the variables currently on $host"
	# Captured first so an SSH failure stops here instead of looking like "no variables"
	# (which would drop the host's current values on write).
	server_names=$(lab_remote secrets.sh names) || lab_fail "could not read lab.env names from $host"
	while IFS= read -r name; do
		[[ -z $name ]] || SERVER_HAS[$name]=1
	done <<<"$server_names"
fi

lab_step "Collect and validate values"
if [[ -n $from_file ]]; then
	load_file
else
	prompt_all
fi
for name in "${!VALUES[@]}"; do
	check_value "$name" "${VALUES[$name]}"
	[[ -z $CHECK_ERROR ]] || ERRORS+=("$CHECK_ERROR")
done
set_names=() kept_names=() unset_names=()
for name in "${NAMES[@]}"; do
	if [[ -v VALUES[$name] ]]; then
		set_names+=("$name")
	elif [[ -v SERVER_HAS[$name] ]]; then
		kept_names+=("$name")
	elif ((REQUIRED[$name])); then
		ERRORS+=("$name: required, not given and not on the host")
	else
		unset_names+=("$name")
	fi
done
if ((${#ERRORS[@]})); then
	printf '  %s\n' "${ERRORS[@]}" >&2
	lab_fail "${#ERRORS[@]} invalid or missing variable(s); nothing was written"
fi
lab_info "  set:   ${set_names[*]:-(none)}"
lab_info "  kept:  ${kept_names[*]:-(none)}"
lab_info "  unset: ${unset_names[*]:-(none)}"

if ((validate_only)); then
	lab_info "OK: values valid for $host (--validate-only: nothing was sent)"
	exit 0
fi

lab_step "Write /srv/lab/secrets/lab.env on $host"
{
	for name in "${set_names[@]}"; do
		printf 'SET %s=%s\n' "$name" "${VALUES[$name]}"
	done
	for name in "${kept_names[@]}"; do
		printf 'KEEP %s\n' "$name"
	done
} | lab_remote_stdin secrets.sh write
unset VALUES

lab_step "Reload the control plane on $host"
lab_remote secrets.sh reload

tests="skipped"
if ((test_calls)); then
	lab_step "Provider test calls from $host"
	lab_remote secrets.sh test || lab_fail "a provider rejected its key (see above)"
	tests="passed"
fi

lab_info "OK: $host lab.env updated (${#set_names[@]} set, ${#kept_names[@]} kept), provider checks $tests"
