#!/usr/bin/env bash
# Shared helpers for the deploy scripts (docs/DEPLOYMENT.md §4). Sourced, not run.
#
# Environment overrides (for tests and unusual workstations):
#   LAB_HOSTS_FILE         inventory in the §4.1 format (default deploy/hosts.yml)
#   LAB_REPO_ROOT          git checkout that release.sh archives (default: this repo)
#   LAB_SSH_BIN            ssh client (default ssh); tests set it to `false`
#   LAB_PYTHON             a Python with PyYAML (default: an ephemeral `uv run` env)
#   LAB_ANSIBLE_CORE_SPEC  ansible-core requirement for uvx (default pinned below)
set -Eeuo pipefail

LAB_DEPLOY_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LAB_REPO_ROOT=${LAB_REPO_ROOT:-$(cd -- "$LAB_DEPLOY_DIR/.." && pwd)}
LAB_HOSTS_FILE=${LAB_HOSTS_FILE:-$LAB_DEPLOY_DIR/hosts.yml}
# shellcheck disable=SC2034 # read by secrets.sh, which sources this file
LAB_ENV_EXAMPLE=$LAB_DEPLOY_DIR/../.env.example
LAB_SSH_BIN=${LAB_SSH_BIN:-ssh}
LAB_ANSIBLE_CORE_SPEC=${LAB_ANSIBLE_CORE_SPEC:-ansible-core==2.22.0}
LAB_PYYAML_SPEC=pyyaml==6.0.3
LAB_RUNBOOK=${LAB_RUNBOOK:-docs/DEPLOYMENT.md §4.2}
LAB_STEP=""

# ------------------------------------------------------------------- messages

lab_info() { printf '%s\n' "$*"; }
lab_warn() { printf 'WARNING: %s\n' "$*" >&2; }

# lab_fail MESSAGE: print the failing step, the reason and the runbook pointer; exit 1.
lab_fail() {
	printf 'FAILED at step "%s": %s\nSee %s\n' "${LAB_STEP:-startup}" "$*" "$LAB_RUNBOOK" >&2
	exit 1
}

# lab_usage_error MESSAGE: a bad command line; exit 2.
lab_usage_error() {
	printf 'ERROR: %s (try --help)\n' "$*" >&2
	exit 2
}

lab_step() {
	LAB_STEP=$1
	printf '==> %s\n' "$1"
}

lab__on_err() {
	local rc=$1 line=$2 src=$3
	printf 'FAILED at step "%s" (exit %s, %s line %s)\nSee %s\n' \
		"${LAB_STEP:-startup}" "$rc" "${src##*/}" "$line" "$LAB_RUNBOOK" >&2
}
trap 'lab__on_err $? $LINENO "${BASH_SOURCE[0]}"' ERR

lab_require_cmd() {
	local cmd
	for cmd in "$@"; do
		command -v "$cmd" >/dev/null 2>&1 || lab_fail "'$cmd' is required on this workstation"
	done
}

# ------------------------------------------------------------------- python

# lab_python ARG...: Python in isolated mode with PyYAML, without touching the
# project environment or installing anything globally.
lab_python() {
	if [[ -n ${LAB_PYTHON:-} ]]; then
		"$LAB_PYTHON" -I "$@"
	else
		lab_require_cmd uv
		uv run --quiet --no-project --with "$LAB_PYYAML_SPEC" python3 -I "$@"
	fi
}

# Reads hosts.yml (§4.1), validates one host and prints it as shell assignments
# (mode "env") or writes it as an Ansible YAML/JSON inventory (mode "inventory").
read -r -d '' LAB__HOSTS_PY <<'PY' || true
import ipaddress, json, re, shlex, sys

import yaml

path, name, mode = sys.argv[1:4]


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    raise SystemExit(1)


KNOWN = {
    "address": str, "ssh_user": str, "ssh_port": int, "isolation": str, "access": str,
    "allow_containerd_pin": bool, "cloudflare_tunnel": bool, "max_parallel_cells": int,
    "backup_repo": str, "vars": dict,
}
DEFAULTS = {
    "ssh_port": 22, "allow_containerd_pin": False, "cloudflare_tunnel": False,
    "max_parallel_cells": 1, "backup_repo": "", "vars": {},
}
CHOICES = {
    "isolation": ("lxc", "sysbox"),
    "access": ("twingate", "ssh-tunnel", "wireguard", "tailscale"),
}

if not re.fullmatch(r"[A-Za-z0-9_-]+", name):
    die(f"host name {name!r} must be letters, digits, '-' or '_'")
try:
    with open(path, encoding="utf-8") as fh:
        hosts = yaml.safe_load(fh)
except FileNotFoundError:
    die(f"{path} not found: copy deploy/hosts.example.yml to deploy/hosts.yml and edit it")
except yaml.YAMLError as exc:
    die(f"{path} is not valid YAML: {exc}")
if not isinstance(hosts, dict) or name not in hosts:
    known = ", ".join(sorted(hosts)) if isinstance(hosts, dict) else "none"
    die(f"host {name!r} is not in {path} (hosts: {known})")
host = hosts[name]
if not isinstance(host, dict):
    die(f"{name}: expected a mapping of settings")
unknown = sorted(set(host) - set(KNOWN))
if unknown:
    die(f"{name}: unknown key(s) {', '.join(unknown)} (known: {', '.join(sorted(KNOWN))})")
for key in ("address", "ssh_user", "isolation", "access"):
    if key not in host:
        die(f"{name}: '{key}' is required")
cfg = {**DEFAULTS, **host}
for key, kind in KNOWN.items():
    if type(cfg[key]) is not kind:
        die(f"{name}: '{key}' must be a {kind.__name__}")
for key, choices in CHOICES.items():
    if cfg[key] not in choices:
        die(f"{name}: '{key}' must be one of {', '.join(choices)}")
try:
    ipaddress.ip_address(cfg["address"])
except ValueError:
    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?", cfg["address"]):
        die(f"{name}: 'address' is neither an IP address nor a host name")
if not re.fullmatch(r"[a-z_][a-z0-9_-]*", cfg["ssh_user"]):
    die(f"{name}: 'ssh_user' is not a valid user name")
if not 1 <= cfg["ssh_port"] <= 65535:
    die(f"{name}: 'ssh_port' out of range")
if cfg["max_parallel_cells"] < 1:
    die(f"{name}: 'max_parallel_cells' must be at least 1")
if cfg["backup_repo"]:
    print(f"WARNING: {name}: backup_repo is set but unused (backups are not built in M0)",
          file=sys.stderr)
for key in cfg["vars"]:
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", str(key)) or key in KNOWN or key.startswith("ansible_"):
        die(f"{name}: vars.{key} is not an allowed variable name")

scalars = {k: v for k, v in cfg.items() if k != "vars"}
if mode == "env":
    print(f"HOST_NAME={shlex.quote(name)}")
    for key, value in scalars.items():
        text = str(value).lower() if isinstance(value, bool) else str(value)
        print(f"HOST_{key.upper()}={shlex.quote(text)}")
elif mode == "inventory":
    hostvars = {
        **cfg["vars"],
        **scalars,
        "ansible_host": cfg["address"],
        "ansible_user": cfg["ssh_user"],
        "ansible_port": cfg["ssh_port"],
        "ansible_python_interpreter": "/usr/bin/python3",
    }
    with open(sys.argv[4], "w", encoding="utf-8") as fh:
        json.dump({"all": {"hosts": {name: hostvars}}}, fh, indent=2)
else:
    die(f"internal: unknown mode {mode!r}")
PY

# lab_load_host NAME: validate NAME in hosts.yml and set HOST_NAME, HOST_ADDRESS,
# HOST_SSH_USER, HOST_SSH_PORT, HOST_ISOLATION, HOST_ACCESS, HOST_ALLOW_CONTAINERD_PIN,
# HOST_CLOUDFLARE_TUNNEL and HOST_MAX_PARALLEL_CELLS.
lab_load_host() {
	local assignments
	assignments=$(lab_python -c "$LAB__HOSTS_PY" "$LAB_HOSTS_FILE" "$1" env) || exit 1
	eval "$assignments"
	LAB_SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=15 -p "$HOST_SSH_PORT")
}

# lab_render_inventory NAME FILE: write NAME as an Ansible inventory (JSON is YAML).
lab_render_inventory() {
	lab_python -c "$LAB__HOSTS_PY" "$LAB_HOSTS_FILE" "$1" inventory "$2" || exit 1
}

# ------------------------------------------------------------------- remote

lab_ssh() {
	"$LAB_SSH_BIN" "${LAB_SSH_OPTS[@]}" "$HOST_SSH_USER@$HOST_ADDRESS" "$@"
}

# lab_remote SCRIPT [ARG...]: run deploy/remote/SCRIPT on the host as root, with no
# stdin (so ssh cannot swallow terminal input).
lab_remote() {
	lab_remote_stdin "$@" </dev/null
}

# lab_remote_stdin SCRIPT [ARG...]: the same, with stdin passed through (secret values
# and release archives travel on stdin, never in argv). The script is shipped
# base64-encoded so no remote quoting is involved; ARGs are restricted to a safe
# character set.
lab_remote_stdin() {
	local script=$LAB_DEPLOY_DIR/remote/$1 arg b64 sudo=""
	shift
	[[ -f $script ]] || lab_fail "internal: missing $script"
	for arg in "$@"; do
		[[ $arg =~ ^[A-Za-z0-9._/:@=+-]+$ ]] || lab_fail "internal: unsafe remote argument"
	done
	b64=$(base64 <"$script" | tr -d '\n')
	[[ $HOST_SSH_USER == root ]] || sudo="sudo -n "
	lab_ssh "${sudo}bash -c \"\$(printf %s $b64 | base64 -d)\" lab-remote $*"
}

# ------------------------------------------------------------------- usage

lab__lib_usage() {
	cat <<'EOF'
Usage: source deploy/lib.sh

Shared helpers for the deploy scripts (bootstrap.sh, secrets.sh, release.sh,
status.sh, tunnel.sh). It is a library: source it, do not run it.

Functions: lab_load_host NAME, lab_render_inventory NAME FILE, lab_remote SCRIPT
[ARG...] (runs deploy/remote/SCRIPT on the host as root), lab_remote_stdin (the
same, with stdin), lab_step, lab_fail, lab_python.

Environment overrides: LAB_HOSTS_FILE, LAB_REPO_ROOT, LAB_SSH_BIN, LAB_PYTHON,
LAB_ANSIBLE_CORE_SPEC.
EOF
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
	case ${1:-} in
	-h | --help)
		lab__lib_usage
		exit 0
		;;
	*)
		lab__lib_usage >&2
		exit 2
		;;
	esac
fi
