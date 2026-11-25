#!/bin/bash
# The session-event service of the Juice Shop GOAT, run by the entrypoint as root
# from /opt/support (0700). It listens on /run/insights/events.sock; the shop's own
# node process notes administrator sessions there (lib/insights.ts in the fork), and
# every note the service accepts is appended to the latch file in
# /var/lib/svcstate (root 0700, its own volume) the moment it is accepted. done.sh
# and latch-dump.sh read only that file. See session_events.py for what counts as an
# effect and as a mechanism.
#
# The entrypoint passes the shop's pid and start time (APP_PID, APP_START_TIME),
# recorded where it started the shop; the service accepts notes from that very
# process only.
set -euo pipefail
cd /opt/support

die() {
	echo "goat-launch: $*" >&2
	exit 1
}

# Temp files stay root-only.
export TMPDIR=/opt/support/.tmp

# The latch: a root 0700 directory (the image makes it so and a fresh volume copies
# that; re-assert it in case a runtime mounted its own), holding at most a root
# 0600 regular file that only ever grows.
LATCH_DIR=/var/lib/svcstate
[[ -d "$LATCH_DIR" && ! -L "$LATCH_DIR" ]] || die "$LATCH_DIR is missing or not a directory"
if [[ "$(stat -c %u:%a "$LATCH_DIR")" != 0:700 ]]; then
	chmod 0700 "$LATCH_DIR" || die "cannot make $LATCH_DIR mode 0700"
fi
[[ "$(stat -c %u:%a "$LATCH_DIR")" == 0:700 ]] || die "$LATCH_DIR must be root-owned mode 0700"
odd=$(find "$LATCH_DIR" -mindepth 1 \( ! -name events.jsonl -o ! -type f -o ! -uid 0 -o -perm /0177 \) -print)
[[ -z "$odd" ]] || die "unexpected entries in $LATCH_DIR: $odd"

# The socket's directory: root, group insights, 0750. Only the shop process is given
# that group (the entrypoint starts it so), so no other process of the app user,
# such as a `docker exec` shell, can even reach the socket. The entrypoint makes it
# before it starts the shop; check it is still exactly that.
SOCKET_DIR=/run/insights
[[ -d "$SOCKET_DIR" && ! -L "$SOCKET_DIR" ]] || die "$SOCKET_DIR is not a directory"
[[ "$(stat -c %U:%G:%a "$SOCKET_DIR")" == root:insights:750 ]] ||
	die "$SOCKET_DIR must be root:insights mode 0750"

[[ "${APP_PID:-}" =~ ^[1-9][0-9]*$ ]] || die "APP_PID must be the shop's pid"
[[ "${APP_START_TIME:-}" =~ ^[0-9]+$ ]] || die "APP_START_TIME must be the shop's start time"
export APP_PID APP_START_TIME

# What is graded and where comes from the root-only settings.json, and the shop's
# pin from the environment: nothing about it shows on a command line, which every
# process in the container can read.
exec uv run --locked --no-sync --no-cache python session_events.py serve
