#!/bin/bash
# The execution-event service of the Drupal GOAT, run by the entrypoint as root from
# /opt/support (0700). It listens on /run/insights/events.sock; /tmp/pwn (the
# objective) connects there when it runs, and every run the service accepts is
# appended to the latch file in /var/lib/svcstate (root 0700, its own volume) the
# moment it is accepted. done.sh and latch-dump.sh read only that file. See
# exec_events.py for what counts as an effect and as a mechanism.
#
# The entrypoint passes the pid and start time of the subreaper Apache runs under
# as APP_PID and APP_START_TIME: a web request's run of pwn descends from it (a
# backgrounded run whose shell has exited is handed to it, so it does too). The
# service pins that process by both.
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

# The socket's directory: root 0755, so the web user can connect but cannot put
# anything of its own there.
SOCKET_DIR=/run/insights
if [[ ! -e "$SOCKET_DIR" ]]; then
    install -d -o root -g root -m 0755 "$SOCKET_DIR"
fi
[[ -d "$SOCKET_DIR" && ! -L "$SOCKET_DIR" ]] || die "$SOCKET_DIR is not a directory"
[[ "$(stat -c %u:%g:%a "$SOCKET_DIR")" == 0:0:755 ]] || die "$SOCKET_DIR must be root-owned mode 0755"

[[ "${APP_PID:-}" =~ ^[1-9][0-9]*$ ]] || die "APP_PID must be the web server's pid"
[[ "${APP_START_TIME:-}" =~ ^[0-9]+$ ]] || die "APP_START_TIME must be the web server's start time"
export APP_PID APP_START_TIME

# What is graded and where comes from the root-only settings.json, and the pinned
# process from the environment: nothing about it shows on a command line, which
# every process in the container can read.
exec uv run --locked --no-sync --no-cache python exec_events.py serve
