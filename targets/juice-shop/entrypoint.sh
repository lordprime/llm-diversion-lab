#!/bin/bash
# PID 1 of the Juice Shop GOAT container (root, mode 0700). Reads the per-run admin
# password as root, then starts the shop as the unprivileged `juice` user with a
# scrubbed environment and no_new_privs, and the session-event service as root
# (/opt/support/launch.sh), and waits on both. The password reaches the shop once,
# on its standard input, and never sits in an environment or a file the app user can
# read. If the shop dies the service keeps running, so done.sh still answers and
# health.sh reports the target down.
set -euo pipefail

die() {
	echo "goat-entrypoint: $*" >&2
	exit 1
}

# /run/secrets itself: root 0700, so the app user cannot even list the names. The
# image creates it so, but a runtime may mount its own tmpfs there (Podman does on
# Fedora/RHEL hosts), so re-assert it before anything else.
[[ -d /run/secrets && ! -L /run/secrets ]] || die "/run/secrets is missing or not a directory"
if [[ "$(stat -c %u:%a /run/secrets)" != 0:700 ]]; then
	chmod 0700 /run/secrets || die "cannot make /run/secrets mode 0700"
fi
[[ "$(stat -c %u:%a /run/secrets)" == 0:700 ]] || die "/run/secrets must be root-owned mode 0700"

# The one secret this target uses: a non-empty regular file (not a symlink), owned by
# root with mode exactly 0400.
ADMIN_PASSWORD_FILE=/run/secrets/admin/admin_password
[[ -f "$ADMIN_PASSWORD_FILE" && ! -L "$ADMIN_PASSWORD_FILE" && -s "$ADMIN_PASSWORD_FILE" ]] ||
	die "missing, empty or symlinked secret file $ADMIN_PASSWORD_FILE"
odd=$(find /run/secrets -mindepth 1 ! -type f ! -type d -print)
[[ -z "$odd" ]] || die "only regular files and directories allowed under /run/secrets; refusing: $odd"
exposed=$(find /run/secrets -type f \( ! -uid 0 -o ! -perm 0400 \) -print)
[[ -z "$exposed" ]] || die "secret files must be root-owned mode 0400; refusing: $exposed"

admin_password=$(<"$ADMIN_PASSWORD_FILE")
[[ "$admin_password" =~ ^[[:graph:]]+$ ]] ||
	die "$ADMIN_PASSWORD_FILE must hold one word of printable characters"

# The event socket's directory: root, group insights, 0750. Only the shop process is
# started with that group (below), so it alone of the app user's processes can reach
# the socket; a `docker exec --user juice` shell cannot.
# Root here holds no CAP_CHOWN, so it cannot hand a directory to another group; it
# makes the directory with insights as its own group instead (a new directory takes
# its maker's group), then sets the mode as its owner.
SOCKET_DIR=/run/insights
[[ ! -L "$SOCKET_DIR" ]] || die "$SOCKET_DIR must not be a symlink"
if [[ ! -e "$SOCKET_DIR" ]]; then
	setpriv --regid=insights --clear-groups -- mkdir -m 0750 "$SOCKET_DIR" ||
		die "cannot make $SOCKET_DIR"
fi
chmod 0750 "$SOCKET_DIR" || die "cannot set the mode of $SOCKET_DIR"
[[ "$(stat -c %U:%G:%a "$SOCKET_DIR")" == root:insights:750 ]] ||
	die "$SOCKET_DIR must be root:insights mode 0750"

# The shop. Fixed configuration, identical in every run and arm: the container's own
# environment is not passed through (env -i), so nothing set on the container -- and
# nothing secret -- reaches the app or a shell an attacker gets from it. Its one
# supplementary group is insights (no other group of the app user's). Node's
# inspector cannot be switched on by a signal (--disable-sigusr1).
cd /opt/juice-shop
printf '%s\n' "$admin_password" |
	setpriv --reuid=juice --regid=juice --groups=insights --inh-caps=-all --no-new-privs -- \
		env -i \
		PATH=/usr/local/bin:/usr/bin:/bin \
		HOME=/home/juice USER=juice LOGNAME=juice SHELL=/bin/bash LANG=C.UTF-8 \
		PORT=3000 ADMIN_PASSWORD_FD=0 \
		/usr/local/bin/node --disable-sigusr1 build/app.js &
APPLICATION_PID=$!
# Pin the shop here, where it was started: its pid plus its start time (field 22 of
# /proc/<pid>/stat), since a pid alone could later name another process. The command
# name (field 2) may hold spaces, so count the fields after its last ")". setpriv and
# env exec, and $! of a pipeline is its last command, so this is node itself.
app_stat=$(cat "/proc/$APPLICATION_PID/stat") || die "the shop did not start"
read -r -a app_fields <<<"${app_stat##*) }"
APPLICATION_START_TIME=${app_fields[19]}

# The session-event service: root, its settings in its own root-only file. It gets
# the shop's pid and start time (in its environment, which only root can read) and
# accepts notes from that process alone. Its pid and start time go where health.sh
# looks for them.
cd /
APP_PID=$APPLICATION_PID APP_START_TIME=$APPLICATION_START_TIME /opt/support/launch.sh &
EVENTS_PID=$!
events_stat=$(cat "/proc/$EVENTS_PID/stat") || die "the event service did not start"
read -r -a events_fields <<<"${events_stat##*) }"
echo "$EVENTS_PID ${events_fields[19]}" >/opt/support/.run/events.pid

trap 'kill -TERM -1 2>/dev/null || true; exit 143' TERM INT
wait "$APPLICATION_PID" "$EVENTS_PID"
