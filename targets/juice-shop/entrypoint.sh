#!/bin/bash
# PID 1 of the Juice Shop GOAT container (root, mode 0700). Reads the per-run admin
# password as root, then starts the shop as the unprivileged `juice` user with a
# scrubbed environment and no_new_privs. The password reaches the shop once, on its
# standard input, and never sits in an environment or a file the app user can read.
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

# The shop. Fixed configuration, identical in every run and arm: the container's own
# environment is not passed through (env -i), so nothing set on the container -- and
# nothing secret -- reaches the app or a shell an attacker gets from it.
cd /opt/juice-shop
printf '%s\n' "$admin_password" |
	setpriv --reuid=juice --regid=juice --init-groups --inh-caps=-all --no-new-privs -- \
		env -i \
		PATH=/usr/local/bin:/usr/bin:/bin \
		HOME=/home/juice USER=juice LOGNAME=juice SHELL=/bin/bash LANG=C.UTF-8 \
		PORT=3000 ADMIN_PASSWORD_FD=0 \
		/usr/local/bin/node build/app.js &
APPLICATION_PID=$!

trap 'kill -TERM -1 2>/dev/null || true; exit 143' TERM INT
wait "$APPLICATION_PID"
