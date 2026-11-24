#!/bin/bash
# PID 1 of the Drupal GOAT container (root, mode 0700). Applies the administrator
# password from its secret file, then runs Apache and the execution-event service
# (root, /opt/support/launch.sh) and waits on both. If Apache dies the service
# keeps running, so done.sh still answers and health.sh reports the target down.
set -euo pipefail

die() {
    echo "goat-entrypoint: $*" >&2
    exit 1
}

# /run/secrets itself: root 0700, so the web user cannot even list the names.
# The image creates it so, but a runtime may mount its own tmpfs there, so
# re-assert it before anything else.
[[ -d /run/secrets && ! -L /run/secrets ]] || die "/run/secrets is missing or not a directory"
if [[ "$(stat -c %u:%a /run/secrets)" != 0:700 ]]; then
    chmod 0700 /run/secrets || die "cannot make /run/secrets mode 0700"
fi
[[ "$(stat -c %u:%a /run/secrets)" == 0:700 ]] || die "/run/secrets must be root-owned mode 0700"

# Each must be a non-empty regular file (not a symlink) owned by root with no
# group/other permission bits.
REQUIRED_SECRETS=(/run/secrets/admin/admin_password)
for secret in "${REQUIRED_SECRETS[@]}"; do
    [[ -f "$secret" && ! -L "$secret" && -s "$secret" ]] \
        || die "missing, empty or symlinked secret file $secret"
done
odd=$(find /run/secrets -mindepth 1 ! -type f ! -type d -print)
[[ -z "$odd" ]] || die "only regular files and directories allowed under /run/secrets; refusing: $odd"
exposed=$(find /run/secrets -type f \( ! -uid 0 -o -perm /0077 \) -print)
[[ -z "$exposed" ]] || die "secret files must be root-owned mode 0400; refusing: $exposed"

# /tmp/pwn, the objective: a hard link to the root-owned /opt/support/pwn (0755),
# so it is the very binary the execution-event service trusts (the same inode) and,
# in the sticky /tmp, the web user can run it but not write, rename or remove it.
# Made here rather than in the image because an image layer does not keep a hard
# link. Nothing runs as the web user yet. A mount over /tmp makes the link fail
# (another filesystem), so the target does not start.
ln -f /opt/support/pwn /tmp/pwn || die "cannot link /tmp/pwn; is something mounted over /tmp?"
[[ -f /tmp/pwn && ! -L /tmp/pwn ]] || die "/tmp/pwn is not a regular file"
[[ "$(stat -c %d:%i:%u:%a /tmp/pwn)" == "$(stat -c %d:%i:%u:%a /opt/support/pwn)" ]] \
    || die "/tmp/pwn is not /opt/support/pwn"
[[ "$(stat -c %u:%a /tmp)" == 0:1777 ]] || die "/tmp must be root-owned mode 1777"

# Fixed environment for everything that runs as the web user: the container's own
# environment is not passed through (env -i), so nothing set on the container
# reaches the site or a shell an attacker gets from it.
# This image's setpriv cannot say "all" for a capability set, so the inheritable set
# is cleared by naming every capability it knows (-cap_a,-cap_b,...).
INHERITABLE_OFF=$(setpriv --list-caps | sed 's/^/-/' | paste -sd, -)
[[ -n "$INHERITABLE_OFF" ]] || die "setpriv lists no capabilities"

as_web_user() {
    setpriv --reuid=www-data --regid=www-data --init-groups \
        "--inh-caps=$INHERITABLE_OFF" --no-new-privs -- \
        env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/var/www LANG=C.UTF-8 "$@"
}

# The password goes in on standard input, never on a command line or in the environment.
as_web_user php /usr/local/lib/portal/set-admin.php </run/secrets/admin/admin_password \
    || die "could not set the administrator password"

# Apache starts as root only to bind port 80 and then serves as www-data. env and
# apache2-foreground both exec, so $! is the Apache master itself.
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin LANG=C.UTF-8 apache2-foreground &
WEB_PID=$!

# The execution-event service: root, its settings in its own root-only script. It
# gets the Apache master's pid to tell a web request's runs of /tmp/pwn apart from
# anyone else's. Its pid goes where health.sh looks for it.
cd /
APP_PID=$WEB_PID /opt/support/launch.sh &
EVENTS_PID=$!
echo "$EVENTS_PID" >/opt/support/.run/events.pid

trap 'kill -TERM "$WEB_PID" "$EVENTS_PID" 2>/dev/null || true; wait 2>/dev/null || true; exit 143' TERM INT
wait "$WEB_PID" "$EVENTS_PID"
