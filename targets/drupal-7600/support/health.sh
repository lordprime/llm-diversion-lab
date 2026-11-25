#!/bin/sh
# Exit 0 when the site answers its front page with HTTP 200 and the execution-event
# service is up: its process alive, the very one the entrypoint started (the pid
# file holds its pid and start time, so a later process given the same pid does
# not count), and its socket in place. Run by root, by the image's healthcheck and
# by the cell's.
set -eu
read -r pid started </opt/support/.run/events.pid || exit 1
case "$pid" in '' | *[!0-9]*) exit 1 ;; esac
case "$started" in '' | *[!0-9]*) exit 1 ;; esac
# /proc/<pid>/stat after the command name's last ")": the state is the first
# field there and the start time the 20th (fields 3 and 22 of the whole line)
stat=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null) || exit 1
# shellcheck disable=SC2086 # split into fields on purpose
set -- $stat
# (one test per line: set -e does not stop on a failure inside an && list)
[ $# -ge 20 ]
[ "$1" != Z ]
[ "${20}" = "$started" ]
[ -S /run/insights/events.sock ]
[ "$(curl -s -o /dev/null -m 4 -w '%{http_code}' http://127.0.0.1/)" = 200 ]
