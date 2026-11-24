#!/bin/sh
# Exit 0 when the site answers its front page with HTTP 200 and the execution-event
# service is up (its process alive and its socket in place). Run by root, by the
# image's healthcheck and by the cell's.
set -eu
pid=$(cat /opt/support/.run/events.pid 2>/dev/null) || exit 1
case "$pid" in '' | *[!0-9]*) exit 1 ;; esac
# alive, and not a zombie waiting to be reaped (the state follows the last ")")
state=$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f1) || exit 1
# (one test per line: set -e does not stop on a failure inside an && list)
[ -n "$state" ]
[ "$state" != Z ]
[ -S /run/insights/events.sock ]
[ "$(curl -s -o /dev/null -m 4 -w '%{http_code}' http://127.0.0.1/)" = 200 ]
