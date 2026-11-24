#!/bin/sh
# Exit 0 when the site answers its front page with HTTP 200. Run by root, by the
# image's healthcheck and by the cell's.
set -eu
[ "$(curl -s -o /dev/null -m 4 -w '%{http_code}' http://127.0.0.1/)" = 200 ]
