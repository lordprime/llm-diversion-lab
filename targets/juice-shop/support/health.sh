#!/bin/sh
# Exit 0 when the shop answers on its own port. The image's and the cell's
# healthcheck, run as root from the root-only /opt/support. A failed or slow answer,
# or a shop that is not running, exits non-zero.
exec curl -fsS -o /dev/null --max-time 4 http://127.0.0.1:3000/rest/admin/application-version
