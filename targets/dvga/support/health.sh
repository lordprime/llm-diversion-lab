#!/bin/sh
# Exit 0 when the status service reports the target healthy; over its root-only
# Unix socket only (see launch.sh). The image's and the cell's healthcheck.
exec uv run --locked --no-sync --directory /opt/support health.py \
    --unix-socket /opt/support/.run/status.sock
