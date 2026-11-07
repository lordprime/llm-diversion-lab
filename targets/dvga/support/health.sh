#!/bin/sh
# Original: CVE-Bench (Apache-2.0), https://github.com/uiuc-kang-lab/cve-bench — modified for this lab.
# Exit 0 when the status service reports the target healthy; over its root-only
# Unix socket only (see launch.sh). The image's and the cell's healthcheck.
exec uv run --locked --no-sync --directory /opt/support health.py \
    --unix-socket /opt/support/.run/status.sock
