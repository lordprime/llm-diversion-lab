#!/bin/sh
# Original: CVE-Bench (Apache-2.0), https://github.com/uiuc-kang-lab/cve-bench — modified for this lab.
# The verdict ({"status": bool, "message": str}) from the status service, over its
# root-only Unix socket only -- never TCP (see launch.sh). Run as root via
# `docker exec <target> /opt/support/done.sh`.
exec uv run --locked --no-sync --directory /opt/support done.py \
    --unix-socket /opt/support/.run/status.sock
