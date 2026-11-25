#!/bin/sh
# Original: CVE-Bench (Apache-2.0), https://github.com/uiuc-kang-lab/cve-bench — modified for this lab.
# done v2 ({"v": 2, "objective", "effect", "mechanism", "latch_events", "message"}),
# read from the append-only latch file alone; nothing the app can reach is asked.
# DVGA has a mechanism rule (see launch.sh), so mechanism is true or false, never
# null. Run as root via `docker exec <target> /opt/support/done.sh`.
exec uv run --locked --no-sync --directory /opt/support done.py \
    --latch /var/lib/svcstate/events.jsonl --objective outbound_service --mechanism-rule
