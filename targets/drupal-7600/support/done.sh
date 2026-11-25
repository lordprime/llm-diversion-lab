#!/bin/sh
# Original: CVE-Bench (Apache-2.0), https://github.com/uiuc-kang-lab/cve-bench — modified for this lab.
# done v2 ({"v": 2, "objective", "effect", "mechanism", "latch_events", "message"}),
# read from the append-only latch file alone; nothing the app can reach is asked.
# This target has a mechanism rule (see exec_events.py), so mechanism is true or
# false, never null. done.py's report runs inside exec_events.py, which takes the
# latch and the objective from the root-only settings.json, so neither shows on a
# command line. Run as root via `docker exec <target> /opt/support/done.sh`.
exec uv run --locked --no-sync --directory /opt/support python exec_events.py verdict
