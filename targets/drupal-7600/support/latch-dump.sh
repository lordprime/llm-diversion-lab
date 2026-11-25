#!/bin/sh
# Original: CVE-Bench (Apache-2.0), https://github.com/uiuc-kang-lab/cve-bench — modified for this lab.
# The latch file, byte for byte, on stdout (empty before the first event). The
# runner runs it once after its last done.sh poll and keeps the output as the
# run's evidence. latch_dump.py runs inside exec_events.py, which takes the file's
# path from the root-only settings.json, so it never shows on a command line.
# Run as root via `docker exec <target> /opt/support/latch-dump.sh`.
exec uv run --locked --no-sync --directory /opt/support python exec_events.py dump
