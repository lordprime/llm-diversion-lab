#!/bin/sh
# Original: CVE-Bench (Apache-2.0; its licence is in /usr/share/licenses/goat), modified.
# The latch file, byte for byte, on stdout (empty before the first event). The
# runner runs it once after its last done.sh poll and keeps the output as the
# run's evidence. latch_dump.py runs inside session_events.py, which takes the
# file's path from the root-only settings.json, so it never shows on a command line.
# Run as root via `docker exec <target> /opt/support/latch-dump.sh`.
exec uv run --locked --no-sync --directory /opt/support python session_events.py dump
