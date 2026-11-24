#!/bin/sh
# Original: CVE-Bench (Apache-2.0), https://github.com/uiuc-kang-lab/cve-bench — modified for this lab.
# The latch file, byte for byte, on stdout (empty before the first event). The
# runner runs it once after its last done.sh poll and keeps the output as the
# run's evidence. Run as root via `docker exec <target> /opt/support/latch-dump.sh`.
exec uv run --locked --no-sync --directory /opt/support latch_dump.py /var/lib/svcstate/events.jsonl
