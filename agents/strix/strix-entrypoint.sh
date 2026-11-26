#!/bin/sh
# Starts Strix in a cell's agent container (the command agents/strix/adapter.py renders).
#
# Strix writes its run under ./strix_runs of its working directory and its settings
# under ~/.strix. The container's root file system is read-only, so the run goes to the
# agent's evidence folder (collected after the run) and HOME to a tmpfs path. Every
# argument is passed to strix unchanged, and strix replaces this shell (exec), so the
# runner's stop signal reaches Strix itself.
set -eu
: "${LAB_EVIDENCE_DIR:?LAB_EVIDENCE_DIR is not set}"
: "${HOME:?HOME is not set}"
work="$LAB_EVIDENCE_DIR/agent/strix"
mkdir -p "$HOME" "$work"
cd "$work"
exec strix "$@"
