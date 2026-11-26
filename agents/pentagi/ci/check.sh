#!/usr/bin/env bash
# Check a freshly built PentAGI agent image before it is pushed: what the image must
# carry, then one smoke run against the recording stub model, with PentAGI's workers
# started through cell-guard. Called from the repository root by the agent lane of
# .github/workflows/build-images.yml, after uv and the smoke kit image are set up.
#
# The smoke run must show every model call path in agents/sheets/pentagi.yaml reaching
# the stub (python -m agents.pentagi.smoke verify), every chat call carrying the run's
# model and num_ctx, and an empty canary (nothing tried to leave). The flow itself must
# finish: the driver exits 0 only when PentAGI finished the flow's task.
#
#   SMOKE_OUT  where the smoke run's outputs go
#
# Usage: agents/pentagi/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1
base=${SMOKE_OUT:?SMOKE_OUT must be set}
mkdir -p "$base"

# the small Kali worker pinned in source.yaml (smoke_worker_image)
worker=$(awk '
	/^smoke_worker_image:/ { inside = 1; next }
	/^[^ ]/ { inside = 0 }
	inside && $1 == "image:" { image = $2 }
	inside && $1 == "digest:" { digest = $2 }
	END { if (image != "" && digest != "") print image "@" digest }
' agents/pentagi/source.yaml)
[[ "$worker" =~ ^[a-z0-9./-]+@sha256:[0-9a-f]{64}$ ]] || {
	echo "pentagi check: no smoke_worker_image in agents/pentagi/source.yaml" >&2
	exit 1
}

# what the image carries, and that it does not run as root
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --entrypoint /bin/sh "$image" -c '
  set -eu
  test -x /opt/pentagi/bin/pentagi
  test -f /opt/lab/pentagi/driver.py
  command -v python3
  for bin in initdb pg_ctl psql pg_dump postgres; do test -x "/usr/lib/postgresql/17/bin/$bin"; done
  test "$(id -u)" != 0
  test -d /usr/share/postgresql/17/extension && ls /usr/share/postgresql/17/extension/vector.control'

uv sync --frozen
uv run python -m agents.pentagi.smoke env >"$base/pentagi.env"

status=0
SMOKE_OUT="$base/smoke" bash agents/ci/smoke.sh \
	--image "$image" --name pentagi --script agents/pentagi/ci/stub-script.yaml \
	--env-file "$base/pentagi.env" --timeout 900 \
	--docker --worker-image "$worker" || status=$?
if [[ "$status" != 0 ]]; then
	echo "pentagi check: smoke.sh exited $status (0 expected); agent log tail:" >&2
	tail -n 80 "$base/smoke/agent.log" >&2 || true
	exit 1
fi

uv run python -m agents.ci.stub_model.verify "$base/smoke/requests.jsonl" \
	--expect /api/chat --expect /api/embeddings --expect-tool terminal
uv run python -m agents.pentagi.smoke verify "$base/smoke"
