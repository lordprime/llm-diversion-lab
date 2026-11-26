#!/usr/bin/env bash
# Build the agent lane's self-check image, plus the worker image it starts through
# cell-guard. Called from the repository root by the agent lane of
# .github/workflows/build-images.yml.
#
#   SOURCE_URL, REVISION  the OCI source and revision labels
#   EXTRA_IMAGES          a file to list extra images in, one local tag per line
#
# Usage: agents/_selfcheck/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
docker buildx build --load \
	-f agents/_selfcheck/Dockerfile \
	--label org.opencontainers.image.source="$SOURCE_URL" \
	--label org.opencontainers.image.revision="$REVISION" \
	-t "$1" \
	agents/_selfcheck
docker buildx build --load \
	-f agents/_selfcheck/worker.Dockerfile \
	--label org.opencontainers.image.source="$SOURCE_URL" \
	--label org.opencontainers.image.revision="$REVISION" \
	-t agent-selfcheck-worker:ci \
	agents/_selfcheck
echo agent-selfcheck-worker:ci >>"$EXTRA_IMAGES"
