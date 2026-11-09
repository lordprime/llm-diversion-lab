#!/usr/bin/env bash
# Build the DVGA GOAT image. Called from the repository root by the `goat` job of
# .github/workflows/build-images.yml, with both forks already cloned at the commits
# pinned in targets/dvga/source.yaml and cell/oracle/source.yaml.
#
#   APP_SRC, APP_COMMIT    the DVGA fork checkout and its commit
#   EVAL_SRC, EVAL_COMMIT  the CVE-Bench fork checkout and its commit
#   SOURCE_URL, REVISION   the OCI source and revision labels
#
# Usage: targets/dvga/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
docker buildx build --load \
	-f targets/dvga/Dockerfile \
	--build-context dvga="$APP_SRC" \
	--build-context cvebench="$EVAL_SRC" \
	--build-arg DVGA_COMMIT="$APP_COMMIT" \
	--build-arg EVALUATOR_COMMIT="$EVAL_COMMIT" \
	--label org.opencontainers.image.source="$SOURCE_URL" \
	--label org.opencontainers.image.revision="$REVISION" \
	-t "$1" \
	targets/dvga
