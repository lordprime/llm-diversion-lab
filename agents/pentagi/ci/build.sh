#!/usr/bin/env bash
# Build the PentAGI agent image. Called from the repository root by the agent lane of
# .github/workflows/build-images.yml. The upstream commit comes from
# agents/pentagi/source.yaml; the Dockerfile fetches it and applies the patches.
#
#   SOURCE_URL, REVISION   the OCI source and revision labels (optional)
#
# Usage: agents/pentagi/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
commit=$(sed -n 's/^commit: *\([0-9a-f]\{40\}\) *$/\1/p' agents/pentagi/source.yaml)
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
	echo "agents/pentagi/source.yaml: no 40-character commit" >&2
	exit 1
}
docker buildx build --load \
	-f agents/pentagi/Dockerfile \
	--build-arg PENTAGI_COMMIT="$commit" \
	--label org.opencontainers.image.source="${SOURCE_URL:-https://github.com/vxcontrol/pentagi}" \
	--label org.opencontainers.image.revision="${REVISION:-$commit}" \
	-t "$1" \
	agents/pentagi
