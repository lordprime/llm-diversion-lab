#!/usr/bin/env bash
# Build the hackingBuddyGPT agent image. Called from the repository root by
# .github/workflows/build-images.yml. The upstream commit comes from source.yaml, so the
# image always builds what the capability sheet and the audit describe.
#
#   SOURCE_URL, REVISION   optional OCI source and revision labels
#
# Usage: agents/hackingbuddygpt/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
dir=agents/hackingbuddygpt
commit=$(sed -n 's/^commit: *\([0-9a-f]\{40\}\) *$/\1/p' "$dir/source.yaml")
[ -n "$commit" ] || {
	echo "$dir/source.yaml: no full 40-character commit" >&2
	exit 1
}
labels=()
[ -z "${SOURCE_URL:-}" ] || labels+=(--label "org.opencontainers.image.source=$SOURCE_URL")
[ -z "${REVISION:-}" ] || labels+=(--label "org.opencontainers.image.revision=$REVISION")
docker buildx build --load \
	-f "$dir/Dockerfile" \
	--build-arg HBG_COMMIT="$commit" \
	"${labels[@]}" \
	-t "$1" \
	"$dir"
