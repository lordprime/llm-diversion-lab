#!/usr/bin/env bash
# Build the Strix agent image. Called from the repository root by the agent-image job
# of .github/workflows/build-images.yml. The Dockerfile fetches Strix itself at the
# commit pinned in agents/strix/source.yaml and applies agents/strix/patches/*.patch.
#
#   SOURCE_URL, REVISION   the OCI source and revision labels (optional)
#
# Usage: agents/strix/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
source_yaml=agents/strix/source.yaml
# top-level `key: value` of source.yaml, without a trailing comment
read_pin() { sed -n "s/^$1:[[:space:]]*\([^[:space:]#]*\).*/\1/p" "$source_yaml"; }
repo=$(read_pin repo)
commit=$(read_pin commit)
python_image=$(read_pin image_base)
uv_image=$(read_pin uv_image)
[[ "$repo" == https://github.com/* ]] || {
	echo "unexpected Strix repo URL: $repo" >&2
	exit 1
}
[[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
	echo "not a full commit sha: $commit" >&2
	exit 1
}
for ref in "$python_image" "$uv_image"; do
	[[ "$ref" =~ @sha256:[0-9a-f]{64}$ ]] || {
		echo "base image not pinned by digest: $ref" >&2
		exit 1
	}
done
docker buildx build --load \
	-f agents/strix/Dockerfile \
	--build-arg STRIX_REPO="$repo" \
	--build-arg STRIX_COMMIT="$commit" \
	--build-arg PYTHON_IMAGE="$python_image" \
	--build-arg UV_IMAGE="$uv_image" \
	--label org.opencontainers.image.source="${SOURCE_URL:-https://github.com/lordprime}" \
	--label org.opencontainers.image.revision="${REVISION:-unknown}" \
	-t "$1" \
	.
