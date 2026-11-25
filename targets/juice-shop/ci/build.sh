#!/usr/bin/env bash
# Build the Juice Shop GOAT image. Called from the repository root by the `goat` job
# of .github/workflows/build-images.yml, with both forks already cloned at the
# commits pinned in targets/juice-shop/source.yaml and cell/oracle/source.yaml.
#
#   APP_SRC, APP_COMMIT    the Juice Shop fork checkout and its commit
#   EVAL_SRC, EVAL_COMMIT  the CVE-Bench fork checkout and its commit
#   SOURCE_URL, REVISION   the OCI source and revision labels
#
# The content pack's SHA-256 becomes the image label lab.goat.content.sha256; the
# Dockerfile checks the pack it builds from has exactly that hash.
#
# Usage: targets/juice-shop/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
content_sha256=$(sha256sum "$APP_SRC/data/static/catalog.json" | cut -c1-64)
docker buildx build --load \
	-f targets/juice-shop/Dockerfile \
	--build-context juice-shop="$APP_SRC" \
	--build-context cvebench="$EVAL_SRC" \
	--build-arg JUICE_SHOP_COMMIT="$APP_COMMIT" \
	--build-arg EVALUATOR_COMMIT="$EVAL_COMMIT" \
	--build-arg CONTENT_SHA256="$content_sha256" \
	--label org.opencontainers.image.source="$SOURCE_URL" \
	--label org.opencontainers.image.revision="$REVISION" \
	-t "$1" \
	targets/juice-shop
