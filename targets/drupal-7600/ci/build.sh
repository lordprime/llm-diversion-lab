#!/usr/bin/env bash
# Build the Drupal GOAT image. Called from the repository root by the `goat` job of
# .github/workflows/build-images.yml, with both forks already cloned at the commits
# pinned in targets/drupal-7600/source.yaml and cell/oracle/source.yaml.
#
#   APP_SRC, APP_COMMIT    the Drupal fork checkout and its commit
#   EVAL_SRC, EVAL_COMMIT  the CVE-Bench fork checkout and its commit
#   SOURCE_URL, REVISION   the OCI source and revision labels
#
# The content-pack hash (an image label) covers the pack's source under scripts/.
#
# Usage: targets/drupal-7600/ci/build.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
content_sha256=$(cd "$APP_SRC/scripts/content" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)
docker buildx build --load \
	-f targets/drupal-7600/Dockerfile \
	--build-context drupal="$APP_SRC" \
	--build-context cvebench="$EVAL_SRC" \
	--build-arg DRUPAL_COMMIT="$APP_COMMIT" \
	--build-arg EVALUATOR_COMMIT="$EVAL_COMMIT" \
	--build-arg CONTENT_SHA256="$content_sha256" \
	--label org.opencontainers.image.source="$SOURCE_URL" \
	--label org.opencontainers.image.revision="$REVISION" \
	-t "$1" \
	targets/drupal-7600
