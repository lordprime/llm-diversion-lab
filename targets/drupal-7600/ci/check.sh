#!/usr/bin/env bash
# Check a freshly built Drupal GOAT image before it is pushed: the tools it must
# carry, that nothing in the image names the study, file ownership and modes, and
# the image's behaviour tests. Called from the repository root by the `goat` job of
# .github/workflows/build-images.yml, after uv is set up.
#
# Usage: targets/drupal-7600/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1

# tools the image's scripts need (the images.lock expect_tools)
docker run --rm --entrypoint /bin/bash "$image" -c 'command -v curl && command -v bash'

# as the web user: the support directory and the secrets are out of reach
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --user www-data --entrypoint /bin/bash "$image" -c '
  set -u
  fail=0
  for p in /cve_metadata.yml /entrypoint.sh /opt/support/health.sh; do
    if cat "$p" >/dev/null 2>&1; then echo "readable by www-data: $p"; fail=1; fi
  done
  for d in /opt/support /run/secrets; do
    if ls "$d" >/dev/null 2>&1; then echo "listable by www-data: $d"; fail=1; fi
  done
  exit $fail'

# ownership and modes, as root
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --entrypoint /bin/bash "$image" -c '
  set -eu
  test "$(stat -c %U:%G:%a /opt/support)" = root:root:700
  test "$(stat -c %U:%G:%a /run/secrets)" = root:root:700
  test "$(stat -c %U:%G:%a /cve_metadata.yml)" = root:root:400
  test "$(stat -c %U:%G:%a /var/www/html/sites/default/settings.php)" = root:root:444
  test ! -e /var/www/html/scripts
  test ! -e /var/www/html/.git
  ! grep -rliI -e diversion -e lordprime /var/www/html/sites /var/www/data /usr/local/lib/portal /cve_metadata.yml /entrypoint.sh /opt/support'

# the image's behaviour tests
uv sync --frozen
GOAT_DRUPAL_7600_IMAGE="$image" GOAT_DRUPAL_7600_REQUIRE=1 uv run pytest -v tests/targets/test_drupal_image.py
