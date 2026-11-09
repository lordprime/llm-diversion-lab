#!/usr/bin/env bash
# Check a freshly built DVGA GOAT image before it is pushed: the tools it must carry,
# that nothing deciding the result is readable by the app user, file ownership and
# modes, and the image's behaviour tests (health, done, permissions, objective,
# crash). Called from the repository root by the `goat` job of
# .github/workflows/build-images.yml, after uv is set up.
#
# Usage: targets/dvga/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1

# tools the app and CVE-Bench's scripts need (the images.lock expect_tools)
docker run --rm --entrypoint /bin/bash "$image" -c 'command -v curl && command -v bash'

# as the app user: nothing that decides the result is readable
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --user dvga --entrypoint /bin/bash "$image" -c '
  set -u
  fail=0
  for p in /opt/support/grader.py /opt/support/launch.sh /cve_metadata.yml /entrypoint.sh; do
    if cat "$p" >/dev/null 2>&1; then echo "readable by dvga: $p"; fail=1; fi
  done
  for d in /opt/support /run/secrets; do
    if ls "$d" >/dev/null 2>&1; then echo "listable by dvga: $d"; fail=1; fi
  done
  for v in APPLICATION_NAME GRADER_OBJECTIVE; do
    if [ -n "${!v:-}" ]; then echo "image-wide env leaks $v"; fail=1; fi
  done
  exit $fail'

# ownership and modes, as root
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --entrypoint /bin/bash "$image" -c '
  set -eu
  test "$(stat -c %U:%G:%a /opt/support)" = root:root:700
  test "$(stat -c %U:%G:%a /run/secrets)" = root:root:700
  test "$(stat -c %U:%G:%a /cve_metadata.yml)" = root:root:400
  test "$(stat -c %U:%G:%a /opt/support/launch.sh)" = root:root:700
  test ! -e /opt/dvga/requirements.txt
  test ! -e /opt/dvga/README.md
  test ! -e /opt/dvga/tests
  # the base image ships one requirements.txt (mercurial help text); no other
  test -z "$(find / -xdev -name requirements.txt ! -path "/usr/lib/python3/dist-packages/mercurial/*" -print -quit)"
  ! grep -rli diversion /opt/dvga /opt/venv /opt/support /cve_metadata.yml /entrypoint.sh'

# the image's behaviour tests
uv sync --frozen
GOAT_DVGA_IMAGE="$image" GOAT_DVGA_REQUIRE=1 uv run pytest -v tests/targets/test_dvga_image.py
