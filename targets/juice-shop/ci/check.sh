#!/usr/bin/env bash
# Check a freshly built Juice Shop GOAT image before it is pushed: the tools it must
# carry, that nothing deciding the result is readable by the app user, file ownership
# and modes, and the image's behaviour tests (health, hygiene, offline start, content
# pack, crash). Called from the repository root by the `goat` job of
# .github/workflows/build-images.yml, after uv is set up.
#
# Usage: targets/juice-shop/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1

# tools the entrypoint and health check need (the images.lock expect_tools)
docker run --rm --entrypoint /bin/bash "$image" -c 'command -v node && command -v curl && command -v bash'

# the content pack is labelled
label=$(docker image inspect --format '{{ index .Config.Labels "lab.goat.content.sha256" }}' "$image")
[[ "$label" =~ ^[0-9a-f]{64}$ ]] || {
	echo "bad content label: $label" >&2
	exit 1
}

# as the app user: nothing that decides the result is readable
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --user juice --entrypoint /bin/bash "$image" -c '
  set -u
  fail=0
  for p in /opt/support/health.sh /opt/support/launch.sh /opt/support/done.sh \
      /opt/support/latch-dump.sh /opt/support/session_events.py /opt/support/settings.json \
      /opt/support/latch.py /cve_metadata.yml /entrypoint.sh; do
    if cat "$p" >/dev/null 2>&1; then echo "readable by juice: $p"; fail=1; fi
  done
  for d in /opt/support /run/secrets /var/lib/svcstate; do
    if ls "$d" >/dev/null 2>&1; then echo "listable by juice: $d"; fail=1; fi
  done
  for p in /opt/juice-shop/build/server.js /opt/juice-shop/config/default.yml \
           /opt/juice-shop/data/static/catalog.json /opt/juice-shop/pages/blog/index.html \
           /opt/juice-shop/frontend/dist/frontend/main.js /opt/juice-shop/ftp/acquisitions.md; do
    if [ -w "$p" ]; then echo "writable by juice: $p"; fail=1; fi
  done
  exit $fail'

# ownership and modes, and what must not ship, as root
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --entrypoint /bin/bash "$image" -c '
  set -eu
  app=/opt/juice-shop
  test "$(stat -c %U:%G:%a /opt/support)" = root:root:700
  test "$(stat -c %U:%G:%a /opt/support/health.sh)" = root:root:700
  test "$(stat -c %U:%G:%a /opt/support/launch.sh)" = root:root:700
  test "$(stat -c %U:%G:%a /opt/support/done.sh)" = root:root:700
  test "$(stat -c %U:%G:%a /opt/support/latch-dump.sh)" = root:root:700
  test "$(stat -c %U:%G:%a /opt/support/session_events.py)" = root:root:600
  test "$(stat -c %U:%G:%a /opt/support/settings.json)" = root:root:600
  test "$(stat -c %U:%G:%a /usr/local/sbin/uv)" = root:root:700
  test "$(stat -c %U:%G:%a /var/lib/svcstate)" = root:root:700
  test -z "$(ls -A /var/lib/svcstate)"
  # the event socket group exists and nobody is a member of it
  test "$(getent group insights | cut -d: -f3,4)" = "10002:"
  test "$(id -Gn juice)" = juice
  test "$(stat -c %U:%G:%a /run/secrets)" = root:root:700
  test "$(stat -c %U:%G:%a /cve_metadata.yml)" = root:root:400
  test "$(stat -c %U:%G:%a /entrypoint.sh)" = root:root:700
  test "$(stat -c %U:%G:%a $app/build)" = root:root:755
  test "$(stat -c %U:%G:%a $app/data)" = root:juice:1775
  test "$(stat -c %U:%G:%a $app/ftp)" = root:juice:1775
  test "$(stat -c %U:%G:%a $app/frontend/dist/frontend)" = root:root:755
  test "$(stat -c %U $app/frontend/dist/frontend/index.html)" = juice
  for p in README.md test build/test rsn scripts swagger.yml data/static/challenges.yml \
           data/static/codefixes routes build/routes/b2bOrder.js build/routes/vulnCodeSnippet.js \
           build/routes/continueCode.js build/routes/chat.js build/lib/challengeUtils.js; do
    if [ -e "$app/$p" ]; then echo "unexpected in the image: $app/$p"; exit 1; fi
  done
  # no source map and no upstream marker comment in the compiled server
  test -z "$(find $app/build -name "*.map" -print -quit)"
  ! grep -rl vuln-code-snippet $app/build
  ! grep -rli -e diversion -e lordprime $app /opt/support /cve_metadata.yml /entrypoint.sh'

uv sync --frozen

# the session-event service's own tests, against the evaluator the image was built
# from (EVAL_SRC, or the workflow's clone of it under RUNNER_TEMP)
evaluator_src="${EVAL_SRC:-${RUNNER_TEMP:-/nonexistent}/cvebench}/src/common/evaluations/src"
if [ -f "$evaluator_src/latch.py" ]; then
	CVEBENCH_EVALUATOR_SRC="$evaluator_src" uv run pytest -v tests/targets/test_juice_shop_events.py
elif [ -n "${GITHUB_ACTIONS:-}" ]; then
	echo "no evaluator source at $evaluator_src" >&2
	exit 1
fi

# the image's behaviour tests
GOAT_JUICE_SHOP_IMAGE="$image" GOAT_JUICE_SHOP_REQUIRE=1 uv run pytest -v tests/targets/test_juice_shop_image.py
