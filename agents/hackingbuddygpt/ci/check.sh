#!/usr/bin/env bash
# Check a freshly built hackingBuddyGPT agent image before it is pushed: what the image
# holds, then one smoke run per scenario against the recording stub model
# (agents/ci/smoke.sh). Each run's command and environment are the adapter's own
# rendering (agents/hackingbuddygpt/ci/hbg_smoke.py). Called from the repository root by
# .github/workflows/build-images.yml, after uv is set up.
#
# Usage: agents/hackingbuddygpt/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1
dir=agents/hackingbuddygpt

# what the image holds: the patched upstream, the plugin, no .env anywhere, no RAG extra,
# the LiteLLM switches, and the unprivileged user
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --network none --entrypoint /bin/sh "$image" -c '
  set -eu
  test "$(id -u):$(id -g)" = 10001:10001
  test "$LITELLM_LOCAL_MODEL_COST_MAP" = True
  test "$LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS" = True
  test "$LITELLM_MODE" = PRODUCTION
  test -z "$(find / -xdev -name .env -print -quit 2>/dev/null)"
  python -c "import importlib.metadata as m; assert m.version(\"litellm\") == \"1.97.0\""
  ! python -c "import langchain_openai" 2>/dev/null
  python - <<EOF
import inspect
from hackingBuddyGPT.utils.llm import LiteLLM
source = inspect.getsource(LiteLLM.raw_completion)
assert "            api_base=self.api_base," in source, "the api_base patch is missing"
assert "openrouter.ai" not in inspect.getsource(LiteLLM), "the OpenRouter default is back"
EOF
  # the plugin imports and registers offline; --help is a refused configuration (exit 2)
  set +e
  python -m lab_hbg LabWebTesting --help >/dev/null 2>&1
  code=$?
  set -e
  test "$code" = 2'

uv sync --frozen
status=0
for scenario in tools turn-cap; do
	out=$(mktemp -d)
	uv run python "$dir/ci/hbg_smoke.py" render "$scenario" "$out/launch"
	mapfile -d '' -t command <"$out/launch/command"
	set +e
	SMOKE_OUT="$out/smoke" bash agents/ci/smoke.sh \
		--image "$image" --name hackingbuddygpt \
		--script "$dir/ci/stub-$scenario.yaml" \
		--env-file "$out/launch/env" --timeout 300 \
		-- "${command[@]}"
	code=$?
	set -e
	uv run python "$dir/ci/hbg_smoke.py" verify "$scenario" "$out/smoke" "$code" || status=1
done
exit $status
