#!/usr/bin/env bash
# Check a freshly built Strix agent image before it is pushed. Called from the
# repository root by the agent-image job of .github/workflows/build-images.yml, after
# uv is set up. Strix runs only here, in CI, inside agents/ci/smoke.sh's cell, where
# the only reachable host is the recording stub model behind the tap and every other
# name resolves to an egress canary.
#
#  1. the image: uid 10001, Strix at the pinned commit with every lab patch applied,
#     a `docker` that refuses to run, and no key that would turn a side channel on;
#  2. side channels: the real headless CLI with the adapter's environment. Without a
#     Docker daemon it stops before the first agent turn, after the update check, the
#     LiteLLM import and the telemetry error beacon: the canary must stay empty;
#  3. model-call paths: probe_call_paths.py drives each path of the sheet's
#     model_call_paths through Strix's own code. Each must reach the tap as an Ollama
#     /api/chat request carrying the pinned num_ctx, and the canary must stay empty.
#
# Usage: agents/strix/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1
ci=agents/strix/ci
num_ctx=16384
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "== 1. the image"
# shellcheck disable=SC2016 # the script runs inside the image
docker run --rm --entrypoint /bin/sh "$image" -c '
  set -eu
  test "$(id -u)" = 10001
  command -v strix >/dev/null
  if docker version >/dev/null 2>&1; then echo "a working docker CLI is in the image"; exit 1; fi
  src=/opt/strix/strix
  grep -q "litellm.disable_hf_tokenizer_download = True" "$src/config/models.py"
  grep -q "LAB_OLLAMA_NUM_CTX" "$src/config/models.py"
  if grep -Eq "^    web_(search|get_contents),$" "$src/agents/factory.py"; then echo "web tools still offered"; exit 1; fi
  if grep -q "\"NET_ADMIN\"" "$src/runtime/docker_client.py"; then echo "sandbox still asks for NET_ADMIN"; exit 1; fi
  if grep -q "host-gateway" "$src/runtime/docker_client.py"; then echo "sandbox still maps the host"; exit 1; fi
  grep -q "RUNTIME_STATE_DIR_NAME = \"state\"" "$src/core/paths.py"
  grep -q "args.fail_on is not None" "$src/interface/main.py"
  test ! -e /opt/strix/.git
  for v in PERPLEXITY_API_KEY EXA_API_KEY POSTMAN_API_KEY STRIX_DEDUPE_MODEL DEDUPE_LLM_API_BASE OLLAMA_API_BASE STRIX_MCP_CONFIG; do
    if [ -n "$(printenv "$v" || true)" ]; then echo "image-wide env sets $v"; exit 1; fi
  done'

# The environment and command exactly as the adapter renders them for a smoke run.
uv sync --frozen --quiet
uv run python - "$work" "$num_ctx" <<'EOF'
import json
import sys
from pathlib import Path

from agents.base import AdapterLimits, AdapterRun, ModelConfig
from agents.strix.adapter import StrixAdapter

out, num_ctx = Path(sys.argv[1]), int(sys.argv[2])
run = AdapterRun(
    run_id="smoke",
    model=ModelConfig(name="smoke-model", num_ctx=num_ctx),
    target_url="http://target:8000",
    objective="Smoke test: say what you would check first.",
    llm_base_url="http://tap:8000",
    limits=AdapterLimits(max_turns=5, timeout_s=600),
)
launch = StrixAdapter().prepare(run)
env = {**launch.env, "LAB_EVIDENCE_DIR": "/tmp/evidence"}
(out / "strix.env").write_text("".join(f"{k}={v}\n" for k, v in sorted(env.items())))
# smoke.sh mounts no config volume: the objective goes inline instead of from the file
command = list(launch.command)
at = command.index("--instruction-file")
command[at : at + 2] = ["--instruction", run.objective]
(out / "command.json").write_text(json.dumps(command))
EOF
mapfile -t cli < <(uv run python -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))))' "$work/command.json")

canary_empty() { # <smoke out dir>
	if [ -s "$1/canary.jsonl" ]; then
		echo "egress canary saw traffic:" >&2
		cat "$1/canary.jsonl" >&2
		return 1
	fi
}

echo "== 2. side channels: the headless CLI stops at the missing Docker daemon"
export SMOKE_OUT="$work/cli"
mkdir -p "$SMOKE_OUT"
set +e
bash agents/ci/smoke.sh --image "$image" --name strix --script "$ci/stub-script.yaml" \
	--env-file "$work/strix.env" --timeout 300 -- "${cli[@]}"
rc=$?
set -e
echo "headless CLI exited $rc (a non-zero exit is expected without Docker)"
canary_empty "$SMOKE_OUT"

echo "== 3. model-call paths through the tap"
export SMOKE_OUT="$work/paths"
mkdir -p "$SMOKE_OUT"
bash agents/ci/smoke.sh --image "$image" --name strix --script "$ci/stub-script.yaml" \
	--env-file "$work/strix.env" --timeout 300 -- \
	python -I -c "$(cat "$ci/probe_call_paths.py")"
canary_empty "$SMOKE_OUT"
uv run python - "$SMOKE_OUT/requests.jsonl" "$num_ctx" <<'EOF'
import json
import sys
from pathlib import Path

from agents.base import CapabilitySheet

requests_file, num_ctx = Path(sys.argv[1]), int(sys.argv[2])
# what each sheet path's request carries (agents/strix/ci/probe_call_paths.py)
markers = {
    "main agent": "lab smoke: main agent",
    "history compaction": "lab smoke: compaction",
    "report dedupe judge": "You are an expert vulnerability report deduplication judge.",
    "start-up preflight": "Reply with just 'OK'.",
}
paths = [p.split(":", 1)[0] for p in CapabilitySheet.for_framework("strix").model_call_paths]
if sorted(paths) != sorted(markers):
    sys.exit(f"the sheet's call paths {paths} are not the probed ones {sorted(markers)}")

requests = []
for line in requests_file.read_text(encoding="utf-8").splitlines():
    if line.strip():
        request = json.loads(line)
        body = request.get("body")
        if isinstance(body, str):
            body = json.loads(body) if body.strip() else {}
        requests.append((request.get("path", ""), body or {}))
if not requests:
    sys.exit("the tap recorded no request")
failed = []
for path, body in requests:
    if not path.endswith("/api/chat"):
        failed.append(f"a request to {path!r}, not Ollama's /api/chat")
    elif (body.get("options") or {}).get("num_ctx") != num_ctx:
        failed.append(f"a request without options.num_ctx={num_ctx}: {body.get('options')!r}")
for name, marker in markers.items():
    if not any(marker in json.dumps(body, ensure_ascii=False) for _, body in requests):
        failed.append(f"no request from the {name} path ({marker!r})")
if failed:
    sys.exit("\n".join(failed))
print(f"all {len(markers)} call paths reached the tap ({len(requests)} requests)")
EOF
echo "strix image checks passed"
