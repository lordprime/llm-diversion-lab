#!/usr/bin/env bash
# Prove the agent lane end to end with the self-check image: the stub model answers every
# API shape, the canary catches egress by name and by address, a hung agent is timed out,
# a failing agent is reported, bad input is refused, and with --docker the agent reaches
# Docker only through cell-guard while its workers reach only the tap. Called from the
# repository root by the agent lane of .github/workflows/build-images.yml, after uv and
# the smoke kit image are set up.
#
#   SMOKE_OUT     where each smoke run's outputs go (one directory per case)
#   EXTRA_IMAGES  the file build.sh listed the worker image in
#
# Usage: agents/_selfcheck/ci/check.sh <local image name>
set -euo pipefail
[ $# -eq 1 ] || {
	echo "usage: $0 <local image name>" >&2
	exit 2
}
image=$1
base=${SMOKE_OUT:?SMOKE_OUT must be set}
script=agents/_selfcheck/script.yaml
busybox=docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
worker=$(grep -x 'agent-selfcheck-worker:ci' "${EXTRA_IMAGES:?EXTRA_IMAGES must be set}")

# smoke <expected exit status> <case> [smoke.sh flags...] [-- command...]
smoke() {
	local want=$1 case=$2 got=0
	shift 2
	SMOKE_OUT="$base/$case" bash agents/ci/smoke.sh \
		--image "$image" --name _selfcheck --script "$script" --timeout 120 "$@" || got=$?
	if [[ "$got" != "$want" ]]; then
		echo "selfcheck: $case: smoke.sh exited $got, expected $want" >&2
		exit 1
	fi
	echo "selfcheck: $case: smoke.sh exited $got as expected"
}

# has <file> <fixed text>: the file contains the text
has() {
	grep -qF -- "$2" "$1" || {
		echo "selfcheck: $1 does not contain $2" >&2
		exit 1
	}
}

uv sync --frozen

# every API shape, read back through the lab's telemetry parsers; no auth value recorded
smoke 0 apis -- apis
uv run python -m agents.ci.stub_model.verify "$base/apis/requests.jsonl" \
	--expect /api/chat --expect /api/embed --expect /api/embeddings --expect /api/tags \
	--expect /v1/chat/completions --expect /v1/models --expect /v1/embeddings \
	--expect /v1/messages --expect-tool run_command --expect-tool read_file
if grep -q selfcheck-not-a-key "$base/apis/requests.jsonl"; then
	echo "selfcheck: an auth value reached requests.jsonl" >&2
	exit 1
fi
test ! -s "$base/apis/canary.jsonl"

# egress by name: the DNS question and the connection both reach the canary
smoke 10 egress-name -- egress-name example.com
has "$base/egress-name/canary.jsonl" '"kind":"dns"'
has "$base/egress-name/canary.jsonl" '"qname":"example.com."'
has "$base/egress-name/canary.jsonl" '"kind":"tcp"'

# egress by address: the default route leads to the canary too
smoke 10 egress-ip -- egress-ip 192.0.2.10
has "$base/egress-ip/canary.jsonl" '"dst":"192.0.2.10"'

# a hung agent and a failing agent
smoke 11 timeout --timeout 5 -- hang
smoke 12 agent-fails -- fail

# bad input is refused before anything runs
mkdir -p "$base/bad"
printf 'turns:\n  - tool_calls: []\n' >"$base/bad/script.yaml"
smoke 2 bad-script --script "$base/bad/script.yaml" -- apis
smoke 2 unpinned-worker --docker --worker-image busybox:1.37.0 -- apis

# --docker: only cell-guard's socket, workers (pinned and built here) reach only the tap
smoke 0 docker --docker --worker-image "$busybox" --worker-image "$worker" -- docker "$busybox" "$worker"
has "$base/docker/agent.log" 'the real Docker socket is not reachable'
has "$base/docker/agent.log" 'cell-guard refused a worker mounting the Docker socket'
has "$base/docker/cellguard.jsonl" '"allowed":false'
has "$base/docker/cellguard.jsonl" '"op":"container.create"'
test "$(grep -c '"path":"/api/tags"' "$base/docker/requests.jsonl")" = 2

# --docker: a worker's egress reaches the canary
smoke 10 docker-egress --docker --worker-image "$busybox" -- docker-egress "$busybox"
has "$base/docker-egress/canary.jsonl" '"qname":"example.com."'

echo "selfcheck: the agent lane works"
