#!/usr/bin/env bash
# Smoke-test an agent image against the recording stub model, with every way out of the
# network watched by an egress canary. Called from an agent's ci/check.sh in the agent
# lane of .github/workflows/build-images.yml, after the smoke kit image is built.
#
# Layout of one run (all on one internal Docker network, nothing reaches the internet):
#
#   stub    the recording stub model (agents/ci/stub_model), network alias `tap`, port 8000
#   canary  the egress canary (agents/ci/canary): the agent's only DNS server, answering
#           every name but `tap` with its own address, and the agent's default route;
#           it records every DNS question and every TCP/UDP connection attempt
#   holder  a pinned busybox that owns the agent's network namespace and points its
#           default route at the canary (the agent itself gets no NET_ADMIN)
#   agent   the image under test, in the holder's namespace, with /etc/hosts mapping
#           `tap` to the stub and /etc/resolv.conf naming only the canary; hardened
#           like the cell's agent service (read-only root, /tmp tmpfs, every capability
#           dropped but --cap-add ones, no-new-privileges, 512 pids, 1 GiB)
#   guard   with --docker only: cell-guard (python -m cell.cellguard.proxy, run as
#           control/runner/cell_spec.py runs it) in front of this machine's Docker
#           daemon; the agent gets only the guard's socket, at
#           /run/cellguard/docker.sock, with DOCKER_HOST pointing at it. cell-guard
#           forces every container the agent creates onto this run's network with the
#           canary as its only DNS server, so `tap` resolves and egress is recorded.
#
# Outputs, in $SMOKE_OUT (or --out):
#   requests.jsonl  every request the stub saw (path, method, headers with auth values
#                   masked, body, the reply); see agents/ci/stub_model/server.py
#   canary.jsonl    every egress attempt; empty when the agent stayed inside
#   agent.log       the agent's stdout and stderr; agent.exit its exit status
#   stub.log, canary.log  the helpers' own stderr
#   cellguard.jsonl (--docker) cell-guard's decisions; workers/<name>.log the logs of
#                   the containers the agent started through it
#
# Exit status:
#   0   the agent exited 0 within the timeout and the canary saw nothing
#   2   usage error (bad flag, missing file, invalid stub script, refused worker image)
#   3   the smoke run itself failed (Docker error, a helper did not start or died)
#   10  the canary saw an egress attempt (checked first: it wins over 11 and 12)
#   11  the agent did not finish within --timeout seconds and was killed
#   12  the agent exited with a non-zero status
# Containers, volumes and the network are removed on every exit, the guard-started
# containers and volumes (found by their lab.run_id label) included.
set -Eeuo pipefail

readonly EXIT_USAGE=2 EXIT_SETUP=3 EXIT_EGRESS=10 EXIT_TIMEOUT=11 EXIT_AGENT=12
readonly KIT_IMAGE=${SMOKE_KIT_IMAGE:-lab-smoke-kit:ci}
readonly HOLDER_IMAGE=${SMOKE_HOLDER_IMAGE:-docker.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec}
readonly DOCKER_SOCKET=${SMOKE_DOCKER_SOCKET:-/var/run/docker.sock}
readonly GUARD_DIR=/run/cellguard
readonly NAME_RE='^_?[a-z0-9][a-z0-9-]{0,40}$'
readonly PINNED_RE='^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$'
readonly LOCAL_RE='^[a-z0-9][a-z0-9._/-]*(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?$'
readonly CAP_RE='^[A-Z_]{2,32}$'

usage() {
	cat <<'EOF'
Usage: smoke.sh --image <image> --name <name> --script <stub-script.yaml>
                [--env-file <file>] [--timeout <seconds>] [--out <dir>]
                [--cap-add <CAP>]... [--docker [--worker-image <image>]...]
                [--] [command...]

Runs <image> (with [command...], else its own command) against the recording stub
model at http://tap:8000, with every other name and address going to an egress canary.

  --image          the agent image to test (a local tag or a pinned reference)
  --name           the agent's name ([a-z0-9-], a leading _ for lane fixtures)
  --script         the stub model's scripted turns (agents/ci/stub_model/script.py)
  --env-file       environment for the agent, as for docker run --env-file
  --timeout        seconds the agent may run (default 600)
  --out            where outputs go (default $SMOKE_OUT; one of the two is required)
  --cap-add        a capability the agent keeps (all others are dropped)
  --docker         give the agent a Docker socket through cell-guard
  --worker-image   an image the agent may start through cell-guard: either a
                   reference pinned by digest (pulled here, since cell-guard denies
                   pulls) or a tag of an image built on this machine (allowed by its
                   image id); a tag of a pulled image is refused. Repeatable.

Exit status: 0 pass, 2 usage, 3 smoke failure, 10 egress seen, 11 timeout,
12 agent failed. Outputs: requests.jsonl, canary.jsonl, agent.log, agent.exit.
EOF
}

fail_usage() {
	echo "smoke: $*" >&2
	echo "smoke: run with --help for usage" >&2
	exit "$EXIT_USAGE"
}

fail_setup() {
	echo "smoke: $*" >&2
	exit "$EXIT_SETUP"
}

# ------------------------------------------------------------------ arguments

image="" name="" script="" env_file="" timeout_s=600 out="${SMOKE_OUT:-}" use_docker=0
workers=() caps=() command=()

need_value() {
	[[ $# -ge 2 && -n "$2" ]] || fail_usage "$1 needs a value"
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	-h | --help)
		usage
		exit 0
		;;
	--image | --name | --script | --env-file | --timeout | --out | --cap-add | --worker-image)
		need_value "$@"
		case "$1" in
		--image) image=$2 ;;
		--name) name=$2 ;;
		--script) script=$2 ;;
		--env-file) env_file=$2 ;;
		--timeout) timeout_s=$2 ;;
		--out) out=$2 ;;
		--cap-add) caps+=("$2") ;;
		--worker-image) workers+=("$2") ;;
		esac
		shift 2
		;;
	--docker)
		use_docker=1
		shift
		;;
	--)
		shift
		command=("$@")
		break
		;;
	*) fail_usage "unknown argument: $1" ;;
	esac
done

[[ -n "$image" ]] || fail_usage "--image is required"
[[ -n "$name" ]] || fail_usage "--name is required"
[[ "$name" =~ $NAME_RE ]] || fail_usage "--name: not an agent name: $name"
[[ -n "$script" ]] || fail_usage "--script is required"
[[ -f "$script" && -r "$script" ]] || fail_usage "--script: no such file: $script"
[[ -z "$env_file" || (-f "$env_file" && -r "$env_file") ]] || fail_usage "--env-file: no such file: $env_file"
[[ "$timeout_s" =~ ^[1-9][0-9]{0,4}$ ]] || fail_usage "--timeout: not a number of seconds: $timeout_s"
[[ -n "$out" ]] || fail_usage "set SMOKE_OUT or pass --out"
for cap in "${caps[@]}"; do
	[[ "$cap" =~ $CAP_RE ]] || fail_usage "--cap-add: not a capability: $cap"
	[[ "$cap" != SYS_ADMIN && "$cap" != NET_ADMIN && "$cap" != ALL ]] || fail_usage "--cap-add: $cap is never granted"
done
((${#workers[@]} == 0 || use_docker)) || fail_usage "--worker-image needs --docker"
for ref in "${workers[@]}"; do
	[[ "$ref" =~ $PINNED_RE || "$ref" =~ $LOCAL_RE ]] || fail_usage "--worker-image: not an image reference: $ref"
	[[ "$ref" == *@* || "$ref" != *.*/* ]] || fail_usage "--worker-image: a registry image must be pinned by digest: $ref"
done

# ------------------------------------------------------------------ run state

suffix=$(printf '%s-%s' "${name#_}" "$$$RANDOM")
readonly net="smoke-$suffix"
readonly stub="$net-stub" canary="$net-canary" holder="$net-holder" agent="$net-agent"
readonly guard="$net-guard" guard_volume="$net-guard" scratch_volume="$net-scratch"
run_id=""
work=""

cleanup() {
	local status=$?
	trap - ERR
	set +e
	if [[ -n "$run_id" ]]; then
		docker ps -aq --filter "label=lab.run_id=$run_id" | xargs -r docker rm -f >/dev/null 2>&1
		docker volume ls -q --filter "label=lab.run_id=$run_id" | xargs -r docker volume rm -f >/dev/null 2>&1
	fi
	docker rm -f "$agent" "$holder" "$guard" "$canary" "$stub" >/dev/null 2>&1
	docker volume rm -f "$guard_volume" "$scratch_volume" >/dev/null 2>&1
	docker network rm "$net" >/dev/null 2>&1
	[[ -z "$work" ]] || rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT
trap 'fail_setup "command failed (line $LINENO): $BASH_COMMAND"' ERR

ip_of() {
	docker inspect -f "{{(index .NetworkSettings.Networks \"$net\").IPAddress}}" "$1"
}

# Wait up to 30 s for a check command (run inside a container) to succeed.
wait_for() {
	local what=$1
	shift
	for _ in $(seq 60); do
		if "$@" >/dev/null 2>&1; then return 0; fi
		sleep 0.5
	done
	fail_setup "$what did not come up"
}

# ------------------------------------------------------------------ checks before anything runs

docker image inspect "$image" >/dev/null 2>&1 || fail_setup "agent image not found: $image"
docker image inspect "$KIT_IMAGE" >/dev/null 2>&1 || fail_setup "smoke kit image not found: $KIT_IMAGE (build agents/ci/stub_model/Dockerfile)"
if ! docker run --rm -i --network none "$KIT_IMAGE" \
	python -m agents.ci.stub_model.server --check --script /dev/stdin --record /dev/null <"$script"; then
	fail_usage "--script: not a valid stub script: $script"
fi

mkdir -p "$out"
rm -rf "${out:?}/requests.jsonl" "$out/canary.jsonl" "$out/agent.log" "$out/agent.exit" \
	"$out/stub.log" "$out/canary.log" "$out/cellguard.jsonl" "$out/workers"
work=$(mktemp -d)

# Worker images become cell-guard's allow-list (role agent). A pinned reference is pulled
# now (cell-guard denies pulls); a local tag is allowed by its image id, but only if it was
# built here: a pulled image has a registry digest and must be named by it.
lock="$work/images.lock"
echo "images:" >"$lock"
index=0
for ref in "${workers[@]}"; do
	index=$((index + 1))
	if [[ "$ref" == *@* ]]; then
		docker pull --quiet "$ref" >/dev/null || fail_setup "cannot pull worker image $ref"
		repo=${ref%@*} digest=${ref#*@}
	else
		docker image inspect "$ref" >/dev/null 2>&1 || fail_usage "--worker-image: $ref is not pinned and not built here"
		[[ "$(docker image inspect -f '{{len .RepoDigests}}' "$ref")" == 0 ]] ||
			fail_usage "--worker-image: $ref was pulled, not built here; pin it by digest"
		repo=${ref%:*} digest=$(docker image inspect -f '{{.Id}}' "$ref")
	fi
	printf '  - {name: worker-%s, image: "%s", digest: "%s", role: agent}\n' "$index" "$repo" "$digest" >>"$lock"
done
chmod 0644 "$lock"

# ------------------------------------------------------------------ the network and helpers

docker network create --internal --label "lab.smoke=$net" "$net" >/dev/null

docker create --name "$stub" --network "$net" --network-alias tap \
	--cap-drop ALL --security-opt no-new-privileges:true \
	"$KIT_IMAGE" python -m agents.ci.stub_model.server \
	--script /tmp/script.yaml --record /tmp/requests.jsonl >/dev/null
docker cp "$script" "$stub:/tmp/script.yaml" >/dev/null
docker start "$stub" >/dev/null
wait_for "the stub model" docker exec "$stub" python -c \
	'import socket; socket.create_connection(("127.0.0.1", 8000), 1).close()'
stub_ip=$(ip_of "$stub")

docker run -d --name "$canary" --network "$net" --user 0:0 \
	--cap-drop ALL --cap-add NET_RAW --cap-add NET_BIND_SERVICE \
	"$KIT_IMAGE" python -m agents.ci.canary.canary \
	--record /tmp/canary.jsonl --ready /tmp/canary.ready --allow "tap=$stub_ip" >/dev/null
wait_for "the egress canary" docker exec "$canary" test -e /tmp/canary.ready
canary_ip=$(ip_of "$canary")

agent_args=(
	--name "$agent" --network "container:$holder"
	--read-only --tmpfs "/tmp:size=256m,mode=1777"
	--cap-drop ALL --security-opt no-new-privileges:true
	--pids-limit 512 --memory 1g
	-v "$work/hosts:/etc/hosts:ro" -v "$work/resolv.conf:/etc/resolv.conf:ro"
)
for cap in "${caps[@]}"; do agent_args+=(--cap-add "$cap"); done
[[ -z "$env_file" ]] || agent_args+=(--env-file "$env_file")

if ((use_docker)); then
	alphabet=0123456789ABCDEFGHJKMNPQRSTVWXYZ
	run_id=run_
	for _ in $(seq 26); do run_id+=${alphabet:RANDOM%32:1}; done
	docker volume create "$guard_volume" >/dev/null
	docker volume create "$scratch_volume" >/dev/null
	# as control/runner/cell_spec.py runs it: root with every capability dropped (it
	# needs only the socket's owner bits), read-only, no network, under an init
	docker run -d --name "$guard" --init --user 0:0 --read-only \
		--tmpfs /tmp:size=16m,mode=1777 --tmpfs /evidence:size=16m \
		--network none --cap-drop ALL --security-opt no-new-privileges:true \
		--pids-limit 128 --memory 256m \
		-e "LAB_RUN_ID=$run_id" \
		-e "LAB_CELLGUARD_NETWORK=$net" \
		-e LAB_CELLGUARD_IMAGES_LOCK=/etc/lab/cellguard/images.lock \
		-e "LAB_CELLGUARD_DNS=$canary_ip" \
		-e "LAB_CELLGUARD_LISTEN=$GUARD_DIR/docker.sock" \
		-e LAB_CELLGUARD_UPSTREAM=/var/run/docker.sock \
		-e "LAB_CELLGUARD_SCRATCH_VOLUME=$scratch_volume" \
		-e LAB_CELLGUARD_SOCKET_MODE=666 \
		-e LAB_EVIDENCE_DIR=/evidence \
		-v "$DOCKER_SOCKET:/var/run/docker.sock" \
		-v "$guard_volume:$GUARD_DIR" \
		-v "$lock:/etc/lab/cellguard/images.lock:ro" \
		"$KIT_IMAGE" python -m cell.cellguard.proxy >/dev/null
	wait_for "cell-guard" docker exec "$guard" test -S "$GUARD_DIR/docker.sock"
	agent_args+=(-v "$guard_volume:$GUARD_DIR" -e "DOCKER_HOST=unix://$GUARD_DIR/docker.sock")
fi

docker run -d --name "$holder" --network "$net" --hostname agent \
	--cap-drop ALL --cap-add NET_ADMIN "$HOLDER_IMAGE" \
	sh -c "ip route replace default via $canary_ip && touch /tmp/ready && exec tail -f /dev/null" >/dev/null
wait_for "the network holder" docker exec "$holder" test -e /tmp/ready
holder_ip=$(ip_of "$holder")

printf '127.0.0.1\tlocalhost\n::1\tlocalhost ip6-localhost ip6-loopback\n%s\tagent\n%s\ttap\n' \
	"$holder_ip" "$stub_ip" >"$work/hosts"
printf 'nameserver %s\n' "$canary_ip" >"$work/resolv.conf"
chmod 0644 "$work/hosts" "$work/resolv.conf"

# ------------------------------------------------------------------ the agent

docker create "${agent_args[@]}" "$image" "${command[@]}" >/dev/null

# the agent must never see this machine's Docker socket, only cell-guard's
mounts=$(docker inspect -f '{{range .Mounts}}{{.Type}} {{.Source}} {{.Destination}}{{"\n"}}{{end}}' "$agent")
while read -r kind source destination; do
	[[ -n "$kind" ]] || continue
	case "$destination" in
	/etc/hosts | /etc/resolv.conf) [[ "$kind" == bind && "$source" == "$work/"* ]] ;;
	"$GUARD_DIR") ((use_docker)) && [[ "$kind" == volume ]] ;;
	*) false ;;
	esac || fail_setup "the agent container has an unexpected mount: $kind $source -> $destination"
	[[ "$source" != "$DOCKER_SOCKET" && "$source" != *docker.sock ]] ||
		fail_setup "the agent container would see the Docker socket $source"
done <<<"$mounts"

docker start "$agent" >/dev/null
timed_out=0
if ! timeout "$timeout_s" docker wait "$agent" >"$out/agent.exit" 2>/dev/null; then
	timed_out=1
	docker kill "$agent" >/dev/null 2>&1 || true
	echo "timeout" >"$out/agent.exit"
fi
docker logs "$agent" >"$out/agent.log" 2>&1 || true

# ------------------------------------------------------------------ evidence

sleep 1 # the canary's last frames and lines
for helper in "$stub" "$canary"; do
	[[ "$(docker inspect -f '{{.State.Running}}' "$helper")" == true ]] ||
		fail_setup "$helper stopped during the run (see its log)"
done
docker cp "$stub:/tmp/requests.jsonl" "$out/requests.jsonl" >/dev/null
docker cp "$canary:/tmp/canary.jsonl" "$out/canary.jsonl" >/dev/null
docker logs "$stub" >"$out/stub.log" 2>&1 || true
docker logs "$canary" >"$out/canary.log" 2>&1 || true
if ((use_docker)); then
	docker exec "$guard" cat /evidence/cellguard/decisions.jsonl >"$out/cellguard.jsonl" 2>/dev/null || : >"$out/cellguard.jsonl"
	mkdir -p "$out/workers"
	for worker in $(docker ps -aq --filter "label=lab.run_id=$run_id"); do
		worker_name=$(docker inspect -f '{{.Name}}' "$worker")
		docker logs "$worker" >"$out/workers/${worker_name#/}.log" 2>&1 || true
	done
fi

echo "smoke: $name: $(wc -l <"$out/requests.jsonl") model request(s), $(wc -l <"$out/canary.jsonl") egress attempt(s), agent exit $(cat "$out/agent.exit")" >&2
if [[ -s "$out/canary.jsonl" ]]; then
	echo "smoke: the egress canary saw:" >&2
	head -n 20 "$out/canary.jsonl" >&2
	exit "$EXIT_EGRESS"
fi
((! timed_out)) || {
	echo "smoke: the agent ran longer than ${timeout_s}s" >&2
	exit "$EXIT_TIMEOUT"
}
[[ "$(cat "$out/agent.exit")" == 0 ]] || {
	echo "smoke: the agent failed; the end of agent.log:" >&2
	tail -n 30 "$out/agent.log" >&2
	exit "$EXIT_AGENT"
}
echo "smoke: $name passed" >&2
