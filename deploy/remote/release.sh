#!/usr/bin/env bash
# Runs ON THE LAB HOST as root, shipped by lab_remote (deploy/lib.sh) for release.sh.
#
#   preflight                       bootstrap + secrets done, Docker up, no cells running (exit 4)
#   receive TAG SHA256 COMMIT WHO   read a `git archive` tar on stdin into releases/TAG
#   pull REF...                     docker pull each image@sha256:digest
#   compose-pull TAG [allow-build]  pull (or, as a fallback, build) the control-plane images
#   migrate TAG                     pg_dump, then the release's one-shot `migrate` service
#   activate TAG [allow-build]      swap `current` to TAG and (re)start the control plane
#   selftest                        `labctl selftest --quick` (exit 3 if labctl is absent)
#   rollback                        swap `current` back, restore the pre-migration dump
#   record TAG COMMIT WHO RESULT    append the deployment to deployments.jsonl
set -Eeuo pipefail

LAB=/srv/lab
REL=$LAB/releases
STATE=$REL/.state
ENV_FILE=$LAB/secrets/lab.env
COMPOSE_REL=deploy/compose/control-plane.yml
WAIT=(--wait --wait-timeout 300)

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

# compose TREE ARG...: docker compose for the control plane of one release tree.
compose() {
	local tree=$1
	shift
	docker compose --project-name lab --env-file "$ENV_FILE" -f "$tree/$COMPOSE_REL" "$@"
}

swap_current() {
	ln -sfn "$1" "$LAB/current.new"
	mv -T "$LAB/current.new" "$LAB/current"
	echo "current -> $1"
}

release_tree() {
	[[ $1 =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "not a release tag"
	[[ -d $REL/$1 ]] || die "release $1 has not been received"
	printf '%s\n' "$REL/$1"
}

cmd_preflight() {
	local cells
	[[ -d $REL ]] || die "$REL is missing: run bootstrap.sh first"
	[[ -f $ENV_FILE ]] || die "$ENV_FILE is missing: run secrets.sh first"
	docker info >/dev/null 2>&1 || die "Docker is not running"
	cells=$(docker ps --quiet --filter label=lab.run_id | wc -l)
	if ((cells > 0)); then
		echo "$cells run-cell container(s) are running (label lab.run_id)" >&2
		exit 4
	fi
	echo "preflight OK: no run cells in flight"
}

cmd_receive() {
	local tag=$1 sha=$2 commit=$3 who=$4 dest tmpd have
	[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "not a release tag"
	dest=$REL/$tag
	tmpd=$(mktemp -d "$REL/.incoming.XXXXXX")
	# shellcheck disable=SC2064 # expand $tmpd now: it is local to this function
	trap "rm -rf '$tmpd'" EXIT
	cat >"$tmpd/release.tar"
	echo "$sha  $tmpd/release.tar" | sha256sum --check --status ||
		die "checksum mismatch: the transfer was corrupted"
	if [[ -d $dest ]]; then
		have=$(sed -n 's/^commit=//p' "$dest/RELEASE" 2>/dev/null || true)
		[[ $have == "$commit" ]] ||
			die "$dest holds commit ${have:-unknown}, not $commit: the tag moved; refusing"
		echo "release $tag already present (commit $commit)"
		return 0
	fi
	mkdir "$tmpd/tree"
	tar --extract --file "$tmpd/release.tar" --directory "$tmpd/tree" --no-same-owner
	printf 'tag=%s\ncommit=%s\nsha256=%s\nreceived_by=%s\nreceived_at=%s\n' \
		"$tag" "$commit" "$sha" "$who" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$tmpd/tree/RELEASE"
	[[ -f $tmpd/tree/$COMPOSE_REL ]] || die "release has no $COMPOSE_REL"
	chown -R lab:lab "$tmpd/tree"
	mv -T "$tmpd/tree" "$dest"
	echo "received $tag (commit $commit) into $dest"
}

cmd_pull() {
	local ref
	for ref in "$@"; do
		[[ $ref =~ ^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$ ]] || die "not a pinned image ref: $ref"
		docker pull --quiet "$ref"
	done
}

cmd_compose_pull() {
	local tree
	tree=$(release_tree "$1")
	if [[ ${2:-} == allow-build ]]; then
		compose "$tree" pull --ignore-buildable
		echo "building control-plane images on this host (--allow-build fallback)"
		compose "$tree" build
	else
		compose "$tree" pull
	fi
}

cmd_migrate() {
	local tree dump
	tree=$(release_tree "$1")
	mkdir -p "$STATE"
	rm -f "$STATE/pending-dump"
	if ! compose "$tree" config --services | grep -qx migrate; then
		echo "this release has no 'migrate' service: no migrations to run"
		return 0
	fi
	if compose "$tree" ps --status running --services | grep -qx db; then
		dump=$LAB/backups/pre-$1-$(date -u +%Y%m%dT%H%M%SZ).dump
		# shellcheck disable=SC2016 # expanded inside the db container, not here
		compose "$tree" exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' >"$dump"
		chmod 0600 "$dump"
		printf '%s\n' "$dump" >"$STATE/pending-dump"
		echo "pre-migration dump: $dump"
	else
		echo "database not running yet (first deploy): no pre-migration dump"
	fi
	compose "$tree" run --rm migrate
}

cmd_activate() {
	local tree build=(--no-build)
	tree=$(release_tree "$1")
	[[ ${2:-} == allow-build ]] && build=()
	mkdir -p "$STATE"
	if [[ -L $LAB/current ]]; then
		readlink "$LAB/current" >"$STATE/previous"
	else
		: >"$STATE/previous"
	fi
	swap_current "$tree"
	compose "$LAB/current" up -d --remove-orphans "${WAIT[@]}" "${build[@]}"
}

cmd_selftest() {
	if ! command -v labctl >/dev/null 2>&1; then
		echo "labctl is not installed on this host yet" >&2
		exit 3
	fi
	labctl selftest --quick
}

cmd_rollback() {
	local prev="" dump
	[[ -f $STATE/previous ]] && prev=$(<"$STATE/previous")
	if [[ -n $prev && -d $prev ]]; then
		swap_current "$prev"
		compose "$LAB/current" up -d --remove-orphans --no-build "${WAIT[@]}"
		if [[ -f $STATE/pending-dump ]]; then
			dump=$(<"$STATE/pending-dump")
			# shellcheck disable=SC2016 # expanded inside the db container, not here
			compose "$LAB/current" exec -T db \
				sh -c 'pg_restore --clean --if-exists -U "$POSTGRES_USER" -d "$POSTGRES_DB"' <"$dump"
			rm -f "$STATE/pending-dump"
			echo "database restored from $dump"
		fi
	else
		echo "no previous release: stopping the failed one"
		if [[ -L $LAB/current ]]; then
			compose "$LAB/current" down --remove-orphans
			rm -f "$LAB/current"
		fi
	fi
}

cmd_record() {
	local tag=$1 commit=$2 who=$3 result=$4
	printf '{"tag":"%s","commit":"%s","by":"%s","at":"%s","result":"%s"}\n' \
		"$tag" "$commit" "$who" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$result" >>"$LAB/deployments.jsonl"
	rm -f "$STATE/pending-dump"
}

sub=${1:-}
shift || true
case $sub in
preflight) cmd_preflight ;;
receive) cmd_receive "$@" ;;
pull) cmd_pull "$@" ;;
compose-pull) cmd_compose_pull "$@" ;;
migrate) cmd_migrate "$@" ;;
activate) cmd_activate "$@" ;;
selftest) cmd_selftest ;;
rollback) cmd_rollback ;;
record) cmd_record "$@" ;;
*) die "usage: release.sh preflight|receive|pull|compose-pull|migrate|activate|selftest|rollback|record" ;;
esac
