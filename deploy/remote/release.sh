#!/usr/bin/env bash
# Runs ON THE LAB HOST as root, shipped by lab_remote (deploy/lib.sh) for release.sh.
#
#   preflight                       bootstrap + secrets done, Docker up, no cells running (exit 4)
#   receive TAG SHA256 COMMIT WHO   read a `git archive` tar on stdin into releases/TAG
#   begin TAG                       remember the current release as the rollback target
#   pull REF...                     docker pull each image@sha256:digest
#   compose-pull TAG [allow-build]  check every image is pinned by digest, then pull
#                                   (or, as a fallback, build) the control-plane images
#   migrate TAG                     stop the app services (db keeps running), pg_dump,
#                                   then `run --rm --no-deps migrate` from the new release
#   activate TAG [allow-build]      swap `current` to TAG and (re)start the control plane
#   selftest                        `labctl selftest --quick` (exit 3 if labctl is absent)
#   rollback                        stop the app services, restore the pre-migration dump,
#                                   swap `current` back, start the old release
#   record TAG COMMIT WHO RESULT    append the deployment to deployments.jsonl
set -Eeuo pipefail

# LAB_ROOT is for the test suite only; on a host it is never set.
LAB=${LAB_ROOT:-/srv/lab}
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
	local tree images image unpinned=()
	tree=$(release_tree "$1")
	# Images are built in CI and pulled by digest; a tag could change under us. With
	# --allow-build, only services that are built here may use a local tag: every
	# image that is pulled must still be pinned.
	if [[ ${2:-} == allow-build ]]; then
		images=$(compose "$tree" config --format json | python3 -I -c '
import json, sys
for service in json.load(sys.stdin)["services"].values():
    if "build" not in service:
        print(service.get("image", "(no image)"))
') || die "could not read the compose configuration"
	else
		images=$(compose "$tree" config --images) || die "could not read the compose configuration"
	fi
	while IFS= read -r image; do
		[[ -z $image || $image =~ @sha256:[0-9a-f]{64}$ ]] || unpinned+=("$image")
	done <<<"$images"
	((${#unpinned[@]} == 0)) || die "control-plane images not pinned by digest: ${unpinned[*]}"
	if [[ ${2:-} == allow-build ]]; then
		compose "$tree" pull --ignore-buildable
		echo "building control-plane images on this host (--allow-build fallback)"
		compose "$tree" build
	else
		compose "$tree" pull
	fi
}

# app_services TREE: every service except the database and the one-shot migrate.
app_services() {
	compose "$1" config --services | grep -vxE 'db|migrate' || true
}

# stop_writers: stop the running release's app services; the database keeps running.
stop_writers() {
	local services
	[[ -L $LAB/current ]] || return 0
	mapfile -t services < <(app_services "$LAB/current")
	((${#services[@]} > 0)) || return 0
	echo "stopping app services: ${services[*]}"
	compose "$LAB/current" stop "${services[@]}"
}

# begin TAG: remember which release to roll back to, before anything changes.
cmd_begin() {
	release_tree "$1" >/dev/null
	mkdir -p "$STATE"
	rm -f "$STATE/pending-dump"
	if [[ -L $LAB/current ]]; then
		readlink "$LAB/current" >"$STATE/previous"
	else
		: >"$STATE/previous"
	fi
	echo "rollback target: $(<"$STATE/previous")"
}

cmd_migrate() {
	local tree dump
	tree=$(release_tree "$1")
	mkdir -p "$STATE"
	if ! compose "$tree" config --services | grep -qx migrate; then
		echo "this release has no 'migrate' service: no migrations to run"
		return 0
	fi
	stop_writers
	if compose "$tree" ps --status running --services | grep -qx db; then
		dump=$LAB/backups/pre-$1-$(date -u +%Y%m%dT%H%M%SZ).dump
		# shellcheck disable=SC2016 # expanded inside the db container, not here
		compose "$tree" exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' >"$dump"
		chmod 0600 "$dump"
		printf '%s\n' "$dump" >"$STATE/pending-dump"
		echo "pre-migration dump: $dump"
	elif [[ -s $STATE/previous ]]; then
		die "release $(<"$STATE/previous") is deployed but its database is not running:" \
			"refusing to migrate without a pre-migration dump (start the db service, then retry)"
	else
		echo "database not running yet (first deploy): no pre-migration dump"
		compose "$tree" up -d "${WAIT[@]}" db
	fi
	compose "$tree" run --rm --no-deps migrate
}

cmd_activate() {
	local tree build=(--no-build)
	tree=$(release_tree "$1")
	[[ ${2:-} == allow-build ]] && build=()
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

# State of a rollback in progress, printed on any failure so the operator knows
# exactly where the database and `current` stand.
RB_DB="untouched (no pre-migration dump for this release)"
RB_DUMP=""

rollback_fail() {
	{
		printf 'ERROR: rollback failed: %s\n' "$*"
		printf '  current -> %s\n' "$(readlink "$LAB/current" 2>/dev/null || echo '(none)')"
		printf '  database: %s\n' "$RB_DB"
		[[ -z $RB_DUMP ]] || printf '  pre-migration dump kept at %s\n' "$RB_DUMP"
	} >&2
	exit 1
}

# The database is dropped and recreated, then restored in ONE transaction that
# stops at the first error: the result is the dump exactly, or an empty database
# and a non-zero exit, never a half-restored mix of old and new schema.
# shellcheck disable=SC2016 # expanded inside the db container, not here
RECREATE_DB='set -e; M="--maintenance-db=template1 -U $POSTGRES_USER"; dropdb $M --if-exists --force "$POSTGRES_DB"; createdb $M -O "$POSTGRES_USER" "$POSTGRES_DB"'
# shellcheck disable=SC2016 # expanded inside the db container, not here
RESTORE_DB='pg_restore --single-transaction --exit-on-error --no-owner -U "$POSTGRES_USER" -d "$POSTGRES_DB"'

# rollback: stop writers -> recreate + restore the database -> swap back -> start.
cmd_rollback() {
	local prev=""
	[[ -f $STATE/previous ]] && prev=$(<"$STATE/previous")
	stop_writers || rollback_fail "could not stop the app services"
	if [[ -f $STATE/pending-dump && -L $LAB/current ]]; then
		RB_DUMP=$(<"$STATE/pending-dump")
		[[ -s $RB_DUMP ]] || rollback_fail "the pre-migration dump is missing or empty"
		RB_DB="unchanged so far (recreating it failed before the drop, or the drop failed)"
		compose "$LAB/current" exec -T db sh -c "$RECREATE_DB" ||
			rollback_fail "could not drop and recreate the database"
		RB_DB="EMPTY (recreated); restore it by hand from the dump"
		compose "$LAB/current" exec -T db sh -c "$RESTORE_DB" <"$RB_DUMP" ||
			rollback_fail "pg_restore failed (single transaction: nothing was restored)"
		RB_DB="restored from $RB_DUMP"
		rm -f "$STATE/pending-dump"
		echo "database restored from $RB_DUMP"
	fi
	if [[ -n $prev && -d $prev ]]; then
		swap_current "$prev"
		compose "$LAB/current" up -d --remove-orphans --no-build "${WAIT[@]}" ||
			rollback_fail "the previous release $prev did not start; check the host (status.sh)"
	else
		echo "no previous release: stopping the failed one"
		if [[ -L $LAB/current ]]; then
			compose "$LAB/current" down --remove-orphans ||
				rollback_fail "could not stop the failed release"
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
begin) cmd_begin "$@" ;;
receive) cmd_receive "$@" ;;
pull) cmd_pull "$@" ;;
compose-pull) cmd_compose_pull "$@" ;;
migrate) cmd_migrate "$@" ;;
activate) cmd_activate "$@" ;;
selftest) cmd_selftest ;;
rollback) cmd_rollback ;;
record) cmd_record "$@" ;;
*) die "usage: release.sh preflight|begin|receive|pull|compose-pull|migrate|activate|selftest|rollback|record" ;;
esac
