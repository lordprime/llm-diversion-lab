#!/usr/bin/env bash
# Runs ON THE LAB HOST as root, shipped by lab_remote (deploy/lib.sh) for release.sh.
#
#   preflight                       bootstrap + secrets done, Docker up, no cells running (exit 4)
#   receive TAG SHA256 COMMIT WHO   read a `git archive` tar on stdin into releases/TAG
#   begin TAG                       remember the current release as the rollback target
#   labctl TAG                      install labctl for TAG into releases/TAG/.venv (host
#                                   uv, the release's uv.lock); /usr/local/bin/labctl
#                                   -> current/.venv/bin/labctl, so it follows `current`
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

# LAB_ROOT and LAB_BIN_DIR are for the test suite only; on a host they are never set.
LAB=${LAB_ROOT:-/srv/lab}
BIN=${LAB_BIN_DIR:-/usr/local/bin}
REL=$LAB/releases
STATE=$REL/.state
ENV_FILE=$LAB/secrets/lab.env
COMPOSE_REL=deploy/compose/control-plane.yml
WAIT=(--wait --wait-timeout 300)
# labctl's interpreter: installed by the base role with the host's pinned uv, the
# control-plane image's Python minor (tests check the role, this and the image agree).
LABCTL_PYTHON=3.12.13
LABCTL_PYTHON_DIR=/opt/lab/python
TAG_RE='^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'

die() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

# release_tag_of TREE: the release tag a tree (or the `current` link) belongs to.
release_tag_of() {
	local real
	real=$(readlink -f -- "$1") && real=${real##*/} && [[ $real =~ $TAG_RE ]] || {
		printf 'ERROR: %s is not a release tree (releases/vX.Y.Z)\n' "$1" >&2
		return 1
	}
	printf '%s\n' "$real"
}

# compose TREE ARG...: docker compose for the control plane of one release tree.
# LAB_RELEASE_TAG is that tree's tag: the control-plane image is lab/control:<tag>,
# so every release (and every rollback) runs its own image, never another's.
compose() {
	local tree=$1 tag
	shift
	tag=$(release_tag_of "$tree") || return 1
	LAB_RELEASE_TAG=$tag docker compose --project-name lab --env-file "$ENV_FILE" \
		-f "$tree/$COMPOSE_REL" "$@"
}

# ensure_pgdata: the Postgres data directory, mounted as the db container's data
# directory. Created 0700 when missing (the entrypoint then chowns it to postgres);
# an existing one is never touched. /srv/lab/db itself comes from the base role.
ensure_pgdata() {
	[[ -d $LAB/db ]] || die "$LAB/db is missing: run bootstrap.sh first"
	[[ -d $LAB/db/pgdata ]] && return 0
	mkdir -m 0700 "$LAB/db/pgdata"
	echo "created $LAB/db/pgdata"
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
	grep -Eq '^LAB_DB_PASSWORD=.+' "$ENV_FILE" ||
		die "LAB_DB_PASSWORD is missing from $ENV_FILE: run bootstrap.sh (it generates it once)"
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

# labctl TAG: labctl from TAG's tree, into TAG's own venv, with the host's pinned
# uv and Python; only the locked packages (and the pinned build backend) are
# downloaded, never an interpreter. The PATH entry is a link through `current`, so
# activating or rolling back a release switches labctl.
cmd_labctl() {
	local tree venv
	tree=$(release_tree "$1")
	command -v uv >/dev/null 2>&1 ||
		die "uv is not installed on this host: run bootstrap.sh (base role) first"
	venv=$tree/.venv
	echo "installing labctl for $1 into $venv"
	UV_PROJECT_ENVIRONMENT=$venv UV_PYTHON_DOWNLOADS=never \
		UV_PYTHON_INSTALL_DIR=$LABCTL_PYTHON_DIR UV_NO_CONFIG=1 \
		uv sync --project "$tree" --frozen --no-dev --no-editable --compile-bytecode \
		--python "$LABCTL_PYTHON" || die "could not install labctl for $1 (uv sync failed)"
	"$venv/bin/labctl" --help >/dev/null || die "labctl for $1 does not run"
	ln -sfn "$LAB/current/.venv/bin/labctl" "$BIN/labctl.new"
	mv -T "$BIN/labctl.new" "$BIN/labctl"
	echo "labctl: $BIN/labctl -> $LAB/current/.venv/bin/labctl"
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

# stop_writers: stop the running release's app services (everything except the
# database and the one-shot migrate); the database keeps running. Fails closed: if
# the service list cannot be read, nothing is assumed stopped.
stop_writers() {
	local all service services=()
	[[ -L $LAB/current ]] || return 0
	all=$(compose "$LAB/current" config --services) || {
		echo "ERROR: cannot read the services of $(readlink "$LAB/current")" >&2
		return 1
	}
	while IFS= read -r service; do
		[[ -z $service || $service == db || $service == migrate ]] || services+=("$service")
	done <<<"$all"
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

# in_subshell: true inside $(...) or ( ... ). With errtrace (set -E) an ERR trap also
# fires there; the failure then reaches the main shell, whose trap reports it once.
in_subshell() {
	[[ $BASHPID != "$$" ]]
}

MG_DUMP="(none)"
MG_DB="untouched (the migration has not started)"

# migrate_fail LINE: the ERR trap of cmd_migrate; release.sh then rolls back.
migrate_fail() {
	in_subshell && exit 1
	{
		printf 'ERROR: migrate failed (line %s)\n' "$1"
		printf '  current -> %s\n' "$(readlink "$LAB/current" 2>/dev/null || echo '(none)')"
		printf '  pre-migration dump: %s\n' "$MG_DUMP"
		printf '  database: %s\n' "$MG_DB"
	} >&2
	exit 1
}

cmd_migrate() {
	local tree dump services db_up=false
	trap 'migrate_fail $LINENO' ERR
	tree=$(release_tree "$1")
	mkdir -p "$STATE"
	ensure_pgdata
	services=$(compose "$tree" config --services)
	if ! grep -qx migrate <<<"$services"; then
		echo "this release has no 'migrate' service: no migrations to run"
		return 0
	fi
	running=$(compose "$tree" ps --status running --services)
	if grep -qx db <<<"$running"; then
		db_up=true
		# Before anything stops: a rollback must be possible for this database.
		compose "$tree" exec -T db sh -c "$NAME_CHECK_DB" </dev/null
	fi
	stop_writers
	if $db_up; then
		dump=$LAB/backups/pre-$1-$(date -u +%Y%m%dT%H%M%SZ).dump
		MG_DUMP="$dump (being written)"
		# shellcheck disable=SC2016 # expanded inside the db container, not here
		compose "$tree" exec -T db sh -c 'pg_dump -U "$POSTGRES_USER" -Fc "$POSTGRES_DB"' >"$dump"
		chmod 0600 "$dump"
		printf '%s\n' "$dump" >"$STATE/pending-dump"
		MG_DUMP=$dump
		echo "pre-migration dump: $dump"
	elif [[ -s $STATE/previous ]]; then
		die "release $(<"$STATE/previous") is deployed but its database is not running:" \
			"refusing to migrate without a pre-migration dump (start the db service, then retry)"
	else
		echo "database not running yet (first deploy): no pre-migration dump"
		compose "$tree" up -d "${WAIT[@]}" db
	fi
	if [[ -n ${dump:-} ]]; then
		MG_DB="may be partly migrated; release.sh rolls back from the dump"
	else
		MG_DB="may be partly migrated (first deploy: there is no dump to roll back from)"
	fi
	compose "$tree" run --rm --no-deps migrate
}

cmd_activate() {
	local tree build=(--no-build)
	tree=$(release_tree "$1")
	[[ ${2:-} == allow-build ]] && build=()
	ensure_pgdata
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
	in_subshell && exit 1
	{
		printf 'ERROR: rollback failed: %s\n' "$*"
		printf '  current -> %s\n' "$(readlink "$LAB/current" 2>/dev/null || echo '(none)')"
		printf '  database: %s\n' "$RB_DB"
		[[ -z $RB_DUMP ]] || printf '  pre-migration dump kept at %s\n' "$RB_DUMP"
	} >&2
	exit 1
}

# The live database is never dropped, and a database always exists under its name:
# 0. NAME      ${POSTGRES_DB} is at most 59 bytes, so ${POSTGRES_DB}_rb and _old (63
#              bytes at most) are never truncated by PostgreSQL onto the live name;
# 1. PRECHECK  `pg_restore --list` reads the whole dump's table of contents;
# 2. SCRATCH   create ${POSTGRES_DB}_rb with CONNECTION LIMIT 0 (no app can use it;
#              the superuser restoring it is exempt);
# 3. RESTORE   into the scratch database, in ONE transaction that stops at the
#              first error (on failure the scratch database is dropped again);
# 4. SWAP      in ONE transaction: end the live database's connections, rename it to
#              ${POSTGRES_DB}_old, rename the scratch one into its place and lift the
#              connection limit. A ${POSTGRES_DB}_old left by an earlier run is dropped
#              first, so the rollback can be run again, but only while a database
#              exists under the live name: if it does not (a manual swap stopped after
#              its first rename), ${POSTGRES_DB}_old IS the former live database and is
#              renamed back instead of dropped;
# 5. CLEANUP   drop ${POSTGRES_DB}_old (a failure only warns: the restore is live).
# Each snippet runs inside the db container (official postgres image; PostgreSQL >= 13
# for DROP DATABASE ... WITH (FORCE)), where POSTGRES_USER and POSTGRES_DB are set;
# psql variables quote the identifiers. Every snippet is one line (one log line).
read -r -d '' NAME_CHECK_DB <<'SH' || true
[ -n "$POSTGRES_DB" ] || { echo 'POSTGRES_DB is not set in the db container' >&2; exit 1; }; [ "$(($(printf %s "$POSTGRES_DB" | wc -c)))" -le 59 ] || { echo "POSTGRES_DB is longer than 59 bytes: ${POSTGRES_DB}_rb and ${POSTGRES_DB}_old would be truncated (63 bytes) onto it" >&2; exit 1; }
SH
read -r -d '' PRECHECK_DB <<'SH' || true
pg_restore --list >/dev/null
SH
read -r -d '' SCRATCH_DB <<'SH' || true
printf '%s\n' 'DROP DATABASE IF EXISTS :"rb";' 'CREATE DATABASE :"rb" OWNER :"owner" CONNECTION LIMIT 0;' | psql -X -q -v ON_ERROR_STOP=1 -v rb="${POSTGRES_DB}_rb" -v owner="$POSTGRES_USER" -U "$POSTGRES_USER" -d template1
SH
read -r -d '' RESTORE_DB <<'SH' || true
pg_restore --single-transaction --exit-on-error -U "$POSTGRES_USER" -d "${POSTGRES_DB}_rb"
SH
read -r -d '' SWAP_DB <<'SH' || true
printf '%s\n' "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = :'db') AS live_exists \gset" '\if :live_exists' 'DROP DATABASE IF EXISTS :"old" WITH (FORCE);' '\else' 'ALTER DATABASE :"old" RENAME TO :"db";' '\endif' 'BEGIN;' "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :'db' AND pid <> pg_backend_pid();" 'ALTER DATABASE :"db" RENAME TO :"old";' 'ALTER DATABASE :"rb" RENAME TO :"db";' 'ALTER DATABASE :"db" CONNECTION LIMIT -1;' 'COMMIT;' | psql -X -q -v ON_ERROR_STOP=1 -v db="$POSTGRES_DB" -v rb="${POSTGRES_DB}_rb" -v old="${POSTGRES_DB}_old" -U "$POSTGRES_USER" -d template1 >/dev/null
SH
read -r -d '' DROP_OLD_DB <<'SH' || true
printf '%s\n' 'DROP DATABASE IF EXISTS :"old" WITH (FORCE);' | psql -X -q -v ON_ERROR_STOP=1 -v old="${POSTGRES_DB}_old" -U "$POSTGRES_USER" -d template1
SH
read -r -d '' DROP_SCRATCH_DB <<'SH' || true
printf '%s\n' 'DROP DATABASE IF EXISTS :"rb" WITH (FORCE);' | psql -X -q -v ON_ERROR_STOP=1 -v rb="${POSTGRES_DB}_rb" -U "$POSTGRES_USER" -d template1
SH

# What to run by hand if the swap did not complete (POSTGRES_DB as in the db container).
# The renames are one transaction, so a half-done manual swap cannot leave the live
# name empty; _old is dropped only after COMMIT succeeded.
# shellcheck disable=SC2016 # printed for the operator, not expanded here
MANUAL_SWAP='(connected to template1, app services stopped) BEGIN; ALTER DATABASE "$POSTGRES_DB" RENAME TO "${POSTGRES_DB}_old"; ALTER DATABASE "${POSTGRES_DB}_rb" RENAME TO "$POSTGRES_DB"; ALTER DATABASE "$POSTGRES_DB" CONNECTION LIMIT -1; COMMIT; then, only if COMMIT succeeded: DROP DATABASE "${POSTGRES_DB}_old"'

db_exec() {
	compose "$LAB/current" exec -T db sh -c "$1"
}

# restore_failed MESSAGE: drop the scratch copy, keep the live database, stop.
restore_failed() {
	db_exec "$DROP_SCRATCH_DB" </dev/null ||
		RB_DB="$RB_DB; the scratch copy \${POSTGRES_DB}_rb could not be dropped (drop it by hand)"
	rollback_fail "$1"
}

# rollback: stop writers -> restore into a scratch db -> swap it in -> swap
# `current` back -> start the previous release.
cmd_rollback() {
	local prev="" restore=false
	trap 'rollback_fail "unexpected error at line $LINENO"' ERR
	[[ -f $STATE/previous ]] && prev=$(<"$STATE/previous")
	# Known before anything can fail, so every failure message names the dump.
	if [[ -f $STATE/pending-dump && -L $LAB/current ]]; then
		restore=true
		RB_DUMP=$(<"$STATE/pending-dump")
		RB_DB="untouched (the live database has not been changed)"
	fi
	stop_writers || rollback_fail "could not stop the app services"
	if $restore; then
		[[ -s $RB_DUMP ]] || rollback_fail "the pre-migration dump is missing or empty"
		db_exec "$NAME_CHECK_DB" </dev/null ||
			rollback_fail "the database name leaves no room for the rollback's scratch names"
		db_exec "$PRECHECK_DB" <"$RB_DUMP" ||
			rollback_fail "the dump is unreadable (pg_restore --list failed)"
		db_exec "$SCRATCH_DB" </dev/null ||
			restore_failed "could not create the scratch database"
		db_exec "$RESTORE_DB" <"$RB_DUMP" ||
			restore_failed "pg_restore into the scratch database failed (nothing was restored)"
		RB_DB="UNKNOWN, most likely untouched (the swap is one transaction); the restored copy is \${POSTGRES_DB}_rb (CONNECTION LIMIT 0). Run the rollback again, or by hand in psql: $MANUAL_SWAP"
		db_exec "$SWAP_DB" </dev/null ||
			rollback_fail "could not swap the restored copy into place"
		RB_DB="restored from $RB_DUMP"
		rm -f "$STATE/pending-dump"
		echo "database restored from $RB_DUMP"
		db_exec "$DROP_OLD_DB" </dev/null ||
			echo "WARNING: the replaced database \${POSTGRES_DB}_old could not be dropped (drop it by hand)" >&2
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
labctl) cmd_labctl "$@" ;;
pull) cmd_pull "$@" ;;
compose-pull) cmd_compose_pull "$@" ;;
migrate) cmd_migrate "$@" ;;
activate) cmd_activate "$@" ;;
selftest) cmd_selftest ;;
rollback) cmd_rollback ;;
record) cmd_record "$@" ;;
*) die "usage: release.sh preflight|begin|receive|labctl|pull|compose-pull|migrate|activate|selftest|rollback|record" ;;
esac
