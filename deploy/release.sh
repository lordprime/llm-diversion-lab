#!/usr/bin/env bash
# Deploy a tagged release to a lab host, with automatic rollback (DEPLOYMENT §4.2).
set -Eeuo pipefail

usage() {
	cat <<'EOF'
Usage: deploy/release.sh <host> --tag vX.Y.Z[-suffix] [--allow-build] [--quick-selftest | --skip-selftest]

Deploys the git tag to /srv/lab/releases/<tag> on <host> and makes it current:
 1. refuse if this git tree is dirty or the tag does not exist, or if its
    images.lock does not pin every image the chosen self-test starts;
 2. refuse if run cells are in flight (containers labelled lab.run_id);
 3. `git archive` the tag and copy it over SSH, verified by SHA-256;
 4. pull every image in the tag's deploy/images.lock by digest, and the
    control-plane images (deploy/compose/control-plane.yml), which must all be
    pinned by digest (unless --allow-build); install labctl for the tag into
    its own venv (/usr/local/bin/labctl follows `current`);
 5. if the release has a `migrate` service: stop the app services (the database
    keeps running), pg_dump, then `compose run --rm --no-deps migrate`;
 6. swap the `current` symlink and restart the control plane (compose up --wait);
 7. `labctl selftest` (every target; `--quick-selftest`: DVGA only) if labctl
    is installed;
 8. on any failure in 5-7: stop the app services, restore the dump, swap
    `current` back, start the previous release, exit non-zero;
 9. record the deployment in /srv/lab/deployments.jsonl.

Re-deploying a tag that is already on the host reuses it; a tag that now points
at a different commit is refused.

Options:
  --tag TAG        the release tag (required)
  --allow-build    let compose build images on the host (fallback only: images
                   are normally built in CI and pulled)
  --quick-selftest run the quick self-test (DVGA pair only) instead of the full
                   one (every target; Juice Shop resets restart its container,
                   so the full self-test takes several minutes)
  --skip-selftest  do not run the self-test (emergencies only)
  --drain          not available in M0 (there is no queue to pause yet)
  -h, --help       show this help
EOF
}

host="" tag="" allow_build=0 selftest=1 selftest_mode=full
while (($#)); do
	case $1 in
	-h | --help)
		usage
		exit 0
		;;
	--tag)
		[[ $# -ge 2 ]] || {
			printf 'ERROR: --tag needs a value (try --help)\n' >&2
			exit 2
		}
		tag=$2
		shift
		;;
	--allow-build) allow_build=1 ;;
	--quick-selftest) selftest_mode=quick ;;
	--skip-selftest) selftest=0 ;;
	--drain)
		printf 'ERROR: --drain is not available in M0: stop the runner by hand, then deploy\n' >&2
		exit 2
		;;
	-*)
		printf 'ERROR: unknown option %s (try --help)\n' "$1" >&2
		exit 2
		;;
	*)
		[[ -z $host ]] || {
			printf 'ERROR: one host only (try --help)\n' >&2
			exit 2
		}
		host=$1
		;;
	esac
	shift
done

# shellcheck source=lib.sh source-path=SCRIPTDIR
source "$(dirname -- "${BASH_SOURCE[0]}")/lib.sh"
LAB_RUNBOOK="docs/DEPLOYMENT.md §4.2 (release.sh), §5 (operating rules)"
[[ -n $host ]] || lab_usage_error "missing <host>"
[[ -n $tag ]] || lab_usage_error "missing --tag vX.Y.Z"
[[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] ||
	lab_usage_error "'$tag' is not a release tag (vX.Y.Z or vX.Y.Z-suffix)"

git_() { git -C "$LAB_REPO_ROOT" "$@"; }

lab_step "Check the git tree"
[[ -z $(git_ status --porcelain) ]] ||
	lab_fail "the working tree is dirty: commit or stash first (git status)"
commit=$(git_ rev-parse -q --verify "refs/tags/$tag^{commit}") ||
	lab_fail "tag $tag does not exist (git tag -l; git fetch --tags)"
for path in deploy/compose/control-plane.yml deploy/images.lock; do
	git_ cat-file -e "$commit:$path" 2>/dev/null || lab_fail "$tag has no $path"
done
who=$(git_ config user.name 2>/dev/null || id -un)
who=${who//[^A-Za-z0-9._@-]/_}

# images.lock -> image@sha256:digest refs (validated; the host checks them again).
read -r -d '' IMAGES_PY <<'PY' || true
import re, sys

import yaml

doc = yaml.safe_load(sys.stdin)
entries = doc.get("images") if isinstance(doc, dict) else None
if not isinstance(entries, list):
    sys.exit("images.lock: expected a top-level 'images' list")
for entry in entries:
    ref = f"{entry.get('image', '')}@{entry.get('digest', '')}"
    if not re.fullmatch(r"[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}", ref):
        sys.exit(f"images.lock: entry {entry.get('name')!r} has no pinned image@digest")
    print(ref)
PY
images=$(git_ show "$commit:deploy/images.lock" | lab_python -c "$IMAGES_PY") ||
	lab_fail "deploy/images.lock in $tag is not usable"
[[ -n $images ]] || lab_fail "deploy/images.lock in $tag lists no images"
mapfile -t image_refs <<<"$images"

# The images the chosen self-test starts, from the release's own self-test experiment
# (its targets; quick mode keeps the first, as labctl does) and each target's cell file
# (x-lab cell_image and target_image). Prints the ones images.lock does not pin.
read -r -d '' SELFTEST_IMAGES_PY <<'PY' || true
import subprocess, sys

import yaml

repo, commit, mode = sys.argv[1:4]


def show(path):
    done = subprocess.run(
        ["git", "-C", repo, "show", f"{commit}:{path}"], capture_output=True, text=True
    )
    if done.returncode != 0:
        sys.exit(f"{path} is missing from the release")
    return yaml.safe_load(done.stdout)


try:
    targets = [t["name"] for t in show("experiments/selftest.yaml")["targets"]]
    if mode == "quick":
        targets = targets[:1]
    needed = []
    for target in targets:
        meta = show(f"deploy/compose/cell.{target}.yml")["x-lab"]
        for name in (meta["cell_image"], meta["target_image"]):
            if name not in needed:
                needed.append(name)
    pinned = {entry.get("name") for entry in show("deploy/images.lock")["images"]}
except (KeyError, TypeError, yaml.YAMLError) as exc:
    sys.exit(f"cannot work out the self-test's images: {exc!r}")
if not needed:
    sys.exit("the self-test experiment lists no targets")
print(" ".join(name for name in needed if name not in pinned))
PY
if ((selftest)); then
	missing=$(lab_python -c "$SELFTEST_IMAGES_PY" "$LAB_REPO_ROOT" "$commit" "$selftest_mode") ||
		lab_fail "cannot check the images the $selftest_mode self-test needs in $tag"
	[[ -z $missing ]] || lab_fail "the $selftest_mode self-test needs $missing pinned in deploy/images.lock of $tag; \
pin them (build-images workflow, then images.lock) or deploy with --quick-selftest (DVGA only)"
fi

lab_step "Preflight on $host"
lab_load_host "$host"
rc=0
lab_remote release.sh preflight || rc=$?
case $rc in
0) ;;
4) lab_fail "an experiment is running on $host; wait for it to finish (no deploys mid-experiment)" ;;
*) lab_fail "preflight failed on $host (exit $rc)" ;;
esac

lab_step "Copy $tag ($commit) to $host"
workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT
git_ archive --format=tar -o "$workdir/release.tar" "$commit"
sha=$(sha256sum "$workdir/release.tar" | cut -d' ' -f1)
lab_remote_stdin release.sh receive "$tag" "$sha" "$commit" "$who" <"$workdir/release.tar"

lab_step "Pull pinned images on $host"
lab_remote release.sh pull "${image_refs[@]}"
build_arg=()
((allow_build)) && build_arg=(allow-build)
lab_remote release.sh compose-pull "$tag" "${build_arg[@]}"

# Before anything changes: a release whose labctl cannot be installed is refused.
lab_step "Install labctl for $tag on $host"
lab_remote release.sh labctl "$tag"

rollback() {
	lab_warn "$1: rolling back $host"
	LAB_STEP="Roll back $host"
	if lab_remote release.sh rollback; then
		lab_remote release.sh record "$tag" "$commit" "$who" rolled-back ||
			lab_warn "the rollback worked but could not be recorded in deployments.jsonl"
		lab_fail "$1; $host was rolled back to the previous release"
	fi
	lab_fail "$1; THE ROLLBACK ALSO FAILED: check $host by hand (status.sh)"
}

lab_step "Record the rollback target on $host"
lab_remote release.sh begin "$tag"

lab_step "Migrate the database on $host"
lab_remote release.sh migrate "$tag" || rollback "migrations failed"

lab_step "Activate $tag on $host"
lab_remote release.sh activate "$tag" "${build_arg[@]}" || rollback "the control plane did not come up"

selftest_result="skipped"
if ((selftest)); then
	lab_step "Self-test ($selftest_mode) on $host"
	rc=0
	lab_remote release.sh selftest "$selftest_mode" || rc=$?
	case $rc in
	0) selftest_result="passed ($selftest_mode)" ;;
	3)
		lab_warn "labctl is not installed on $host; self-test skipped"
		selftest_result="not available"
		;;
	*) rollback "the $selftest_mode self-test failed (exit $rc)" ;;
	esac
fi

lab_step "Record the deployment"
lab_remote release.sh record "$tag" "$commit" "$who" ok

lab_info "OK: $host now runs $tag (${commit:0:12}), self-test $selftest_result"
