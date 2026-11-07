#!/usr/bin/env bash
# Installed by deploy/ansible (role docker) as /usr/local/sbin/lab-docker-start-test.
# Starts one throwaway container on the default bridge network to prove Docker can
# run containers here. The image is built from the host's own /usr/bin/true and its
# libraries, so the test needs no registry, no network and no unpinned image.
set -Eeuo pipefail

image=lab/start-test:local

if ! docker image inspect "$image" >/dev/null 2>&1; then
	root=$(mktemp -d)
	trap 'rm -rf "$root"' EXIT
	mapfile -t libs < <(ldd /usr/bin/true | grep -o '/[^ ]*')
	for file in /usr/bin/true "${libs[@]}"; do
		cp --parents --dereference "$file" "$root"
	done
	tar --create --directory "$root" . | docker import - "$image" >/dev/null
fi

docker run --rm --pull=never --name "lab-start-test-$$" "$image" /usr/bin/true
echo "OK: a test container started and exited cleanly"
