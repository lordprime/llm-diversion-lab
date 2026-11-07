#!/usr/bin/env bash
# Runs ON THE LAB HOST as root, shipped by lab_remote (deploy/lib.sh): `labctl doctor`.
# Exits 3 when labctl is not installed yet (it arrives with a release).
set -Eeuo pipefail

if ! command -v labctl >/dev/null 2>&1; then
	echo "labctl is not installed on this host yet" >&2
	exit 3
fi
exec labctl doctor
