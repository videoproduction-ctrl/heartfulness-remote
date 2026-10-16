#!/usr/bin/env bash
# Heartfulness Remote — update the server to a newer version from GitHub.
#
# Usage (as root on the server, e.g. over SSH):
#   /opt/heartfulness-remote/deploy/update.sh            # latest "main"
#   /opt/heartfulness-remote/deploy/update.sh v1.2.0     # a release tag
#
# Fetches the requested tag/branch, checks it out, then re-runs provision.sh
# (which rebuilds and restarts the services). deploy/.env and
# deploy/turnserver.conf are git-ignored and kept as they are.
set -Eeuo pipefail

REF="${1:-main}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATUS_LOG=/var/log/heartfulness-remote-setup.log

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) update: $*" | tee -a "$STATUS_LOG"; }

if [ "$(id -u)" -ne 0 ]; then
	echo "Please run this as root (sudo $0 $REF)." >&2
	exit 1
fi
if ! [[ "$REF" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]{0,99}$ ]] || [[ "$REF" == *..* ]]; then
	echo "Not a valid tag or branch name: $REF" >&2
	exit 1
fi
if [ ! -d "$REPO_DIR/.git" ]; then
	echo "This server was installed by copying files (scripts/deploy-server.sh), not with git." >&2
	echo "To update it, run scripts/deploy-server.sh again from your Mac." >&2
	exit 1
fi

# Do not change the code under a running setup or weekly rebuild.
exec 9>/run/heartfulness-remote.lock
if ! flock -w 3600 9; then
	echo "Another setup or rebuild is still running; try again later." >&2
	exit 1
fi
old="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
log "fetching '$REF' (currently at $old)"
if ! git -C "$REPO_DIR" fetch --quiet --depth 1 --force origin "$REF"; then
	log "FAILED: could not download '$REF' from GitHub; nothing was changed"
	exit 1
fi
git -C "$REPO_DIR" checkout --quiet --force --detach FETCH_HEAD
new="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
log "code updated $old -> $new; rebuilding"
# provision.sh takes the same lock itself.
exec 9>&-
exec bash "$REPO_DIR/deploy/provision.sh"
