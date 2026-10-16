#!/usr/bin/env bash
# Heartfulness Remote — weekly security rebuild (run by heartfulness-rebuild.timer).
#
# Rebuilds the images from the code that is ALREADY checked out (it never
# downloads new project code) so that patched base images (Alpine, Debian,
# Caddy, coturn) are picked up, then restarts only what changed.
# To move to a newer version of the project itself, use deploy/update.sh.
set -Eeuo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$REPO_DIR/deploy"
STATUS_LOG=/var/log/heartfulness-remote-setup.log
COMPOSE=(docker compose --project-name heartfulness-remote -f "$DEPLOY_DIR/docker-compose.yml" --env-file "$DEPLOY_DIR/.env")

log() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) weekly rebuild: $*" | tee -a "$STATUS_LOG"; }
trap 'log "FAILED (see: journalctl -u heartfulness-rebuild)"' ERR

if [ ! -f "$DEPLOY_DIR/.env" ] || [ ! -f "$DEPLOY_DIR/turnserver.conf" ]; then
	log "skipped: run deploy/provision.sh first"
	exit 1
fi
rev="$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "copied files")"
"${COMPOSE[@]}" pull --quiet caddy coturn
"${COMPOSE[@]}" build --pull server
"${COMPOSE[@]}" up -d --remove-orphans
docker image prune -f >/dev/null
log "OK (code $rev, base images refreshed)"
