#!/usr/bin/env bash
# Downloads a release tarball, verifies it against a SHA-256 pinned in the
# workflow (not one fetched from the same release), and installs one binary
# into $RUNNER_TEMP/bin (added to PATH).
#
# Usage: install-pinned-tool.sh <url> <sha256> <binary-name-in-tarball>
set -euo pipefail

url="${1:?url}"; sha="${2:?sha256}"; bin="${3:?binary}"
[[ "$sha" =~ ^[0-9a-f]{64}$ ]] || { echo "::error::bad sha256 for $bin"; exit 1; }
case "$url" in https://github.com/*) ;; *) echo "::error::unexpected download host: $url"; exit 1 ;; esac

dest="$RUNNER_TEMP/bin"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$dest"

curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp/tool.tar.gz" "$url"
echo "$sha  $tmp/tool.tar.gz" | sha256sum -c -
tar -xzf "$tmp/tool.tar.gz" -C "$tmp" "$bin"
install -m 0755 "$tmp/$bin" "$dest/$bin"
echo "$dest" >> "$GITHUB_PATH"
echo "installed $bin from $url (sha256 verified)"
