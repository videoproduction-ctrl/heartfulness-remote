#!/usr/bin/env bash
# Downloads the built installers from GitHub into ./dist/ (run on your Mac).
#
#   scripts/fetch-dist.sh               newest GitHub Release; falls back to
#                                       the newest successful CI run on main
#   scripts/fetch-dist.sh --release v0.1.0   a specific release
#   scripts/fetch-dist.sh --ci [--branch main] [--run RUN_ID]
#                                       artifacts of a CI run instead
#
# Files (same names in releases and CI):
#   Heartfulness-Remote-Mac.zip                    the app for the Mac you control
#   Heartfulness-Remote-Client-Mac.dmg             client for another Mac
#   Heartfulness-Remote-Client-Windows-Setup.exe   client for Windows
#   Heartfulness-Remote-Client-Windows.msi         client for Windows (MSI)
#   SHA256SUMS.txt                                 checksums (releases only)
#
# Needs the GitHub CLI: `brew install gh` (or https://cli.github.com), then
# `gh auth login` once. Works with the macOS default bash 3.2.
set -euo pipefail

REPO="${HR_REPO:-videoproduction-ctrl/heartfulness-remote}"
WORKFLOW="ci.yml"
mode="auto"; tag=""; branch="main"; run_id=""

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --release) mode="release"; if [ $# -gt 1 ] && [ "${2#-}" = "$2" ]; then tag="$2"; shift; fi ;;
    --ci) mode="ci" ;;
    --branch) mode="ci"; branch="${2:?--branch needs a name}"; shift ;;
    --run) mode="ci"; run_id="${2:?--run needs a run id}"; shift ;;
    --repo) REPO="${2:?--repo needs owner/name}"; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
  shift
done

if ! command -v gh >/dev/null 2>&1; then
  cat >&2 <<'EOF'
The GitHub command-line tool "gh" is not installed.
Install it with Homebrew:   brew install gh
(or download it from https://cli.github.com), then run this script again.
EOF
  exit 1
fi
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  cat >&2 <<'EOF'
You are not signed in to GitHub in the terminal yet. Run:

    gh auth login

and answer: GitHub.com -> HTTPS -> "Login with a web browser". Copy the code
it shows, press Enter, approve in the browser, then run this script again.
EOF
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
dist="$root/dist"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$dist"

sha256() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$@"; else sha256sum "$@"; fi; }

fetch_release() {
  local t="$1"
  if [ -z "$t" ]; then
    t="$(gh release view -R "$REPO" --json tagName --jq .tagName 2>/dev/null || true)"
    [ -n "$t" ] || return 1
  fi
  # Called from `if`/`||`, where `set -e` is suspended: check explicitly.
  echo "Downloading release $t from $REPO ..."
  gh release download "$t" -R "$REPO" -D "$tmp" --clobber \
    --pattern 'Heartfulness-Remote-*' --pattern 'SHA256SUMS.txt' || return 1
  if [ -f "$tmp/SHA256SUMS.txt" ]; then
    echo "Checking SHA-256 checksums ..."
    if ! (cd "$tmp" && sha256 -c SHA256SUMS.txt); then
      echo "Checksum mismatch: the downloads are damaged or were altered. Nothing was copied to dist/." >&2
      exit 1
    fi
  else
    echo "warning: release has no SHA256SUMS.txt; files were not verified" >&2
  fi
  source_desc="release $t"
}

fetch_ci() {
  local id="$run_id"
  if [ -z "$id" ]; then
    id="$(gh run list -R "$REPO" --workflow "$WORKFLOW" --branch "$branch" --event push \
          --status success --limit 1 --json databaseId --jq '.[0].databaseId // empty')"
    if [ -z "$id" ]; then
      echo "No successful CI run found on branch '$branch'." >&2
      exit 1
    fi
  fi
  local sha
  sha="$(gh run view "$id" -R "$REPO" --json headSha --jq .headSha)"
  echo "Downloading artifacts of CI run $id (commit ${sha:0:12}) from $REPO ..."
  gh run download "$id" -R "$REPO" -D "$tmp/ci" \
    -n heartfulness-remote-mac-host \
    -n heartfulness-remote-client-macos \
    -n heartfulness-remote-client-windows
  find "$tmp/ci" -type f -name 'Heartfulness-Remote-*' -exec mv -f {} "$tmp/" \;
  source_desc="CI run $id (commit ${sha:0:12})"
}

source_desc=""
case "$mode" in
  release) fetch_release "$tag" || { echo "Release '${tag:-latest}' not found in $REPO." >&2; exit 1; } ;;
  ci) fetch_ci ;;
  auto)
    if ! fetch_release ""; then
      echo "No GitHub Release yet; using the newest successful CI run on '$branch'."
      fetch_ci
    fi
    ;;
esac

got=0
for f in "$tmp"/Heartfulness-Remote-* "$tmp"/SHA256SUMS.txt; do
  [ -f "$f" ] || continue
  mv -f "$f" "$dist/"
  got=$((got + 1))
done
[ "$got" -gt 0 ] || { echo "Nothing was downloaded." >&2; exit 1; }

echo
echo "Downloaded from $source_desc into $dist:"
(cd "$dist" && for f in Heartfulness-Remote-* SHA256SUMS.txt; do
  [ -f "$f" ] || continue
  size="$(du -h "$f" | cut -f1)"
  printf '  %-46s %6s  sha256 %s\n' "$f" "$size" "$(sha256 "$f" | cut -d' ' -f1)"
done)

for want in Heartfulness-Remote-Mac.zip Heartfulness-Remote-Client-Mac.dmg \
            Heartfulness-Remote-Client-Windows-Setup.exe Heartfulness-Remote-Client-Windows.msi; do
  [ -f "$dist/$want" ] || echo "  (missing: $want)"
done
