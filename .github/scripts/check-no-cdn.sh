#!/usr/bin/env bash
# Fails if the built web client references third-party resources (CDN
# scripts, styles, fonts, images, frames). Everything must be served 'self'.
# Usage: check-no-cdn.sh <dist-dir>
set -euo pipefail

dist="${1:?dist dir}"
[ -d "$dist" ] || { echo "::error::$dist does not exist"; exit 1; }

found=0
report() { echo "::error::third-party resource reference in build output:"; echo "$1"; found=1; }

# Tags that load resources, with an absolute or protocol-relative URL.
html="$(grep -RIinoE '<(script|link|img|iframe|frame|embed|object|source|video|audio|track|image|use)\b[^>]*\b(src|href|data|srcset|poster)[[:space:]]*=[[:space:]]*["'"'"']?(https?:)?//[^"'"'"' >]+' \
  --include='*.html' --include='*.htm' --include='*.svg' "$dist" || true)"
[ -z "$html" ] || report "$html"

# CSS imports / url() pointing off-site.
css="$(grep -RIinoE '(@import|url\()[[:space:]]*["'"'"']?(https?:)?//[^"'"'"' )]+' \
  --include='*.css' --include='*.html' "$dist" || true)"
[ -z "$css" ] || report "$css"

# Dynamic script loading from absolute URLs in JS.
js="$(grep -RIinoE '(import\(|importScripts\()[[:space:]]*["'"'"'`](https?:)?//[^"'"'"'`]+' \
  --include='*.js' --include='*.mjs' "$dist" || true)"
[ -z "$js" ] || report "$js"

[ "$found" -eq 0 ] || exit 1
echo "no third-party resource references in $dist"
