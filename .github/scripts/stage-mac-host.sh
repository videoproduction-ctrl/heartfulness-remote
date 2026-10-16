#!/usr/bin/env bash
# Copies the Mac host app zip produced by scripts/build-mac.sh to
# out/Heartfulness-Remote-Mac.zip (the stable release asset name) and checks
# that it contains README-FIRST.txt.
# Env: STRICT=true makes a missing README-FIRST.txt an error (release builds).
set -euo pipefail
shopt -s nullglob nocaseglob

zips=(dist/Heartfulness-Remote-Mac.zip)
[ -f "${zips[0]:-}" ] || zips=(dist/*.zip)
if [ "${#zips[@]}" -ne 1 ] || [ ! -f "${zips[0]}" ]; then
  echo "::error::expected exactly one zip in dist/ from scripts/build-mac.sh, found ${#zips[@]}"
  ls -la dist || true
  exit 1
fi

mkdir -p out
cp "${zips[0]}" out/Heartfulness-Remote-Mac.zip

if unzip -Z1 out/Heartfulness-Remote-Mac.zip | grep -qE '(^|/)README-FIRST\.txt$'; then
  echo "README-FIRST.txt present"
elif [ "${STRICT:-false}" = true ]; then
  echo "::error::Heartfulness-Remote-Mac.zip has no README-FIRST.txt"; exit 1
else
  echo "::warning::Heartfulness-Remote-Mac.zip has no README-FIRST.txt"
fi

unzip -Z1 out/Heartfulness-Remote-Mac.zip | head -n 20
ls -la out
shasum -a 256 out/Heartfulness-Remote-Mac.zip
