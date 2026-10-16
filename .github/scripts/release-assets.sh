#!/usr/bin/env bash
# Verifies the release asset directory holds exactly the expected files with
# their stable names, then writes SHA256SUMS.txt.
# Usage: release-assets.sh <dir>
set -euo pipefail

dir="${1:?asset dir}"
cd "$dir"
expected=(
  Heartfulness-Remote-Mac.zip
  Heartfulness-Remote-Client-Mac.dmg
  Heartfulness-Remote-Client-Windows.msi
  Heartfulness-Remote-Client-Windows-Setup.exe
)

missing=0
for f in "${expected[@]}"; do
  if [ ! -s "$f" ]; then echo "::error::missing release asset $f"; missing=1; fi
done
for f in *; do
  case " ${expected[*]} " in *" $f "*) ;; *) echo "::error::unexpected file in release assets: $f"; missing=1 ;; esac
done
[ "$missing" -eq 0 ] || { ls -la; exit 1; }

sha256sum "${expected[@]}" > SHA256SUMS.txt
cat SHA256SUMS.txt
ls -la
