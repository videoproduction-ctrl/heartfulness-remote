#!/usr/bin/env bash
# Copies the Tauri bundles to tauri/out/ under the stable release asset names:
#   macOS:   Heartfulness-Remote-Client-Mac.dmg
#   Windows: Heartfulness-Remote-Client-Windows.msi
#            Heartfulness-Remote-Client-Windows-Setup.exe
set -euo pipefail
shopt -s nullglob

cd tauri
rm -rf out
mkdir -p out

one() { # <description> <glob results...>: exactly one existing file
  local what="$1"; shift
  if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "::error::expected exactly one $what, found $#: $*" >&2
    find src-tauri/target -path '*/bundle/*' -maxdepth 6 -type f >&2 || true
    return 1
  fi
  printf '%s' "$1"
}

sum() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

case "$RUNNER_OS" in
  macOS)
    dmg="$(one .dmg src-tauri/target/universal-apple-darwin/release/bundle/dmg/*.dmg)"
    cp "$dmg" out/Heartfulness-Remote-Client-Mac.dmg
    # Informational: signature (ad-hoc unless signing secrets are configured)
    # and architectures of the bundled app.
    for a in src-tauri/target/universal-apple-darwin/release/bundle/macos/*.app; do
      codesign -dv "$a" 2>&1 | grep -E 'Identifier|Signature|TeamIdentifier|flags' || true
      for b in "$a"/Contents/MacOS/*; do lipo -archs "$b" || true; done
    done
    ;;
  Windows)
    msi="$(one .msi src-tauri/target/release/bundle/msi/*.msi)"
    exe="$(one 'NSIS -setup.exe' src-tauri/target/release/bundle/nsis/*-setup.exe)"
    cp "$msi" out/Heartfulness-Remote-Client-Windows.msi
    cp "$exe" out/Heartfulness-Remote-Client-Windows-Setup.exe
    ;;
  *)
    echo "::error::unsupported runner OS $RUNNER_OS"; exit 1 ;;
esac

ls -la out
(cd out && sum ./*)
