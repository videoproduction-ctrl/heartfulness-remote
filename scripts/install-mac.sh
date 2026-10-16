#!/usr/bin/env bash
# OPTIONAL, for technical users: build Heartfulness Remote on this Mac and install it,
# instead of downloading Heartfulness-Remote-Mac.zip from GitHub Releases (the normal way).
#
#   scripts/install-mac.sh [--adhoc] [--firewall] [--no-open]
#
#   --adhoc      sign ad-hoc instead of with a local signing identity
#   --firewall   also turn on the macOS firewall + stealth mode and allow the app (sudo)
#   --no-open    don't start the app after installing
#
# What it does:
#   1. Creates (once) a self-signed code-signing identity "Heartfulness Remote Local Signing"
#      in your login keychain. Signing every build with the same identity lets macOS keep the
#      Screen Recording and Accessibility permissions across rebuilds (an ad-hoc signature
#      changes with every build, so macOS asks again after each update). macOS asks for your
#      login password once to trust the certificate for code signing.
#   2. Builds with scripts/build-mac.sh --sign "<identity>" --out dist.
#   3. Quits a running copy and installs the app to ~/Applications, then opens it.
#
# Needs: Xcode (swift, codesign) and Go (the version in go.work).
set -euo pipefail

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

identity="Heartfulness Remote Local Signing"
adhoc=0
firewall=0
open_app=1
while [ $# -gt 0 ]; do
  case "$1" in
    --adhoc) adhoc=1 ;;
    --firewall) firewall=1 ;;
    --no-open) open_app=0 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
  shift
done

[ "$(uname -s)" = Darwin ] || { echo "install-mac.sh runs on macOS only." >&2; exit 1; }
root="$(cd "$(dirname "$0")/.." && pwd)"
keychain="$HOME/Library/Keychains/login.keychain-db"

have_identity() {
  security find-identity -v -p codesigning "$keychain" 2>/dev/null | grep -qF "\"$identity\""
}

create_identity() {
  echo "==> Creating the code-signing identity \"$identity\" (once)"
  local tmp pass
  tmp="$(mktemp -d)"
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN
  cat > "$tmp/cert.cnf" <<EOF
[ req ]
distinguished_name = dn
x509_extensions = ext
prompt = no
[ dn ]
CN = $identity
[ ext ]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
EOF
  # macOS' own LibreSSL writes a PKCS#12 file that `security import` understands.
  /usr/bin/openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -sha256 \
    -config "$tmp/cert.cnf" -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null
  pass="$(/usr/bin/openssl rand -hex 16)"
  /usr/bin/openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" -name "$identity" \
    -out "$tmp/identity.p12" -passout "pass:$pass"
  security import "$tmp/identity.p12" -k "$keychain" -P "$pass" -T /usr/bin/codesign >/dev/null
  echo "    macOS now asks for your login password to trust this certificate for code signing."
  security add-trusted-cert -r trustRoot -p codeSign -k "$keychain" "$tmp/cert.pem"
}

if [ "$adhoc" = 1 ]; then
  sign="adhoc"
else
  have_identity || create_identity
  if ! have_identity; then
    echo "The signing identity is not usable (was the certificate trusted?). Re-run, or use --adhoc." >&2
    exit 1
  fi
  sign="$identity"
fi

echo "==> Building"
(cd "$root" && bash scripts/build-mac.sh --sign "$sign" --out dist)
built="$root/dist/Heartfulness Remote.app"
[ -d "$built" ] || { echo "build output missing: $built" >&2; exit 1; }

echo "==> Installing to ~/Applications"
if pgrep -x HeartfulnessRemote >/dev/null 2>&1; then
  echo "    Quitting the running copy"
  # SIGTERM ends the app; its helper sees the closed pipe, ends any session and exits cleanly.
  pkill -TERM -x HeartfulnessRemote || true
  for _ in $(seq 1 40); do
    pgrep -x HeartfulnessRemote >/dev/null 2>&1 || pgrep -x hr-agent >/dev/null 2>&1 || break
    sleep 0.25
  done
fi
dest="$HOME/Applications/Heartfulness Remote.app"
mkdir -p "$HOME/Applications"
rm -rf "$dest"
ditto "$built" "$dest"
xattr -dr com.apple.quarantine "$dest" 2>/dev/null || true
codesign --verify --deep --strict "$dest"
echo "    Installed: $dest"

if [ "$firewall" = 1 ]; then
  echo "==> Firewall + stealth mode (sudo asks for your password)"
  fw=/usr/libexec/ApplicationFirewall/socketfilterfw
  sudo "$fw" --setglobalstate on
  sudo "$fw" --setstealthmode on
  for path in "$dest" "$dest/Contents/MacOS/hr-agent"; do
    sudo "$fw" --add "$path"
    sudo "$fw" --unblockapp "$path"
  done
  "$fw" --getglobalstate
  "$fw" --getstealthmode
fi

if [ "$open_app" = 1 ]; then
  open "$dest"
  echo "==> Opened Heartfulness Remote (look for its icon in the menu bar)."
fi
