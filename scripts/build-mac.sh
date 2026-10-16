#!/usr/bin/env bash
# Builds the Mac host app "Heartfulness Remote.app" (universal: Apple silicon + Intel) and
# DIR/Heartfulness-Remote-Mac.zip, which contains a folder "Heartfulness Remote" with the app
# and README-FIRST.txt. Runs on macOS with Xcode (or its command-line tools) and Go.
#
#   scripts/build-mac.sh [--sign adhoc|"<codesign identity>"] [--out DIR]
#
#   --sign adhoc        ad-hoc signature (default; what CI and GitHub Releases use)
#   --sign "Name"       a code-signing identity from your keychain, e.g. the self-signed
#                       "Heartfulness Remote Local Signing" created by scripts/install-mac.sh
#   --out DIR           output directory (default: dist), relative to the current directory
#
# Environment:
#   HR_VERSION   x.y.z stamped into Info.plist and hr-agent (default: 0.1.0)
#   HR_BUILD     CFBundleVersion (default: $GITHUB_RUN_NUMBER, else 1)
#
# Steps: hr-agent (Go, arm64 + amd64, lipo) → HeartfulnessRemote (swift build, arm64 +
# x86_64) → bundle (Info.plist, AppIcon.icns) → codesign (hardened runtime; helper first)
# → verify → zip (ditto) → verify the zipped copy.
set -euo pipefail

usage() { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit "${1:-0}"; }

sign="adhoc"
out="dist"
while [ $# -gt 0 ]; do
  case "$1" in
    --sign) sign="${2:?--sign needs adhoc or an identity name}"; shift ;;
    --out) out="${2:?--out needs a directory}"; shift ;;
    -h|--help) usage 0 ;;
    *) echo "unknown option: $1" >&2; usage 2 ;;
  esac
  shift
done

if [ "$(uname -s)" != Darwin ]; then
  echo "build-mac.sh must run on macOS (it uses swift, lipo, codesign, sips, iconutil and ditto)." >&2
  exit 1
fi
for tool in go swift lipo codesign sips iconutil ditto plutil xattr; do
  command -v "$tool" >/dev/null 2>&1 || { echo "missing tool: $tool" >&2; exit 1; }
done

root="$(cd "$(dirname "$0")/.." && pwd)"
case "$out" in
  /*) ;;
  *) out="$(pwd)/$out" ;;
esac

version="${HR_VERSION:-}"
[ -n "$version" ] || version="0.1.0"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "HR_VERSION must look like 1.2.3 (got '$version')" >&2
  exit 1
fi
build="${HR_BUILD:-${GITHUB_RUN_NUMBER:-1}}"
[[ "$build" =~ ^[0-9]+$ ]] || build=1

if [ "$sign" = adhoc ]; then
  identity="-"
  sign_label="ad-hoc"
else
  identity="$sign"
  sign_label="identity \"$sign\""
fi

resources="$root/mac/Resources"
entitlements="$resources/HeartfulnessRemote.entitlements"
for f in Info.plist HeartfulnessRemote.entitlements README-FIRST.txt AppIcon.png; do
  [ -f "$resources/$f" ] || { echo "missing mac/Resources/$f" >&2; exit 1; }
done

work="$(mktemp -d "${TMPDIR:-/tmp}/hr-build-mac.XXXXXX")"
trap 'rm -rf "$work"' EXIT

echo "==> Heartfulness Remote $version (build $build), signing: $sign_label"
sw_vers 2>/dev/null | sed 's/^/    /' || true

# ---------------------------------------------------------------- hr-agent
echo "==> hr-agent (Go, darwin arm64 + amd64)"
go version
ldflags="-s -w -X github.com/videoproduction-ctrl/heartfulness-remote/agent/internal/core.Version=$version"
for arch in arm64 amd64; do
  (cd "$root" && CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" \
    go build -trimpath -ldflags "$ldflags" -o "$work/hr-agent-$arch" ./agent/cmd/hr-agent)
done
lipo -create -output "$work/hr-agent" "$work/hr-agent-arm64" "$work/hr-agent-amd64"
lipo -info "$work/hr-agent"

# ------------------------------------------------------------- Swift app
echo "==> HeartfulnessRemote (Swift, release, arm64 + x86_64)"
swift --version 2>&1 | sed -n 1p
swift_args=(-c release --arch arm64 --arch x86_64 --package-path "$root/mac")
swift build "${swift_args[@]}"
bin_dir="$(swift build "${swift_args[@]}" --show-bin-path)"
exe="$bin_dir/HeartfulnessRemote"
if [ ! -x "$exe" ]; then
  echo "Swift build output not found at $exe" >&2
  ls -la "$bin_dir" >&2 || true
  exit 1
fi
lipo -info "$exe"

# ---------------------------------------------------------------- bundle
echo "==> Assembling Heartfulness Remote.app"
app="$work/Heartfulness Remote.app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$exe" "$app/Contents/MacOS/HeartfulnessRemote"
cp "$work/hr-agent" "$app/Contents/MacOS/hr-agent"
chmod 755 "$app/Contents/MacOS/HeartfulnessRemote" "$app/Contents/MacOS/hr-agent"

plist="$app/Contents/Info.plist"
cp "$resources/Info.plist" "$plist"
plutil -replace CFBundleShortVersionString -string "$version" "$plist"
plutil -replace CFBundleVersion -string "$build" "$plist"
plutil -lint "$plist"
if grep -q "__HR_" "$plist"; then
  echo "Info.plist still contains a placeholder" >&2
  exit 1
fi
printf 'APPL????' > "$app/Contents/PkgInfo"

iconset="$work/AppIcon.iconset"
mkdir -p "$iconset"
for size in 16 32 128 256 512; do
  double=$((size * 2))
  sips -z "$size" "$size" "$resources/AppIcon.png" --out "$iconset/icon_${size}x${size}.png" >/dev/null
  sips -z "$double" "$double" "$resources/AppIcon.png" --out "$iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$iconset" -o "$app/Contents/Resources/AppIcon.icns"

# Extended attributes (Finder info, quarantine) make codesign fail.
xattr -cr "$app"

# ------------------------------------------------------------------ sign
echo "==> Signing (hardened runtime, $sign_label)"
codesign --force --options runtime --timestamp=none --entitlements "$entitlements" \
  --identifier org.heartfulness.remote.host.agent --sign "$identity" "$app/Contents/MacOS/hr-agent"
codesign --force --options runtime --timestamp=none --entitlements "$entitlements" \
  --sign "$identity" "$app"

echo "==> Verifying signatures"
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/hr-agent"
codesign --verify --deep --strict --verbose=2 "$app"
codesign --display --verbose=2 "$app" 2>&1 | grep -E "^(Identifier|Format|CodeDirectory|Signature|Authority|TeamIdentifier|Runtime)" | sed 's/^/    /' || true
codesign --display --verbose=2 "$app/Contents/MacOS/hr-agent" 2>&1 | grep -E "^(Identifier|CodeDirectory)" | sed 's/^/    /' || true

# ------------------------------------------------------------------- zip
echo "==> Packaging"
mkdir -p "$out"
stage="$work/stage/Heartfulness Remote"
mkdir -p "$stage"
ditto "$app" "$stage/Heartfulness Remote.app"
cp "$resources/README-FIRST.txt" "$stage/README-FIRST.txt"
zip="$out/Heartfulness-Remote-Mac.zip"
rm -f "$zip"
ditto -c -k --keepParent "$stage" "$zip"

# The plain app next to the zip (scripts/install-mac.sh installs it from here).
rm -rf "$out/Heartfulness Remote.app"
ditto "$app" "$out/Heartfulness Remote.app"

# The copy users get must still verify after zipping and unzipping.
check="$work/check"
mkdir -p "$check"
ditto -x -k "$zip" "$check"
codesign --verify --deep --strict "$check/Heartfulness Remote/Heartfulness Remote.app"
[ -f "$check/Heartfulness Remote/README-FIRST.txt" ] || { echo "README-FIRST.txt missing from the zip" >&2; exit 1; }

echo "==> Done"
ls -la "$out"
shasum -a 256 "$zip"
