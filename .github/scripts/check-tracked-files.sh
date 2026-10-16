#!/usr/bin/env bash
# Fails if files that must never be committed are tracked by git
# (mirrors the "Secrets" section of .gitignore).
set -euo pipefail

bad="$(git ls-files -z | tr '\0' '\n' | grep -E \
  -e '(^|/)\.env$' \
  -e '(^|/)\.env\.[^/]*$' \
  -e '\.(key|pem|p12|p8|pfx|keystore|jks|mobileprovision)$' \
  -e '(^|/)secrets/' \
  -e '(^|/)id_(rsa|ecdsa|ed25519)$' \
  | grep -vE '(^|/)\.env\.example$' || true)"

if [ -n "$bad" ]; then
  echo "::error::secret-like files are tracked by git:"
  echo "$bad"
  exit 1
fi
echo "no secret-like files tracked ($(git ls-files | wc -l | tr -d ' ') files checked)"
