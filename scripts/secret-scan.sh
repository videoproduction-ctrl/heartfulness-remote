#!/usr/bin/env bash
# Quick pre-commit secret scan of staged files (CI runs gitleaks as well).
set -euo pipefail
pattern='(-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|AKIA[0-9A-Z]{16}|xox[baprs]-[0-9A-Za-z-]{10,})'
files=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$files" ] && exit 0
if echo "$files" | xargs grep -n -I -E "$pattern" 2>/dev/null; then
  echo "secret-scan: possible secret in staged files (see above)" >&2
  exit 1
fi
echo "secret-scan: clean"
