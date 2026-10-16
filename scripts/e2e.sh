#!/usr/bin/env bash
# End-to-end tests: real server + host agent core (hostsim) + Chromium with
# virtual passkeys. Usage: scripts/e2e.sh [playwright args…]
#   E2E_VIDEO=1 scripts/e2e.sh   # also record browser videos into e2e/test-results
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$PWD

if [ ! -f web/dist/index.html ]; then
  echo "• building web client"
  (cd web && npm ci --ignore-scripts --no-audit --no-fund && npm run build)
fi

echo "• building server and host simulator"
mkdir -p e2e/.bin
go build -o e2e/.bin/heartfulness-server ./server/cmd/heartfulness-server
go build -o e2e/.bin/hostsim ./agent/cmd/hostsim

echo "• installing Playwright"
cd e2e
npm ci --no-audit --no-fund
if [ -z "${PLAYWRIGHT_BROWSERS_PATH:-}" ] || [ ! -d "${PLAYWRIGHT_BROWSERS_PATH}" ]; then
  npx playwright install --with-deps chromium
fi

echo "• running end-to-end tests"
npx playwright test "$@"
echo "• e2e passed (report: $ROOT/e2e/playwright-report/index.html)"
