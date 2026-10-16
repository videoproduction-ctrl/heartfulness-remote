# PROGRESS

_Last updated: 2026-10-16 (session 1, cloud container)_

## DONE
- Brief (CLAUDE.md), protocol (docs/PROTOCOL.md), architecture, threat-model draft (SECURITY.md)
- `proto/` shared crypto helpers + `testdata/vectors.json` (Go, TS and Rust all test against them)
- `server/` Go signaling/auth server — unit + integration tests pass (`-race`)
- `agent/` Go host agent (pion WebRTC, pairing, trust store, access log, files) + `hostsim` — tests pass (`-race`)
- `web/` browser client — 57 unit tests, typecheck, build pass
- `tauri/` native client — 27 Rust tests; CI builds macOS + Windows installers successfully
- `e2e/` Playwright end-to-end suite — **9/9 journeys pass** (setup via QR link, pairing approved
  from phone and from Mac with matching codes, deny, full session with video/latency/input/
  clipboard/upload/download, kill switch on Mac and from phone, revocation, access log)
- CI on GitHub (go, web, docker, e2e, mac-host, tauri mac+win, security) + release workflow
- Go moved to a supported version (go 1.26 language, toolchain go1.27.2)
- GitHub repo: https://github.com/videoproduction-ctrl/heartfulness-remote (public)

## IN PROGRESS
- `mac/` Swift app: UI (menu bar, dashboard, wizard) + build scripts being finished; compiled by CI
- `deploy/`: cloud-init/provision/compose being verified with Docker; `scripts/deploy-server.sh`

## NEXT
1. Get CI fully green (mac-host Swift compile, govulncheck, e2e in CI)
2. Tag `v0.1.0` → GitHub Release with the Mac app zip + client installers
3. Owner creates the server (cloud-init) → verify https://<name>/healthz → owner installs Mac app
4. SECURITY.md checklist + run every check; USER-GUIDE.md; final report

## WAITING ON OWNER (no Terminal, no Xcode, no SSH keys)
1. ~~GitHub repo~~ ✅ done (public)
2. Free name at **duckdns.org** (sign in with GitHub, add `heartfulness-remote`) — deSEC's free
   dynDNS signup is currently unavailable
3. VPS (Hetzner CX22, Ubuntu 24.04) created with `deploy/cloud-init.yaml` pasted into
   "Cloud config / User data" (edit the one line with the DuckDNS name); then set the
   DuckDNS IP to the server's IP
4. Download the Mac app from GitHub Releases, open it, follow the setup wizard

## HOW TO RUN (dev, Linux or Mac)
```
# all Go tests
go test -race ./proto/... ./server/... ./agent/...
# web client
cd web && npm ci && npm run typecheck && npm test && npm run build
# Tauri core
cd tauri/src-tauri && cargo test -p hr-client-core
# end-to-end (server + host simulator + Chromium with virtual passkeys)
scripts/e2e.sh                # E2E_VIDEO=1 records browser videos
# run locally by hand
go build -o /tmp/hrs ./server/cmd/heartfulness-server
HR_ORIGIN=http://localhost:8080 HR_LISTEN=127.0.0.1:8080 HR_DATA_DIR=/tmp/hrdata \
  HR_TURN_SECRET=dev HR_WEB_DIR=$PWD/web/dist HR_DEV=1 /tmp/hrs serve
go run ./agent/cmd/hostsim --server http://localhost:8080 --data /tmp/hrhost \
  --video agent/testdata/test.ivf --state-file /tmp/hrhost/state.json
# open the setupURL from state.json in a browser
```

## CI feedback (from a cloud session without API log access)
`git fetch origin 'refs/heads/ci-results/*:refs/remotes/origin/ci-results/*'` then
`git show origin/ci-results/<job>:status.txt` / `:errors.txt` / `:job.log`.
The GitHub API (`gh api repos/videoproduction-ctrl/heartfulness-remote/actions/...`) also works
for run/job status; raw job logs are on a blocked host.
