# PROGRESS

_Last updated: 2026-10-16 (session 1, cloud container)_

## DONE
- Brief (CLAUDE.md), protocol (docs/PROTOCOL.md), architecture, SECURITY.md (threat model,
  checklist with evidence, outside-review list), USER-GUIDE.md, TEST-REPORT.md
- `proto/` shared crypto helpers + `testdata/vectors.json` (Go, TS, Rust and Swift test against them)
- `server/` Go signaling/auth server — tests pass (`-race`); go-webauthn v0.18.2
- `agent/` Go host agent (pion WebRTC, pairing, trust store, access log, files) + `hostsim`
- `web/` browser client — 57 unit tests
- `mac/` Swift app (menu bar, dashboard, wizard, capture/encode/input, banner, kill switch) —
  89 tests, compiled + signed (ad-hoc, hardened runtime) by CI on macOS 15
- `tauri/` native client — 27 Rust tests; CI builds macOS dmg + Windows msi/exe
- `deploy/` cloud-init + provision + compose (caddy 2.11.7, coturn 4.18.0) — verified end to end
  on a simulated Ubuntu 24.04 VPS; `scripts/test-deploy.sh` runs in CI
- `e2e/` — 14 tests pass: 10 owner journeys + 4 hostile-server attack tests
- CI fully green on GitHub (go, web, docker, e2e, mac-host, tauri mac+win, security)
- Release v0.1.0 published from the `release` branch (see "Releasing")

## NEXT (needs the owner)
1. Owner: free name at **duckdns.org** (sign in with GitHub, add `heartfulness-remote`)
2. Owner: create the Hetzner server with `deploy/cloud-init.yaml` (one line edited), then set the
   DuckDNS IP → verify `https://<name>/healthz`
3. Owner: download `Heartfulness-Remote-Mac.zip` from the latest Release, open, follow the wizard,
   scan the QR with the phone
4. Then: first real-Mac check of the 🟡 items in SECURITY.md §5 (banner, permissions, Secure
   Enclave, firewall) and fix anything that shows up

## WAITING ON OWNER
- duckdns.org name (step 1 above)

## LIVE BUILD PAGE (for the owner)
https://claude.ai/artifact/Tyop7rATmbLh99gLStXMjs — private page; Claude updates it with the
ArtifactData tool: `board/status` (headline, needs[], note, updatedAt), `steps/sNN`
(order, title, detail, state done|active|todo|waiting|failed), `board/log` (entries[]),
`shots/pNN` (order, title, caption, url from an asset upload). Source: e2e/demo/out/live-build.html
(git-ignored; republish with the Artifact tool and that file path or the URL).

## RELEASING (this cloud session can push branches, but not tags or workflow dispatches)
1. bump `VERSION` (x.y.z) on main, push, wait for CI green
2. `git push origin main:release` → `.github/workflows/release.yml` builds everything,
   tags `v<VERSION>` and publishes the GitHub Release with the 4 installers + SHA256SUMS.txt

## HOW TO RUN (dev, Linux or Mac)
```
go test -race ./proto/... ./server/... ./agent/...
cd web && npm ci && npm run typecheck && npm test && npm run build
cd tauri/src-tauri && cargo test -p hr-client-core
scripts/e2e.sh                       # E2E_VIDEO=1 records browser videos
cd e2e && node demo/walkthrough.ts && python3 demo/compose.py   # captioned demo video
# by hand:
go build -o /tmp/hrs ./server/cmd/heartfulness-server
HR_ORIGIN=http://localhost:8080 HR_LISTEN=127.0.0.1:8080 HR_DATA_DIR=/tmp/hrdata \
  HR_TURN_SECRET=dev-secret-0123456789 HR_WEB_DIR=$PWD/web/dist HR_DEV=1 /tmp/hrs serve
go run ./agent/cmd/hostsim --server http://localhost:8080 --data /tmp/hrhost \
  --video agent/testdata/test.ivf --state-file /tmp/hrhost/state.json
# open the setupURL from /tmp/hrhost/state.json in a browser
```
Mac app (on a Mac): `scripts/build-mac.sh --sign adhoc --out dist` (or `scripts/install-mac.sh`).
Server over SSH (secondary path): `scripts/deploy-server.sh <ip> <name.duckdns.org>`.

## CI feedback (from a cloud session without API log access)
`git fetch origin '+refs/heads/ci-results/*:refs/remotes/origin/ci-results/*'` then
`git show origin/ci-results/<job>:status.txt` / `:errors.txt` / `:job.log`.
`gh api repos/videoproduction-ctrl/heartfulness-remote/actions/runs` works for status.
