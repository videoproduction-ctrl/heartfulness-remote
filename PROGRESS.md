# PROGRESS

_Last updated: 2026-10-16 (session 1, cloud container)_

## DONE
- Project folder, git init, CLAUDE.md (brief), .gitignore
- docs/PROTOCOL.md (normative security protocol), docs/ARCHITECTURE.md
- `proto/` Go package + `testdata/vectors.json` (tests pass)

## IN PROGRESS
- server/ (Go), agent/ (Go + pion), web/ (TS), mac/ (Swift), tauri/ + CI

## NEXT
- Integrate, end-to-end tests (Playwright + virtual passkey + host simulator)
- Push to GitHub (waiting for owner to create `videoproduction-ctrl/heartfulness-remote`)
- CI builds Mac app + Tauri Mac/Windows installers
- Deploy to VPS (waiting for owner: VPS IP + free deSEC/DuckDNS address)
- SECURITY.md, USER-GUIDE.md, final report

## WAITING ON OWNER (simplified — no Terminal, no Xcode, no SSH keys)
1. Create empty **public** GitHub repo `videoproduction-ctrl/heartfulness-remote`
   (no secrets in it; public lets the server and Mac install with no keys) and
   give the Claude GitHub app access to it
2. Free address from desec.io (dedyn.io) or duckdns.org
3. VPS (Hetzner CX22 / DigitalOcean) created with `deploy/cloud-init.yaml`
   pasted into "User data" (edit one line: the address); then A record → VPS IP
4. Later: download Mac app from GitHub Releases, open, follow the wizard

## HOW TO RUN (dev)
- Protocol tests: `cd proto && go test ./...`
- (more added as components land)
