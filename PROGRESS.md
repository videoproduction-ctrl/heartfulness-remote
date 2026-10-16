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

## WAITING ON OWNER
1. Create empty private GitHub repo `heartfulness-remote`
2. Xcode installed on the Mac
3. VPS (Hetzner CX22 or DigitalOcean Bangalore) with SSH key `~/.ssh/heartfulness_vps`
4. Free address from desec.io (dedyn.io) or duckdns.org → A record to VPS IP
5. Apple Developer account? (optional; default = sign for own Mac only)

## HOW TO RUN (dev)
- Protocol tests: `cd proto && go test ./...`
- (more added as components land)
