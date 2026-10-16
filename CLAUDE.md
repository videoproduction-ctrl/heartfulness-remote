# Heartfulness Remote — project brief (keep this file; future sessions start here)

> Read this brief, then read PROGRESS.md (done / next / how to run) and continue
> from "NEXT". The owner may simply type "continue".

---

## Original brief (verbatim from the owner)

Build my complete product end to end. Work autonomously and don't stop for my
approval between steps. Only pause when you truly need me (see "THINGS ONLY I
CAN DO"), and when you do, put every request into one clear checklist.

SETUP
Create ~/Projects/heartfulness-remote, run git init, and first save this whole
brief there as CLAUDE.md so future sessions keep the plan. Keep PROGRESS.md
updated (done / next / how to run) so that if a session ends I can type "continue".

GOAL
"Heartfulness Remote": my own secure remote-desktop system to fully control my
Mac (screen, audio, mouse, keyboard, clipboard, files) from anywhere. No
third-party remote-access apps or services. Use well-audited open-source
libraries only; never write custom cryptography.

BUILD
1. Mac host app: Swift/SwiftUI, macOS 14+, menu bar + dashboard window.
   ScreenCaptureKit (screen + system audio), VideoToolbox H.264/HEVC encoding
   smooth enough for video editing, CGEvent mouse/keyboard, clipboard sync,
   file transfer. Outbound connections only; no listening ports on the Mac.
   Setup wizard for Screen Recording + Accessibility. Launch at login.
2. Server: Docker on a Linux VPS with signaling + coturn relay, HTTPS via
   Let's Encrypt, also hosting the browser client. Write and run the
   deployment yourself over SSH.
3. Browser client: works on any OS with nothing to install. Full-screen view,
   keyboard shortcuts, file transfer, latency indicator.
4. Native clients: Tauri app for macOS and Windows (build Windows with GitHub
   Actions). Same login and features as the browser client.

SECURITY (non-negotiable)
- WebRTC end-to-end encryption (DTLS-SRTP). Bind DTLS fingerprints to pinned
  Ed25519 device keys so even my own server can't intercept or impersonate.
- Passkey (WebAuthn) login only, no passwords. Every new browser/device must be
  approved from my phone or on the Mac before it can connect.
- Private keys in Keychain / Secure Enclave. Never log secrets.
- Rate limiting + lockout on all endpoints. Strict Content-Security-Policy.
  No third-party scripts, CDNs, analytics or telemetry anywhere.
- On the Mac: notification + visible "being controlled" banner every session,
  one-click kill switch, idle timeout, local tamper-evident access log.
- Server stores no screen data; minimal metadata, auto-deleted after 7 days.
- macOS firewall + stealth mode on. Hardened Runtime.
- Never commit secrets; use a git-ignored .env and the Keychain.

QUALITY
- Build and run everything yourself, write automated tests, and fix all failures
  before moving on. Get it working on my local network first, then over the internet.
- At the end, write SECURITY.md (threat model + checklist), run every check,
  fix what fails, and list what still needs an outside security review.

THINGS ONLY I CAN DO (ask for all of these at the start, so I can do them in
one sitting while you build the local version)
- Install Xcode if it's missing (check first).
- Rent a VPS and buy a domain: recommend cheap, reliable options and give me
  exact steps to point the domain at the server and give you SSH key access.
- Click Allow on macOS permission prompts.
- Create my passkey and approve my first devices.
- A GitHub account (for the Windows build). An Apple Developer account is
  optional; if I don't have one, sign the app for my own Mac only.
Never ask me to paste passwords or card details into chat.

END PRODUCT (when finished, give me)
- Heartfulness Remote.app in ~/Applications, running in the menu bar
- My web address for connecting from any browser
- Mac and Windows client installers in ~/Projects/heartfulness-remote/dist
- USER-GUIDE.md in plain language (I'm a media producer, not a developer): how
  to connect, add/remove devices, use the kill switch, and fix "offline"
- A short report of what was tested and what's left for an outside review

DESIGN
Clean Apple-native look, SF Symbols, light/dark mode, big clear status:
Online / Offline / Someone connected.

(Owner follow-up: "choose the best model for the task.")

---

## Notes for future sessions (added by Claude, keep short)

- The first session ran in a **cloud Linux container** (not on the Mac). It
  builds and tests the server, the Go host agent, the web client and the
  Tauri wrapper, and writes the Swift app, which CI compiles on macOS runners.
  Steps that must happen **on the Mac** (Xcode build, install to
  ~/Applications, permissions, firewall, SSH deploy to the VPS) are scripted
  in `scripts/` and listed in PROGRESS.md under "Mac-side steps".
- GitHub: https://github.com/videoproduction-ctrl/heartfulness-remote (public).
  Releases: bump `VERSION`, then `git push origin main:release` (see PROGRESS.md).
- Architecture and wire protocol: `docs/ARCHITECTURE.md`, `docs/PROTOCOL.md`.
  Any change to signatures/messages must update PROTOCOL.md and the
  cross-language test vectors in `testdata/vectors.json`.
- Never commit secrets. `.env`, `*.key`, `*.pem`, `secrets/` are git-ignored.
- **Owner preference (2026-10-16): "I just need the software to see at the end —
  make it possible."** The owner is non-technical. Prefer zero-Terminal paths:
  CI-built app downloaded from GitHub Releases (no Xcode needed), server via a
  pasted cloud-init file (no SSH keys needed), free deSEC/DuckDNS address (no
  paid domain — owner declined to pay for one). Keep owner steps minimal and
  batch them into one checklist.
- This cloud container cannot SSH or reach most hosts; CI feedback comes back
  through `ci-results/<job>` branches (git fetch), not the GitHub API.
