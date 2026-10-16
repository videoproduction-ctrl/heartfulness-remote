# Test report — Heartfulness Remote 0.1.0

_2026-10-16. Everything below ran automatically, in this build session and on
GitHub's Linux, macOS 15 and Windows build machines. Nothing here ran on the
owner's own Mac yet._

## What was tested

| Area | How | Result |
|---|---|---|
| Crypto agreement across languages | Same test vectors checked in Go, TypeScript, Rust and Swift | ✅ all agree |
| Server (sign-in, approvals, relay, limits, headers, purge) | 49 Go test functions, race detector on | ✅ pass |
| Mac agent (WebRTC, pairing, trust list, access log, files, idle, kill) | 62 Go test functions incl. a real WebRTC session, race detector on | ✅ pass (a real upload race was found and fixed) |
| Mac app core (IPC, video packaging, key codes, signatures, wording) | 89 Swift tests on macOS 15 | ✅ pass |
| Mac app build | Universal (Apple Silicon + Intel), hardened runtime, signature verified | ✅ builds |
| Browser client | 57 unit tests + typecheck + CSP check of the built page | ✅ pass |
| Desktop clients (Tauri) | 27 Rust tests; installers built for macOS and Windows | ✅ pass / built |
| **Whole system, owner journeys** (real server + Mac agent + Chromium + virtual passkeys) | 10 end-to-end tests: phone setup from QR, passkey, approval from phone and from Mac with matching codes, deny, live session (video, latency, mouse, keyboard, clipboard, 300 KB upload, download), kill switch on Mac and from phone, device removal, access log, **no secrets in any log** | ✅ 10/10 |
| **Hostile server** | 4 end-to-end attack tests: server swaps the Mac's encryption fingerprint, swaps the browser's, forges the Mac's signature → all refused; clean connection still works | ✅ 4/4 |
| Server deployment | Paste-in setup run end to end on a simulated Ubuntu 24.04 server; firewall, SSH hardening, 7-day log expiry, TURN relay allow/deny rules; relay tests in CI | ✅ pass (a relay-blocking config bug was found and fixed) |
| Security scans | Secret scan of full git history, Go vulnerability scan (reachable code), npm audit, cargo audit, workflow lint | ✅ clean (one reachable Go library issue found and fixed by upgrading) |

The end-to-end tests use VP8 video from a simulator because the open-source
test browser has no H.264; the real Mac sends H.264/HEVC, which is covered by
the Go WebRTC test.

## Not tested yet (needs the real Mac / server)

- First run on your Mac: permissions prompts, screen capture, sound, mouse and
  keyboard control, the orange banner, the firewall step, launch at login,
  Secure Enclave key protection.
- Your real server: Let's Encrypt certificate, connecting over the internet,
  relay through coturn from a restrictive network.
- Windows and Mac desktop apps on real machines (they build; not yet clicked through).

## Left for an outside security review

See [SECURITY.md §6](SECURITY.md#6-what-still-needs-an-outside-security-review):
the pairing protocol and signature transcripts, the browser code-delivery risk,
the Mac app on real hardware, the agent's file and input handling, the
server's message routing, a penetration test of the live server, and a
dependency review.
