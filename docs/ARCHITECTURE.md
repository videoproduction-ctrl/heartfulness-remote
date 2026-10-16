# Architecture

```
 Phone / laptop browser            Tauri app (Mac / Windows)
 (web client, passkey,             (same web client bundled locally,
  WebCrypto device key)             device key in OS keychain)
            \                         /
             \  HTTPS + WSS (signaling only, no media)
              v                     v
     ┌──────────── VPS (Docker) ─────────────┐
     │ Caddy (Let's Encrypt, HTTP/2+3)       │
     │   └─> heartfulness-server (Go)        │  passkeys, device registry mirror,
     │         serves web client, /api, /ws  │  signaling relay, rate limits, 7-day purge
     │ coturn (TURN/STUN relay, UDP+TCP 3478)│  relays encrypted packets only
     └───────────────────────────────────────┘
              ^                     ^
              |  WSS (outbound)     |  DTLS-SRTP media + SCTP data channels
              |                     |  (direct P2P when possible, else via TURN)
     ┌──────────── Mac ─────────────────────────────────────────┐
     │ Heartfulness Remote.app (Swift/SwiftUI, menu bar)        │
     │   ScreenCaptureKit → VideoToolbox H.264/HEVC  ─┐         │
     │   system audio → Opus (AudioToolbox)          ─┤ IPC     │
     │   CGEvent input, NSPasteboard, Keychain key   ◄┤ (pipes) │
     │   banner, kill switch, notifications, wizard   │         │
     │ hr-agent (Go helper, bundled): pion WebRTC,  ◄─┘         │
     │   signaling client, trust store, access log, files       │
     └──────────────────────────────────────────────────────────┘
```

## Repository layout

| Path | What | Language |
|---|---|---|
| `proto/` | Normative protocol helpers shared by server & agent (TBS, SAS, setup keys, certs) | Go |
| `server/` | Signaling + auth server, embeds `web/dist` | Go |
| `agent/` | Host networking helper launched by the Mac app (WebRTC via pion) + `hostsim` simulator for tests | Go |
| `web/` | Browser client (no framework, no runtime deps), built with esbuild | TypeScript |
| `mac/` | Mac host app (SwiftPM; `HRCore` library is unit-tested) | Swift |
| `tauri/` | Native client wrapper (bundles `web/dist`), device key in OS keychain | Rust |
| `deploy/` | docker-compose (caddy, server, coturn), Caddyfile, coturn config, VPS provisioning | YAML/sh |
| `scripts/` | `install-mac.sh`, `deploy-server.sh`, `dev.sh`, test runners | sh |
| `e2e/` | Playwright end-to-end tests (server + hostsim + Chromium + virtual passkey) | TS |
| `testdata/vectors.json` | Cross-language crypto test vectors | JSON |

## Why these choices

* **pion (Go) for WebRTC on the Mac** instead of a prebuilt libwebrtc binary:
  pure Go, memory-safe, auditable, lets us feed VideoToolbox H.264/HEVC and
  Opus packets directly, gives full control of the DTLS certificate, and runs
  on Linux so the whole host stack can be tested in CI with a simulator.
* **Swift ⇄ Go over stdin/stdout pipes**: no sockets on the Mac at all apart
  from the outbound WSS and per-session ICE sockets.
* **Mac is the root of trust**: device keys are pinned on the Mac; the server
  cannot add a device because it cannot produce the Mac's signature.
* **Caddy** for automatic Let's Encrypt; **coturn** for relay; Go server is a
  single static binary in a distroless, read-only, non-root container.
* **No runtime JS dependencies** in the web client; strict CSP with Trusted
  Types; no CDNs, fonts, analytics or telemetry anywhere.
