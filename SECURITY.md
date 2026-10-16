# Heartfulness Remote — Security

Version 0.1.0 · Normative protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md) ·
Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## 1. What we protect

| Asset | Why it matters |
|---|---|
| Control of the Mac (input, screen, audio, clipboard, files) | Full takeover of the owner's work machine |
| Host key `H` (Mac) | Whoever holds it can impersonate the Mac to clients |
| Device keys `D` (each approved browser / app / phone) | Whoever holds one can request sessions as that device |
| Owner passkeys | Gate access to the signaling server |
| Server state (device registry, sessions) | Availability; minimal metadata about usage |

## 2. Trust model in one paragraph

The **Mac is the root of trust**. It keeps the list of pinned device keys and
starts a session only after verifying a signature, by a pinned key, over the
WebRTC offer — which contains the client's DTLS fingerprint — and it signs its
own answer (containing its DTLS fingerprint) with its host key, which every
client pinned when it was approved. The signaling server, DNS, the TURN relay
and the network are therefore **untrusted for confidentiality and integrity
of sessions**: they can block or delay, but not read, alter or impersonate.
Passkeys decide who may *talk to* the server; device approval (on the Mac, or
from an already-approved phone, with a 6-digit commit-then-reveal code
comparison) decides who may *control the Mac*.

## 3. Adversaries and outcomes

| Adversary | Can | Cannot |
|---|---|---|
| Network attacker (Wi-Fi, ISP, hotel) | See that the service is used, traffic volume and timing | Read or alter media, input, clipboard, files (DTLS-SRTP / SCTP-over-DTLS; TLS 1.3 to the server) |
| Compromised TURN relay | Drop or delay packets, see packet sizes | Decrypt (end-to-end DTLS) |
| **Compromised signaling server or DNS** | Deny service; refuse logins; see metadata; **serve modified JavaScript to browsers** (§4.1) | Add a device (needs the Mac's signature); MITM a session (fingerprints signed by pinned keys — proven by attack tests A–C); read media |
| Stolen phone/laptop that is an approved device | Request sessions if it can also pass the passkey (device unlock) | Stay unnoticed: every session shows a notification + banner on the Mac and is logged; owner can revoke it or hit the kill switch |
| Phished owner | — | Approve an attacker's device without ignoring a mismatching 6-digit code |
| Someone racing first-time setup | Claim an unconfigured server (denial of service only) | Reach the Mac: the real Mac and phone pin each other through the QR code |
| Malware running as the Mac user | Everything the user can (out of scope for any remote-desktop tool); the access log is tamper-*evident*, not tamper-proof | — |

## 4. Known residual risks (accepted and documented)

1. **Browser clients trust the server for code delivery.** A web page's
   JavaScript comes from the server; a compromised server could serve a
   modified client that uses an already-approved browser's non-extractable key
   to start a session. Mitigations: notification + banner + access-log entry
   on the Mac for every session; "Allow browser clients" can be switched off
   on the Mac, leaving only the native apps, whose code is bundled at build
   time. This limitation applies to every web-based end-to-end-encrypted product.
2. **Ad-hoc / self-signed Mac app** (no Apple Developer ID): Gatekeeper doesn't
   vouch for it; integrity relies on the build coming from this repository's CI
   (or building it yourself). After each update macOS asks again for Screen
   Recording / Accessibility and Keychain access (the signature changes).
3. **ICE sockets:** during an approved session the Mac opens ephemeral UDP
   sockets for WebRTC connectivity checks. There is no listening TCP service,
   nothing is open when no session is active, and "Relay only" removes direct
   inbound paths entirely.
4. **Server metadata:** login times, device names, session start/end and IP
   addresses (for rate limiting and abuse handling) are kept for at most 7 days.
5. **Free DNS provider** (DuckDNS/deSEC) can redirect the name; impact equals a
   compromised server (item 1).
6. **Windows Credential Manager** is not per-application: another program
   running as the same Windows user can read the Tauri client's device key and
   token. (macOS Keychain items are bound to the app's code signature.)
7. **Secure Enclave wrapping** of the host key is attempted at runtime; on
   failure the app falls back to Keychain-only storage and shows which
   protection is active.

## 5. Controls checklist

✅ implemented **and** covered by an automated test (CI) · 🟡 implemented, needs
manual verification on a real Mac / VPS · ⬜ not done

### End-to-end encryption and key pinning
| Control | Status | Evidence |
|---|---|---|
| WebRTC DTLS-SRTP media + SCTP data channels only | ✅ | agent `TestWebRTCIntegration`; e2e journey 5 |
| Offer signed by pinned device key, answer by pinned host key, over session id + both nonces + SDP hashes | ✅ | proto vectors; agent `TestVerifyOffer`, `TestOfferRejectedAgent`; web `hr1.test.ts` |
| Exactly one sha-256 fingerprint per SDP | ✅ | proto `TestSDPFingerprint`; web tests |
| **Hostile server swapping the Mac's fingerprint → refused** | ✅ | e2e attack A |
| **Hostile server swapping the browser's fingerprint → refused by the Mac** | ✅ | e2e attack B |
| **Forged answer signature → refused** | ✅ | e2e attack C |
| Cross-language crypto agreement (Go, TypeScript, Rust, Swift) | ✅ | `testdata/vectors.json` checked by all four test suites |
| No custom cryptography (only Ed25519, SHA-256, HMAC, HKDF, WebAuthn, DTLS from platform libraries) | ✅ | code review; `proto/` composes stdlib only |

### Login and device approval
| Control | Status | Evidence |
|---|---|---|
| Passkey-only login (no passwords anywhere), user verification required | ✅ | server WebAuthn tests with a software authenticator; e2e journeys 1–4 (Chromium virtual authenticator) |
| Cloned-authenticator detection (signature counter going backwards → rejected) | ✅ | server `TestLoginRejectsCounterGoingBackwards` |
| First phone bootstrapped from the Mac's QR code; server learns only Kc, never Ka | ✅ | server `TestClaimChecks`; agent `TestSetupClaimFlow`; e2e journey 1 |
| Setup secret stripped from the address bar immediately; single use | ✅ | e2e journey 1 |
| New devices need approval on the Mac or an approved phone; 6-digit SAS with commit-then-reveal | ✅ | agent `TestPairingCommitAndSAS`, `TestPairingCommitMismatchAgentAndExpiry`; e2e journeys 2–4 |
| Pairing limits: 3 pending, 5-min expiry, auto-deny after 5 denials/hour | ✅ | agent `TestPairingLimits`, `TestPairingExpiry` |
| Revocation (Mac or approved phone, signed) takes effect immediately | ✅ | agent `TestKillAndRevokeRequestsSigned`; e2e journey 8 |
| Server cannot add a device (cert must be host-signed; Mac authoritative via trust-sync) | ✅ | server `TestPairingAndSessionRelay`, cert-rejection tests |
| Native app login via typed link code (no code in URLs) | ✅ | server `TestLinkFlow` |

### Server hardening
| Control | Status | Evidence |
|---|---|---|
| Rate limiting on every endpoint + IP lockout + global throttle | ✅ | `TestRateLimitAuthEndpoints`, `TestRateLimitGeneralAPI`, `TestRateLimitWSUpgrades`, `TestLockoutAfterFailures`, `TestGlobalThrottle` |
| Client IP only from the trusted proxy (spoofed X-Forwarded-For ignored) | ✅ | `TestClientIPFromTrustedProxyOnly`; manual stack test |
| Strict CSP with Trusted Types, HSTS, nosniff, COOP/CORP, Permissions-Policy on every response | ✅ | `TestSecurityHeadersEverywhere`, `TestPermissionsPolicy`; web `dist.test.ts` (no inline code) |
| CSRF (Origin + custom header + SameSite=Strict), CORS only for Tauri origins | ✅ | `TestCSRF`, `TestCORS`, `TestClientWSTauriOrigins` |
| No third-party scripts, CDNs, fonts, analytics or telemetry | ✅ | CI `check-no-cdn.sh`; zero runtime npm dependencies |
| Server stores no screen data; minimal metadata purged after 7 days | ✅ | `TestPurgeJob`, `TestPurge`; signaling never persists SDP |
| VPS logs (journald, rsyslog, fail2ban, containers) expire after 7 days | 🟡 | provision.sh; verified on a simulated Ubuntu 24.04 VPS, not yet on the real one |
| Container: distroless, non-root, read-only FS, all capabilities dropped, not published to the host | ✅ | CI docker job + `scripts/test-deploy.sh` |
| coturn: REST credentials, all private/reserved peers denied, quotas, current version (4.18.0) | ✅ | `scripts/test-deploy.sh` (CI) |
| Host firewall (ufw), SSH key-only, fail2ban, unattended upgrades | 🟡 | provision.sh; verified on the simulated VPS |

### Secrets
| Control | Status | Evidence |
|---|---|---|
| Never log secrets (setup secret, cookies, tokens, assertions, keys) | ✅ | e2e journey 10 scans all server + Mac-agent output; Tauri `errors_never_contain_the_seed` |
| Never commit secrets (.env git-ignored, secret scan of full history) | ✅ | CI gitleaks (full history) + `scripts/secret-scan.sh`; no secrets in repo |
| Server secrets generated on the VPS, never leave it | ✅ | provision.sh; deploy test checks the TURN secret reaches only the server |
| Mac host key + storage key in Keychain, Secure Enclave wrapping when available | 🟡 | `HostKeyStore.swift`; needs first run on a real Mac |
| Browser device key non-extractable (WebCrypto) in IndexedDB | ✅ | web platform tests |
| Tauri device key in OS keychain, signs only protocol transcripts with device labels | ✅ | Tauri core tests (27) |

### On the Mac
| Control | Status | Evidence |
|---|---|---|
| Notification + visible "being controlled" banner every session | 🟡 | `SessionBanner.swift`, `Notifier.swift`; EVENTs proven by agent tests; visual check on a real Mac |
| One-click kill switch (menu, banner, ⌃⌥⌘K, phone) | ✅ / 🟡 | agent + e2e journeys 6–7 prove the kill logic; Mac UI buttons need a real-Mac check |
| Idle timeout (default 30 min, warning 60 s before) | ✅ | agent `TestIdleTimeout` |
| Tamper-evident access log (hash chain + HMAC, truncation-evident) | ✅ | agent `TestEditDetected`, `TestDeleteDetected`, `TestReorderDetected`, `TestTruncateDetected`, …; e2e journey 9 |
| Trust store integrity (tampered pins → refuse everything) | ✅ | agent `TestTamperDetected`, `TestTamperedTrustStoreRefusesEverything` |
| Outbound connections only; no listening ports | ✅ / 🟡 | agent design (pipes to the app, outbound WSS); ICE sockets only during sessions (§4.3) |
| Downloads confined to the home folder; uploads sanitized, hash-verified | ✅ | agent `TestDownloadConfinement`, `TestDeviceFileRefused`, `TestSanitizeName`; e2e journey 5 |
| Hardened Runtime, no entitlement exceptions, not sandboxed (needed for input injection) | ✅ | CI mac-host: `codesign --options runtime`, verify --strict |
| macOS firewall + stealth mode on | 🟡 | setup wizard step (admin prompt); verify on the real Mac |
| Launch at login | 🟡 | `SMAppService.mainApp`; verify on the real Mac |

### Supply chain
| Control | Status | Evidence |
|---|---|---|
| Go vulnerability scan (govulncheck, reachable code) — clean | ✅ | CI security job (fixed GO-2026-5942 by upgrading x/net) |
| npm audit (runtime) — clean; zero runtime dependencies | ✅ | CI |
| cargo audit — no vulnerabilities (2 informational warnings in Linux-only GTK crates, not shipped on Mac/Windows) | ✅ | CI |
| GitHub Actions pinned to full commit SHAs; downloaded tools checksum-verified | ✅ | `.github/workflows/*.yml` |
| Supported toolchains (Go 1.27.2, Node 22, Rust stable, Xcode 16) | ✅ | go.work, CI |
| Container base images pinned by version (digest pinning) | 🟡 | tags pinned; digests not yet |

## 6. What still needs an outside security review

An independent reviewer (ideally someone experienced with WebRTC and
authentication protocols) should look at, in order of importance:

1. **The pairing protocol (PROTOCOL.md §4–§5)** — the commit-then-reveal SAS,
   the setup-key split (Kc/Ka), and the choice of a 6-digit SAS (10⁻⁶ per
   attempt, each attempt visible to the owner).
2. **Signature transcripts (§3)** — completeness of what is bound into the
   offer/answer signatures (replay, reflection, cross-session confusion).
3. **The browser code-delivery risk (§4.1)** and whether to add mitigations
   (e.g. require native clients, or per-session confirmation for browsers).
4. **The Mac app on real hardware** — Keychain/Secure Enclave behaviour with
   ad-hoc signing, TCC permission handling, banner always visible and not
   captured, CGEvent injection limits, behaviour at the login window.
5. **The Go host agent's data-channel handling** — input validation, file
   transfer paths (symlinks, TOCTOU), resource limits under a malicious but
   approved client.
6. **Server WebSocket routing** — authorization of every routed message type.
7. **Deployment** — a penetration test of the real VPS (TLS config, coturn
   relay abuse, firewall) after it is live.
8. **Dependency review** — pion, go-webauthn, coder/websocket, Tauri, keyring.

Fuzzing targets worth adding: IPC frame decoder, signaling message decoding,
SDP fingerprint parser, file-transfer framing.

## 7. Reporting a problem

Open a private security advisory on the GitHub repository, or tell Claude in a
new session ("continue" + describe the issue).
