# Heartfulness Remote — Security

Status: **draft, checklist results filled in at the end of the build.**
Normative protocol: [docs/PROTOCOL.md](docs/PROTOCOL.md).

## 1. What we protect

| Asset | Why it matters |
|---|---|
| Control of the Mac (input, screen, audio, clipboard, files) | Full account takeover of the owner's work machine |
| Host key `H` (Mac) | Whoever holds it can impersonate the Mac to clients |
| Device keys `D` (each approved browser / app / phone) | Whoever holds one can request sessions as that device |
| Owner passkeys | Gate access to the signaling server |
| Server state (device registry, sessions) | Availability; minimal metadata about usage |

## 2. Trust model in one paragraph

The **Mac is the root of trust**. It keeps the list of pinned device keys and
will only start a session after verifying a signature from a pinned key over
the WebRTC offer (which contains the client's DTLS fingerprint), and it signs
its answer (containing its own DTLS fingerprint) with its host key, which
every client pinned when it was approved. The signaling server, DNS, the
TURN relay and the network are therefore **untrusted for confidentiality and
integrity of sessions**: they can block or delay, but cannot read, alter or
impersonate. Passkeys decide who may *talk to* the server; device approval
(on the Mac or from an already-approved phone, with a 6-digit code
comparison) decides who may *control the Mac*.

## 3. Adversaries and outcomes

| Adversary | Can | Cannot |
|---|---|---|
| Network attacker (Wi-Fi, ISP, hotel) | See that you use the service, traffic volume, timing | Read/alter media, input, files (DTLS-SRTP/SCTP, TLS 1.3 to the server) |
| Compromised TURN relay | Drop/delay packets, see packet sizes | Decrypt (end-to-end DTLS) |
| **Compromised signaling server / DNS** | Deny service; refuse logins; see metadata; **serve modified JavaScript to browsers** (see §4) | Add a device (needs the Mac's signature), MITM a session (fingerprints signed by pinned keys), read media |
| Stolen phone / laptop that is an approved device | Request sessions *if* also signed in with a passkey and the device unlocks | Stay unnoticed: every session shows a notification + banner on the Mac; owner can revoke the device from the Mac or another device, or hit the kill switch |
| Phished owner | Approving an attacker's device requires the owner to approve a request **and** ignore a mismatching 6-digit code | |
| Malware running as the Mac user | Everything the user can do (out of scope: a remote-desktop tool cannot defend against local compromise). The access log is tamper-*evident*, not tamper-proof | |
| Someone racing the first-time setup | Claim an unconfigured server (denial of service only) | Reach the Mac: the real Mac and phone pin each other via the QR code |

## 4. Known residual risks (accepted, documented)

1. **Browser clients trust the server for code delivery.** A web page's
   JavaScript comes from the server; a compromised server could serve a
   modified client that uses an already-approved browser's (non-extractable)
   key to start a session. Mitigations: the Mac shows a notification and a
   banner for every session and logs it; "Allow browser clients" can be
   switched off on the Mac, leaving only the native apps, whose code is
   bundled and signed at build time. This limitation applies to every
   web-based end-to-end-encrypted product.
2. **Self-signed Mac app** (no Apple Developer ID): Gatekeeper doesn't vouch
   for it; integrity relies on building it yourself from this repository.
3. **ICE sockets**: during an approved session the Mac opens ephemeral UDP
   sockets for WebRTC connectivity checks (standard WebRTC). No listening TCP
   service exists, nothing listens when no session is active, and
   "Relay only" mode removes direct inbound paths entirely.
4. **Metadata on the server**: login times, device names, session start/end
   and IP addresses are kept for 7 days for abuse handling, then deleted.
5. **Free DNS provider** (deSEC/DuckDNS): can redirect the name; impact equals
   a compromised server (item 1).

## 5. Controls checklist

(✅ = implemented and covered by an automated test; 🟡 = implemented, manual
verification; ⬜ = pending.) Filled in at the end of the build.

## 6. Needs an outside security review

Filled in at the end of the build.
