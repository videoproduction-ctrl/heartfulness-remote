// One remote-desktop session (PROTOCOL.md §7.3, §8): session-request →
// session-accept → signed offer → answer verified with the PINNED host key
// and the fingerprint rule BEFORE setRemoteDescription → trickle ICE.

import type { Api } from "./api";
import { type Bytes, b64, randomBytes } from "./b64";
import { b64Field, ID_SIZE, NONCE_SIZE, ProtocolError, type SessionBinding, SIG_SIZE, signOffer, type Signer, verifyAnswer } from "./hr1";
import { aboutMac, iceMsg, offerMsg, sessionEndMsg, sessionRequestMsg } from "./messages";
import { type Msg, type Signal, waitFor } from "./signal";

export type EndKind = "user" | "host" | "network" | "security" | "rejected" | "error";
export type Stage = "requesting" | "negotiating" | "connecting" | "connected";

export interface SessionEvents {
  stage(s: Stage): void;
  track(stream: MediaStream, track: MediaStreamTrack): void;
  channelsOpen(): void;
  control(m: Record<string, unknown>): void;
  fileData(data: ArrayBuffer): void;
  end(kind: EndKind, reason: string): void;
}

export interface SessionDeps {
  signal: Signal;
  api: Api;
  signer: Signer;
  /** The PINNED key of the Mac to connect to (also its routing id, §10.3). */
  pinnedHost: Bytes;
  relayOnly?: boolean;
}

const ACCEPT_TIMEOUT_MS = 30_000;
const ANSWER_TIMEOUT_MS = 30_000;
const CONNECT_TIMEOUT_MS = 30_000;
const DISCONNECT_GRACE_MS = 10_000;
const MAX_CONTROL_MSG = 2 * 1024 * 1024;

export function rejectText(reason: unknown): string {
  switch (reason) {
    case "blocked":
      return "Connections are blocked on your Mac. Allow connections on the Home screen or on the Mac.";
    case "busy":
      return "Someone else is connected to your Mac right now.";
    case "not-trusted":
      return "Your Mac doesn't trust this device any more. It needs to be approved again.";
    case "browser-disabled":
      return "Your Mac only accepts the Heartfulness Remote app, not web browsers. You can change this in the settings on your Mac.";
    default:
      return "Your Mac couldn't start the session. Please try again.";
  }
}

/** Plain-language text for a "bye" / "session-end" reason (agent session.go, server hub.go). */
export function byeText(reason: unknown): string {
  switch (reason) {
    case "idle":
    case "idle-timeout":
      return "The session ended because it was idle for a while.";
    case "killed":
    case "kill":
    case "blocked":
      return "All connections were blocked on your Mac.";
    case "revoked":
    case "trust-reset":
      return "This device was removed from your Mac's trusted devices.";
    case "replaced":
      return "Another device took over the session.";
    case "quit":
    case "host-quit":
    case "shutdown":
    case "host-shutdown":
      return "Heartfulness Remote was closed on your Mac.";
    case "user":
    case "disconnect":
    case "host":
    case "host-disconnected":
      return "The session was ended on your Mac.";
    case "browser-disabled":
      return "Your Mac no longer accepts web browsers, only the Heartfulness Remote app. You can change this in the settings on your Mac.";
    case "host-offline":
    case "host-reconnected":
      return "Your Mac lost its connection to the server. It usually comes back within a minute — try Reconnect.";
    case "offer-rejected":
      return "Your Mac couldn't verify this device's security signature, so it refused the connection. Try again; if it keeps happening, remove this device and approve it again.";
    case "no-common-codec":
      return "This browser can't play your Mac's video format. Try a recent Chrome, Edge or Safari.";
    case "offer-timeout":
    case "connect-timeout":
    case "timeout":
      return "The connection took too long to set up. Please try again.";
    case "connection-failed":
    case "connection-closed":
      return "The connection to your Mac was lost.";
    default:
      return "The session ended.";
  }
}

function preferCodecs(t: RTCRtpTransceiver): void {
  try {
    const caps = typeof RTCRtpReceiver !== "undefined" && typeof RTCRtpReceiver.getCapabilities === "function" ? RTCRtpReceiver.getCapabilities("video") : null;
    if (!caps || typeof t.setCodecPreferences !== "function") return;
    const rank = (c: RTCRtpCodec): number => {
      const m = c.mimeType.toLowerCase();
      if (m === "video/h265" || m === "video/hevc") return 0;
      if (m === "video/h264") return 1;
      if (m === "video/rtx" || m === "video/red" || m === "video/ulpfec" || m === "video/flexfec-03") return 2;
      return 3;
    };
    t.setCodecPreferences([...caps.codecs].sort((a, b) => rank(a) - rank(b)));
  } catch {
    /* keep browser defaults */
  }
}

function sanitizeCandidate(v: unknown): RTCIceCandidateInit | null | undefined {
  if (v === null) return null;
  if (!v || typeof v !== "object") return undefined;
  const o = v as Record<string, unknown>;
  if (typeof o["candidate"] !== "string" || o["candidate"].length > 2048) return undefined;
  const c: RTCIceCandidateInit = { candidate: o["candidate"] };
  if (typeof o["sdpMid"] === "string" || o["sdpMid"] === null) c.sdpMid = o["sdpMid"] as string | null;
  if (typeof o["sdpMLineIndex"] === "number" || o["sdpMLineIndex"] === null) c.sdpMLineIndex = o["sdpMLineIndex"] as number | null;
  if (typeof o["usernameFragment"] === "string") c.usernameFragment = o["usernameFragment"];
  return c;
}

export class RemoteSession {
  readonly sessionId: Bytes = randomBytes(ID_SIZE);
  readonly sid = b64(this.sessionId);
  readonly hostPub: string;
  private readonly clientNonce: Bytes = randomBytes(NONCE_SIZE);
  pc: RTCPeerConnection | null = null;
  control: RTCDataChannel | null = null;
  input: RTCDataChannel | null = null;
  pointer: RTCDataChannel | null = null;
  file: RTCDataChannel | null = null;
  readonly stream = new MediaStream();
  ended = false;
  connected = false;
  private readonly abort = new AbortController();
  private offs: Array<() => void> = [];
  private offerSent = false;
  private localIce: Array<RTCIceCandidateInit | null> = [];
  private remoteSet = false;
  private remoteIce: Array<RTCIceCandidateInit | null> = [];
  private timers = new Set<ReturnType<typeof setTimeout>>();
  private disconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private openChannels = 0;

  constructor(
    private readonly deps: SessionDeps,
    private readonly ev: SessionEvents,
  ) {
    this.hostPub = b64(deps.pinnedHost);
  }

  /** Messages for this session: our sessionId, from our Mac. */
  private own = (m: Msg): boolean => m["sessionId"] === this.sid && aboutMac(m, this.hostPub);

  private timer(fn: () => void, ms: number): ReturnType<typeof setTimeout> {
    const t = setTimeout(() => {
      this.timers.delete(t);
      fn();
    }, ms);
    this.timers.add(t);
    return t;
  }

  async start(): Promise<void> {
    try {
      await this.run();
    } catch (e) {
      if (this.ended) return;
      if (e instanceof ProtocolError) {
        this.end("security", `Security check failed: ${e.message}. The connection was stopped to protect you.`, true);
      } else if (e instanceof Error && e.message === "timeout") {
        this.end("network", "Your Mac didn't answer in time. Make sure it's online and try again.", true);
      } else if (e instanceof Error && e.message === "aborted") {
        /* ended elsewhere */
      } else {
        this.end("error", e instanceof Error ? e.message : "The connection failed.", true);
      }
    }
  }

  private async run(): Promise<void> {
    const { signal: sig, signer } = this.deps;
    this.offs.push(
      sig.on("session-end", (m) => {
        if (this.own(m)) this.end("host", byeText(m["reason"]), false);
      }),
    );
    this.offs.push(
      sig.on("ice", (m) => {
        if (this.own(m)) void this.onRemoteIce(m["candidate"]);
      }),
    );
    this.offs.push(
      sig.onState((s) => {
        if (!this.connected && s !== "ready") this.end("network", "Lost the connection to the server.", false);
      }),
    );

    this.ev.stage("requesting");
    const turnP = this.deps.api.turn().catch(() => null);
    const req = sessionRequestMsg(this.hostPub, this.sid, signer.pub, this.clientNonce, !!this.deps.relayOnly);
    if (!sig.send(req)) throw new Error("Not connected to the server.");

    const acc = await waitFor(sig, ["session-accept", "session-reject"], this.own, ACCEPT_TIMEOUT_MS, this.abort.signal);
    if (acc.type === "session-reject") {
      this.end("rejected", rejectText(acc["reason"]), false);
      return;
    }
    const hostNonce = b64Field(acc, "hostNonce", NONCE_SIZE);
    const binding: SessionBinding = {
      sessionId: this.sessionId,
      hostPub: this.deps.pinnedHost,
      devicePub: signer.pub,
      clientNonce: this.clientNonce,
      hostNonce,
    };

    const turn = await turnP;
    if (this.ended) return;
    const iceServers = Array.isArray(turn?.iceServers) ? turn.iceServers : [];
    const pc = new RTCPeerConnection({
      iceServers,
      iceTransportPolicy: this.deps.relayOnly ? "relay" : "all",
      bundlePolicy: "max-bundle",
      rtcpMuxPolicy: "require",
    });
    this.pc = pc;

    const video = pc.addTransceiver("video", { direction: "recvonly" });
    pc.addTransceiver("audio", { direction: "recvonly" });
    preferCodecs(video);

    this.control = pc.createDataChannel("control", { ordered: true });
    this.input = pc.createDataChannel("input", { ordered: true });
    this.pointer = pc.createDataChannel("pointer", { ordered: false, maxRetransmits: 0 });
    this.file = pc.createDataChannel("file", { ordered: true });
    this.file.binaryType = "arraybuffer";
    for (const ch of [this.control, this.input, this.pointer, this.file]) {
      ch.addEventListener("open", () => {
        this.openChannels++;
        if (this.openChannels === 4) this.ev.channelsOpen();
      });
    }
    this.control.addEventListener("message", (e: MessageEvent) => {
      if (typeof e.data !== "string" || e.data.length > MAX_CONTROL_MSG) return;
      try {
        const m: unknown = JSON.parse(e.data);
        if (m && typeof m === "object" && typeof (m as Record<string, unknown>)["t"] === "string") this.ev.control(m as Record<string, unknown>);
      } catch {
        /* ignore malformed */
      }
    });
    this.control.addEventListener("close", () => {
      if (this.connected) this.end("host", "The session ended.", false);
    });
    this.file.addEventListener("message", (e: MessageEvent) => {
      if (e.data instanceof ArrayBuffer) this.ev.fileData(e.data);
    });

    pc.onicecandidate = (e) => {
      const c = e.candidate ? e.candidate.toJSON() : null;
      if (this.offerSent) this.sendIce(c);
      else this.localIce.push(c);
    };
    pc.ontrack = (e) => {
      if (!this.stream.getTracks().includes(e.track)) this.stream.addTrack(e.track);
      this.ev.track(this.stream, e.track);
    };
    pc.onconnectionstatechange = () => this.onConnState();

    this.ev.stage("negotiating");
    const offer = await pc.createOffer();
    const offerSdp = offer.sdp ?? "";
    await pc.setLocalDescription(offer);
    // Sign exactly the SDP string we send.
    const offerSig = await signOffer(signer, binding, offerSdp);
    if (this.ended) return;
    if (!sig.send(offerMsg(this.hostPub, this.sid, offerSdp, offerSig))) throw new Error("Not connected to the server.");
    this.offerSent = true;
    for (const c of this.localIce.splice(0)) this.sendIce(c);

    const ans = await waitFor(sig, ["answer"], this.own, ANSWER_TIMEOUT_MS, this.abort.signal);
    const answerSdp = ans["sdp"];
    if (typeof answerSdp !== "string" || answerSdp.length > 200_000) throw new ProtocolError("malformed answer");
    const answerSig = b64Field(ans, "sig", SIG_SIZE);
    // MUST happen before setRemoteDescription: pinned host key + fingerprint rule.
    await verifyAnswer(binding, offerSdp, answerSdp, answerSig);
    if (this.ended) return;
    // Announce "connecting" BEFORE applying the answer: on a fast (LAN) link ICE
    // and DTLS can complete while we are still awaiting below, and a late
    // "connecting" would otherwise cover a session that is already live.
    this.ev.stage("connecting");
    await pc.setRemoteDescription({ type: "answer", sdp: answerSdp });
    this.remoteSet = true;
    for (const c of this.remoteIce.splice(0)) await this.addRemoteIce(c);
    if (this.ended || this.connected) return;
    this.timer(() => {
      if (!this.connected) this.end("network", "Couldn't establish a connection to your Mac. A firewall may be blocking it — try again, or check your network.", true);
    }, CONNECT_TIMEOUT_MS);
  }

  private sendIce(c: RTCIceCandidateInit | null): void {
    this.deps.signal.send(iceMsg(this.hostPub, this.sid, c));
  }

  private async onRemoteIce(raw: unknown): Promise<void> {
    const c = sanitizeCandidate(raw);
    if (c === undefined) return;
    if (!this.remoteSet) this.remoteIce.push(c);
    else await this.addRemoteIce(c);
  }

  private async addRemoteIce(c: RTCIceCandidateInit | null): Promise<void> {
    const pc = this.pc;
    if (!pc || this.ended) return;
    try {
      if (c === null || c.candidate === "") await pc.addIceCandidate();
      else await pc.addIceCandidate(c);
    } catch {
      /* a bad candidate is not fatal */
    }
  }

  private onConnState(): void {
    const pc = this.pc;
    if (!pc || this.ended) return;
    switch (pc.connectionState) {
      case "connected":
        if (this.disconnectTimer) {
          clearTimeout(this.disconnectTimer);
          this.timers.delete(this.disconnectTimer);
          this.disconnectTimer = null;
        }
        if (!this.connected) {
          this.connected = true;
          this.ev.stage("connected");
        }
        break;
      case "disconnected":
        if (!this.disconnectTimer) {
          this.disconnectTimer = this.timer(() => {
            this.disconnectTimer = null;
            if (this.pc?.connectionState !== "connected") this.end("network", "The connection to your Mac was lost.", true);
          }, DISCONNECT_GRACE_MS);
        }
        break;
      case "failed":
        this.end("network", this.connected ? "The connection to your Mac was lost." : "Couldn't connect to your Mac.", true);
        break;
      case "closed":
        this.end("network", "The connection closed.", false);
        break;
      default:
        break;
    }
  }

  private sendJSON(ch: RTCDataChannel | null, m: Record<string, unknown>): boolean {
    if (!ch || ch.readyState !== "open" || this.ended) return false;
    try {
      ch.send(JSON.stringify(m));
      return true;
    } catch {
      return false;
    }
  }

  sendControl(m: Record<string, unknown>): boolean {
    return this.sendJSON(this.control, m);
  }

  sendInput(m: Record<string, unknown>): boolean {
    return this.sendJSON(this.input, m);
  }

  sendPointer(m: Record<string, unknown>): boolean {
    return this.sendJSON(this.pointer, m);
  }

  async getStats(): Promise<RTCStatsReport | null> {
    if (!this.pc || this.ended) return null;
    try {
      return await this.pc.getStats();
    } catch {
      return null;
    }
  }

  /** Ends the session. `notify` tells the Mac (via the server) that we're leaving. */
  end(kind: EndKind, reason: string, notify = true): void {
    if (this.ended) return;
    this.ended = true;
    this.abort.abort();
    if (notify && this.deps.signal.isReady) {
      this.deps.signal.send(sessionEndMsg(this.hostPub, this.sid, kind === "user" ? "user" : kind));
    }
    for (const off of this.offs.splice(0)) off();
    for (const t of this.timers) clearTimeout(t);
    this.timers.clear();
    for (const ch of [this.control, this.input, this.pointer, this.file]) {
      try {
        ch?.close();
      } catch {
        /* ignore */
      }
    }
    if (this.pc) {
      this.pc.onicecandidate = null;
      this.pc.ontrack = null;
      this.pc.onconnectionstatechange = null;
      try {
        this.pc.close();
      } catch {
        /* ignore */
      }
    }
    for (const t of this.stream.getTracks()) t.stop();
    this.ev.end(kind, reason);
  }
}
