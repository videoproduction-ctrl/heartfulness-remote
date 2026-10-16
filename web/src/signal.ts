// WebSocket signaling client for /ws/client (docs/PROTOCOL.md §7.2).
// Authenticates with the session (cookie or bearer token) and then proves
// possession of the device key with HR1/client-auth over a server nonce.

import { b64 } from "./b64";
import type { HostInfo } from "./api";
import { b64Field, signClientAuth, type Signer } from "./hr1";
import type { Platform } from "./platform";

export type Msg = Record<string, unknown> & { type: string };

export type DeviceStatus = "unknown" | "pending" | "approved" | "revoked";

export interface ReadyInfo {
  status: DeviceStatus;
  host: HostInfo | null;
}

export type SignalState = "connecting" | "ready" | "reconnecting" | "closed" | "unauthorized";

const MAX_FRAME = 256 * 1024;
const BACKOFF_MS = [1000, 2000, 4000, 8000, 15000, 30000];
const AUTH_TIMEOUT_MS = 15_000;

type Handler = (m: Msg) => void;

function parseHost(v: unknown): HostInfo | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  const h: HostInfo = {
    pub: typeof o["pub"] === "string" ? o["pub"] : "",
    name: typeof o["name"] === "string" ? o["name"] : "",
    online: o["online"] === true,
    state: typeof o["state"] === "string" ? o["state"] : "",
  };
  if (typeof o["sessionDeviceName"] === "string") h.sessionDeviceName = o["sessionDeviceName"];
  return h;
}

export function parseStatus(v: unknown): DeviceStatus {
  return v === "pending" || v === "approved" || v === "revoked" ? v : "unknown";
}

export class Signal {
  private ws: WebSocket | null = null;
  private handlers = new Map<string, Set<Handler>>();
  private stateHandlers = new Set<(s: SignalState) => void>();
  private attempt = 0;
  private failuresBeforeReady = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private closedByUser = false;
  private firstReady: { resolve: (r: ReadyInfo) => void; reject: (e: Error) => void } | null = null;
  state: SignalState = "closed";
  lastReady: ReadyInfo | null = null;

  constructor(
    private readonly platform: Platform,
    private readonly signer: Signer,
  ) {}

  /** Connects and resolves on the first `ready`. Reconnects automatically afterwards. */
  connect(): Promise<ReadyInfo> {
    this.closedByUser = false;
    const p = new Promise<ReadyInfo>((resolve, reject) => {
      this.firstReady = { resolve, reject };
    });
    this.open();
    return p;
  }

  on(type: string, h: Handler): () => void {
    let set = this.handlers.get(type);
    if (!set) {
      set = new Set();
      this.handlers.set(type, set);
    }
    set.add(h);
    return () => set.delete(h);
  }

  onState(h: (s: SignalState) => void): () => void {
    this.stateHandlers.add(h);
    return () => this.stateHandlers.delete(h);
  }

  get isReady(): boolean {
    return this.state === "ready";
  }

  send(msg: Msg): boolean {
    const ws = this.ws;
    if (!ws || ws.readyState !== WebSocket.OPEN || this.state !== "ready") return false;
    const s = JSON.stringify(msg);
    if (s.length > MAX_FRAME) throw new Error("Message too large.");
    ws.send(s);
    return true;
  }

  close(): void {
    this.closedByUser = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
    const ws = this.ws;
    this.ws = null;
    if (ws) {
      ws.onclose = null;
      ws.onmessage = null;
      ws.onerror = null;
      try {
        ws.close(1000);
      } catch {
        /* ignore */
      }
    }
    this.setState("closed");
    this.firstReady?.reject(new Error("closed"));
    this.firstReady = null;
  }

  private setState(s: SignalState): void {
    if (this.state === s) return;
    this.state = s;
    for (const h of this.stateHandlers) h(s);
  }

  private emit(m: Msg): void {
    const set = this.handlers.get(m.type);
    if (set) for (const h of [...set]) h(m);
    const any = this.handlers.get("*");
    if (any) for (const h of [...any]) h(m);
  }

  private open(): void {
    let url: string;
    try {
      url = this.platform.wsURL();
    } catch (e) {
      this.firstReady?.reject(e instanceof Error ? e : new Error(String(e)));
      this.firstReady = null;
      return;
    }
    this.setState(this.lastReady ? "reconnecting" : "connecting");
    const ws = new WebSocket(url);
    this.ws = ws;
    let authed = false;
    const authTimer = setTimeout(() => {
      if (!authed) ws.close(4000);
    }, AUTH_TIMEOUT_MS);

    ws.onopen = () => {
      void this.platform.wsAuthMessage().then((m) => {
        if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(m));
      });
    };

    ws.onmessage = (ev: MessageEvent) => {
      if (typeof ev.data !== "string" || ev.data.length > MAX_FRAME) return;
      let m: Msg;
      try {
        const parsed: unknown = JSON.parse(ev.data);
        if (!parsed || typeof parsed !== "object" || typeof (parsed as Msg).type !== "string") return;
        m = parsed as Msg;
      } catch {
        return;
      }
      if (m.type === "challenge") {
        void this.answerChallenge(ws, m);
        return;
      }
      if (m.type === "ready") {
        authed = true;
        clearTimeout(authTimer);
        this.attempt = 0;
        this.failuresBeforeReady = 0;
        const info: ReadyInfo = {
          status: parseStatus((m["device"] as Record<string, unknown> | undefined)?.["status"]),
          host: parseHost(m["host"]),
        };
        this.lastReady = info;
        this.setState("ready");
        if (this.firstReady) {
          this.firstReady.resolve(info);
          this.firstReady = null;
        }
        this.emit(m);
        return;
      }
      if (m.type === "error" && !authed) {
        // Authentication was refused (expired session or bad device proof).
        const code = typeof m["code"] === "string" ? m["code"] : "";
        if (/auth|unauthor|session|login/i.test(code)) this.failuresBeforeReady = 99;
      }
      this.emit(m);
    };

    ws.onerror = () => {
      /* onclose follows */
    };

    ws.onclose = (ev: CloseEvent) => {
      clearTimeout(authTimer);
      if (this.ws !== ws) return;
      this.ws = null;
      if (this.closedByUser) return;
      if (!authed) this.failuresBeforeReady++;
      // 4401/4403 (or repeated failures before `ready`) mean we're not signed in.
      if (ev.code === 4401 || ev.code === 4403 || ev.code === 1008 || this.failuresBeforeReady >= 3) {
        this.setState("unauthorized");
        this.firstReady?.reject(new Error("unauthorized"));
        this.firstReady = null;
        return;
      }
      this.setState("reconnecting");
      const delay = BACKOFF_MS[Math.min(this.attempt, BACKOFF_MS.length - 1)]!;
      this.attempt++;
      this.timer = setTimeout(() => {
        this.timer = null;
        if (!this.closedByUser) this.open();
      }, delay);
    };
  }

  private async answerChallenge(ws: WebSocket, m: Msg): Promise<void> {
    try {
      const nonce = b64Field(m, "nonce", 32);
      const origin = this.platform.origin();
      if (!origin) throw new Error("no origin");
      // The origin is OUR notion of the server (never one supplied by it).
      const sig = await signClientAuth(this.signer, origin, nonce);
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: "device-auth", devicePub: b64(this.signer.pub), sig: b64(sig) }));
      }
    } catch {
      ws.close(4000);
    }
  }
}

/** Resolves with the first message of `type` matching `pred`, or rejects on timeout/abort. */
export function waitFor(signal: Signal, types: string[], pred: (m: Msg) => boolean, timeoutMs: number, abort?: AbortSignal): Promise<Msg> {
  return new Promise<Msg>((resolve, reject) => {
    const offs: Array<() => void> = [];
    const done = () => {
      clearTimeout(t);
      for (const o of offs) o();
      abort?.removeEventListener("abort", onAbort);
    };
    const onAbort = () => {
      done();
      reject(new Error("aborted"));
    };
    const t = setTimeout(() => {
      done();
      reject(new Error("timeout"));
    }, timeoutMs);
    for (const ty of types) {
      offs.push(
        signal.on(ty, (m) => {
          if (!pred(m)) return;
          done();
          resolve(m);
        }),
      );
    }
    if (abort) {
      if (abort.aborted) onAbort();
      else abort.addEventListener("abort", onAbort);
    }
  });
}
