// Application controller: authentication state, the signaling connection,
// device approval state, the approvals inbox and view routing.

import { Api, ApiError, type HostInfo, type Me } from "./api";
import { type Bytes, b64, unb64Len } from "./b64";
import { clear } from "./dom";
import {
  type ApprovalRequest,
  checkApprovalRequest,
  nowSeconds,
  parseApprovalNeeded,
  signKillRequest,
  signPairApprove,
  signRevokeRequest,
  type Signer,
} from "./hr1";
import type { Platform } from "./platform";
import { type DeviceStatus, type Msg, parseStatus, type ReadyInfo, Signal, type SignalState } from "./signal";
import { errorMessage, toast } from "./ui";
import { firstRunView } from "./views/firstrun";
import { homeView } from "./views/home";
import { linkApproveView } from "./views/link";
import { loginView } from "./views/login";
import { errorView, loadingView, missingPinView, notSetUpView, revokedView, unsupportedView } from "./views/common";
import { pairView } from "./views/pair";
import { sessionView } from "./views/session";
import { type SetupFragment, setupView } from "./views/setup";

export interface View {
  name: string;
  el: HTMLElement;
  destroy?(): void;
}

export interface Approval {
  key: string;
  req: ApprovalRequest;
  sas: string | null;
  error: string | null;
  state: "open" | "sending" | "sent";
  receivedAt: number;
}

type AppEvent = "host" | "approvals" | "me" | "signal" | "status";

const APPROVAL_TTL_MS = 5 * 60 * 1000;

export class App {
  readonly api: Api;
  signal: Signal | null = null;
  signer: Signer | null = null;
  me: Me | null = null;
  host: HostInfo | null = null;
  status: DeviceStatus = "unknown";
  pinned: Bytes | null = null;
  readonly approvals = new Map<string, Approval>();
  private view: View | null = null;
  private readonly events = new EventTarget();
  private signalOffs: Array<() => void> = [];

  constructor(
    readonly platform: Platform,
    readonly root: HTMLElement,
    private setupFragment: SetupFragment | null,
  ) {
    this.api = new Api(platform);
    window.addEventListener("hashchange", () => this.onHashChange());
    setInterval(() => this.expireApprovals(), 30_000);
  }

  // ------------------------------------------------------------ events

  on(ev: AppEvent, fn: () => void): () => void {
    const l = () => fn();
    this.events.addEventListener(ev, l);
    return () => this.events.removeEventListener(ev, l);
  }

  private emit(ev: AppEvent): void {
    this.events.dispatchEvent(new Event(ev));
  }

  // ------------------------------------------------------------ views

  show(v: View): void {
    const prev = this.view;
    this.view = v;
    try {
      prev?.destroy?.();
    } catch {
      /* a view failing to clean up must not block navigation */
    }
    clear(this.root);
    this.root.appendChild(v.el);
    this.root.dataset["view"] = v.name;
    document.body.dataset["view"] = v.name;
    const focusTarget = v.el.querySelector<HTMLElement>("[autofocus]") ?? v.el.querySelector<HTMLElement>("h1");
    if (focusTarget) {
      if (!focusTarget.hasAttribute("tabindex") && focusTarget.tagName === "H1") focusTarget.tabIndex = -1;
      focusTarget.focus({ preventScroll: true });
    }
  }

  get viewName(): string {
    return this.view?.name ?? "";
  }

  private setHash(hash: string): void {
    const url = location.pathname + location.search + hash;
    if (location.hash !== hash) history.pushState(null, "", url);
  }

  private replaceHash(hash: string): void {
    history.replaceState(null, "", location.pathname + location.search + hash);
  }

  private onHashChange(): void {
    const hash = location.hash;
    if (hash === "#link") {
      if (this.me) this.show(linkApproveView(this));
      else void this.boot();
      return;
    }
    if (this.viewName === "session" && hash !== "#session") {
      this.routeByStatus();
      return;
    }
    if (this.viewName === "link" && hash !== "#link") {
      this.routeByStatus();
      return;
    }
    if (hash === "#session" && this.viewName !== "session") this.replaceHash("");
  }

  // ------------------------------------------------------------ boot & routing

  async start(): Promise<void> {
    const problem = await unsupportedReason();
    if (problem) {
      this.show(unsupportedView(problem));
      return;
    }
    try {
      await this.platform.init();
    } catch (e) {
      this.show(errorView(this, e, () => void this.start()));
      return;
    }
    if (this.platform.kind === "tauri" && !this.platform.origin()) {
      this.show(firstRunView(this));
      return;
    }
    if (this.setupFragment) {
      const f = this.setupFragment;
      this.setupFragment = null;
      this.show(setupView(this, f));
      return;
    }
    await this.boot();
  }

  /** Works out who we are (session? device status?) and shows the right view. */
  async boot(): Promise<void> {
    this.show(loadingView("Connecting…"));
    try {
      this.me = await this.api.me();
    } catch (e) {
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) {
        await this.toLogin();
        return;
      }
      this.show(errorView(this, e, () => void this.boot()));
      return;
    }
    this.emit("me");
    try {
      await this.connectSignal();
    } catch (e) {
      if (e instanceof Error && e.message === "unauthorized") {
        await this.toLogin();
        return;
      }
      this.show(errorView(this, e, () => void this.boot()));
      return;
    }
    this.routeByStatus();
  }

  private async toLogin(): Promise<void> {
    this.closeSignal();
    this.me = null;
    try {
      const st = await this.api.status();
      if (!st.claimed) {
        this.show(notSetUpView(this));
        return;
      }
    } catch {
      /* fall through to login */
    }
    if (this.platform.kind === "tauri" && (await this.platform.hasToken())) await this.platform.clearToken();
    this.show(loginView(this));
  }

  /** Shows the main view for the current device status. */
  routeByStatus(): void {
    if (location.hash === "#link" && this.me) {
      this.show(linkApproveView(this));
      return;
    }
    if (location.hash !== "") this.replaceHash("");
    switch (this.status) {
      case "approved":
        this.show(this.pinned ? homeView(this) : missingPinView(this));
        return;
      case "revoked":
        this.show(revokedView(this));
        return;
      default:
        this.show(pairView(this));
    }
  }

  goSession(): void {
    if (this.status !== "approved" || !this.pinned) return;
    this.setHash("#session");
    this.show(sessionView(this));
  }

  /** Leaves the session (or link) screen and returns to Home. */
  goHome(): void {
    if (location.hash === "#session" || location.hash === "#link") {
      this.replaceHash("");
    }
    this.routeByStatus();
  }

  // ------------------------------------------------------------ signaling

  /** True if the server reports a host key different from the one we pinned. */
  get hostMismatch(): boolean {
    return !!(this.pinned && this.host && this.host.pub !== "" && this.host.pub !== b64(this.pinned));
  }

  get signalState(): SignalState {
    return this.signal?.state ?? "closed";
  }

  closeSignal(): void {
    for (const off of this.signalOffs) off();
    this.signalOffs = [];
    this.signal?.close();
    this.signal = null;
    this.approvals.clear();
  }

  async connectSignal(): Promise<ReadyInfo> {
    this.closeSignal();
    this.signer = await this.platform.signer(true);
    if (!this.signer) throw new Error("Could not create this device's security key.");
    this.pinned = await this.platform.pinnedHost();
    const sig = new Signal(this.platform, this.signer);
    this.signal = sig;
    const offs = this.signalOffs;
    offs.push(sig.on("ready", (m) => this.onReady(m)));
    offs.push(sig.on("host-status", (m) => this.onHostStatus(m)));
    offs.push(sig.on("devices-changed", () => void this.refreshMe()));
    offs.push(sig.on("approval-needed", (m) => void this.onApprovalNeeded(m)));
    offs.push(sig.on("approval-closed", (m) => this.onApprovalClosed(m)));
    offs.push(
      sig.onState((s) => {
        this.emit("signal");
        if (s === "unauthorized" && this.signal === sig) {
          toast("You were signed out.", "info");
          void this.toLogin();
        }
      }),
    );
    const info = await sig.connect();
    this.status = info.status;
    this.host = info.host;
    return info;
  }

  private onReady(m: Msg): void {
    const prev = this.status;
    this.status = parseStatus((m["device"] as Record<string, unknown> | undefined)?.["status"]);
    this.host = this.signal?.lastReady?.host ?? this.host;
    this.emit("host");
    if (prev !== this.status) this.onStatusChanged(prev);
  }

  private onHostStatus(m: Msg): void {
    const h: HostInfo = { ...(this.host ?? { pub: "", name: "", online: false, state: "" }) };
    if (typeof m["online"] === "boolean") h.online = m["online"];
    if (typeof m["state"] === "string") h.state = m["state"];
    if (typeof m["sessionDeviceName"] === "string") h.sessionDeviceName = m["sessionDeviceName"];
    else delete h.sessionDeviceName;
    if (typeof m["name"] === "string") h.name = m["name"];
    this.host = h;
    this.emit("host");
  }

  async refreshMe(): Promise<void> {
    try {
      this.me = await this.api.me();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        await this.toLogin();
      }
      return;
    }
    if (this.me.host) {
      const h = this.me.host;
      this.host = { ...h, pub: h.pub || this.host?.pub || "" };
      this.emit("host");
    }
    const mine = this.signer ? this.me.devices.find((d) => d.pub === b64(this.signer!.pub)) : undefined;
    if (mine) {
      const s = parseStatus(mine.status);
      if (s !== this.status) {
        const prev = this.status;
        this.status = s;
        this.onStatusChanged(prev);
      }
    }
    this.emit("me");
  }

  private onStatusChanged(prev: DeviceStatus): void {
    this.emit("status");
    // Views that manage approval themselves (pairing, setup) listen to "status".
    if (this.status === "revoked" && prev !== "revoked") {
      toast("This device was removed from your Mac's trusted devices.", "info");
      this.show(revokedView(this));
    }
  }

  // ------------------------------------------------------------ approvals inbox

  private async onApprovalNeeded(m: Msg): Promise<void> {
    let req: ApprovalRequest;
    try {
      req = parseApprovalNeeded(m);
    } catch {
      return; // malformed: ignore
    }
    const key = b64(req.requestId);
    if (this.approvals.has(key)) return;
    const a: Approval = { key, req, sas: null, error: null, state: "open", receivedAt: Date.now() };
    if (!this.pinned) {
      a.error = "This device can't check the request because it doesn't know your Mac's key.";
    } else {
      try {
        a.sas = await checkApprovalRequest(this.pinned, req);
      } catch (e) {
        a.error = `Security check failed: ${errorMessage(e)}. Do not approve.`;
      }
    }
    this.approvals.set(key, a);
    this.emit("approvals");
    if (this.viewName !== "home") toast(`“${req.name}” is asking to use your Mac. Open Home to review.`, "info", 8000);
  }

  private onApprovalClosed(m: Msg): void {
    const id = m["requestId"];
    if (typeof id === "string" && this.approvals.delete(id)) this.emit("approvals");
  }

  private expireApprovals(): void {
    const now = Date.now();
    let changed = false;
    for (const [k, a] of this.approvals) {
      if (now - a.receivedAt > APPROVAL_TTL_MS) {
        this.approvals.delete(k);
        changed = true;
      }
    }
    if (changed) this.emit("approvals");
  }

  async approve(key: string): Promise<void> {
    const a = this.approvals.get(key);
    if (!a || a.state !== "open" || !a.sas || a.error) return;
    if (!this.signer || !this.pinned || !this.signal) throw new Error("Not connected.");
    a.state = "sending";
    this.emit("approvals");
    try {
      const sig = await signPairApprove(this.signer, this.pinned, a.req);
      const ok = this.signal.send({
        type: "pair-approve",
        requestId: key,
        approverPub: b64(this.signer.pub),
        sig: b64(sig),
      });
      if (!ok) throw new Error("Not connected to the server. Try again.");
      a.state = "sent";
    } catch (e) {
      a.state = "open";
      throw e;
    } finally {
      this.emit("approvals");
    }
  }

  deny(key: string): void {
    const a = this.approvals.get(key);
    if (!a || !this.signal) return;
    if (!this.signal.send({ type: "pair-deny", requestId: key })) throw new Error("Not connected to the server. Try again.");
    this.approvals.delete(key);
    this.emit("approvals");
  }

  // ------------------------------------------------------------ device management

  async revokeDevice(targetPubB64: string): Promise<void> {
    if (!this.signer || !this.pinned || !this.signal) throw new Error("Not connected.");
    const target = unb64Len(targetPubB64, 32);
    const ts = nowSeconds();
    const sig = await signRevokeRequest(this.signer, this.pinned, target, ts);
    const ok = this.signal.send({
      type: "revoke-request",
      targetPub: targetPubB64,
      ts,
      approverPub: b64(this.signer.pub),
      sig: b64(sig),
    });
    if (!ok) throw new Error("Not connected to the server. Try again.");
  }

  async killSwitch(action: "kill" | "resume"): Promise<void> {
    if (!this.signer || !this.pinned || !this.signal) throw new Error("Not connected.");
    const ts = nowSeconds();
    const sig = await signKillRequest(this.signer, this.pinned, action, ts);
    const ok = this.signal.send({ type: "kill-request", action, ts, approverPub: b64(this.signer.pub), sig: b64(sig) });
    if (!ok) throw new Error("Not connected to the server. Try again.");
  }

  /** Forgets the device key (and optionally the pinned Mac key) and starts pairing again. */
  async resetDevice(forgetHost: boolean): Promise<void> {
    this.closeSignal();
    await this.platform.resetDeviceKey();
    if (forgetHost) await this.platform.forgetHost();
    this.pinned = null;
    this.status = "unknown";
    await this.boot();
  }

  async signOut(): Promise<void> {
    try {
      await this.api.logout();
    } catch {
      /* the session may already be gone */
    }
    await this.platform.clearToken().catch(() => undefined);
    this.closeSignal();
    this.me = null;
    this.status = "unknown";
    this.show(loginView(this));
  }
}

async function unsupportedReason(): Promise<string | null> {
  if (!window.isSecureContext) return "Heartfulness Remote only works over a secure (https) connection.";
  if (!globalThis.crypto?.subtle) return "This browser doesn't provide the security features Heartfulness Remote needs.";
  if (typeof indexedDB === "undefined") return "This browser can't store the device's security key (private mode?).";
  try {
    await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  } catch {
    return "This browser is too old: it doesn't support Ed25519 security keys. Please update it (Safari 17+, Chrome 137+, Firefox 129+, Edge 137+).";
  }
  return null;
}
