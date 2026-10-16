// Application controller: authentication state, the signaling connection,
// the owner's Macs (PROTOCOL.md §10) with this device's approval on each,
// pinned Mac keys, the approvals inbox and view routing.

import { Api, ApiError, type DeviceInfo, type DeviceProof, type HostInfo, type Me } from "./api";
import { type Bytes, b64, unb64Len } from "./b64";
import { clear } from "./dom";
import { type Fragment, type JoinFragment, takeFragment } from "./fragment";
import { type ApprovalRequest, checkApprovalRequest, macId as computeMacId, nowSeconds, parseApprovalNeeded, PUB_SIZE, type Signer } from "./hr1";
import { aboutMac, killRequestMsg, pairApproveMsg, pairDenyMsg, revokeRequestMsg } from "./messages";
import type { PinMap } from "./pins";
import type { Platform } from "./platform";
import { type DeviceStatus, type Msg, parseReady, parseStatus, type ReadyHost, type ReadyInfo, Signal, type SignalState, waitFor } from "./signal";
import { requestPersistence } from "./store";
import { errorMessage, toast } from "./ui";
import { addMacView, joinNeedsApprovalView } from "./views/addmac";
import { errorView, loadingView, missingPinView, notSetUpView, revokedView, unsupportedView } from "./views/common";
import { firstRunView } from "./views/firstrun";
import { homeView } from "./views/home";
import { linkApproveView } from "./views/link";
import { loginView } from "./views/login";
import { pairView } from "./views/pair";
import { sessionView } from "./views/session";
import { setupView } from "./views/setup";

export interface View {
  name: string;
  el: HTMLElement;
  destroy?(): void;
}

/** One of the owner's Macs, with THIS device's approval status on it. */
export interface Mac extends HostInfo {
  /** 9-digit Mac ID computed locally from `pub` (never taken from the server). */
  macId: string;
  deviceStatus: DeviceStatus;
}

export interface Approval {
  key: string;
  hostPub: string;
  requestId: string;
  req: ApprovalRequest;
  sas: string | null;
  error: string | null;
  state: "open" | "sending" | "sent";
  receivedAt: number;
}

type AppEvent = "macs" | "approvals" | "me" | "signal" | "status" | "pins";

const APPROVAL_TTL_MS = 5 * 60 * 1000;

/** Aggregate approval of this device over all Macs: approved on any wins. */
export function aggregateStatus(macs: ReadonlyArray<{ deviceStatus: DeviceStatus }>): DeviceStatus {
  if (macs.some((m) => m.deviceStatus === "approved")) return "approved";
  if (macs.some((m) => m.deviceStatus === "pending")) return "pending";
  if (macs.some((m) => m.deviceStatus === "revoked")) return "revoked";
  return "unknown";
}

/** This device's status on each Mac according to /api/me (devices[mine].approvals). */
export function statusFromMe(me: Me, devicePub: string): (hostPub: string) => DeviceStatus {
  const mine = me.devices.find((d) => d.pub === devicePub);
  return (hostPub) => parseStatus(mine?.approvals.find((a) => a.hostPub === hostPub)?.status);
}

export class App {
  readonly api: Api;
  signal: Signal | null = null;
  signer: Signer | null = null;
  me: Me | null = null;
  /** The account's Macs in server order (at most 20). */
  macs: Mac[] = [];
  /** Pinned (verified) Mac keys on this device. */
  pins: PinMap = new Map();
  readonly approvals = new Map<string, Approval>();
  /** A join link (#join=…) waiting for sign-in / routing. Memory only. */
  pendingJoin: JoinFragment | null = null;
  private view: View | null = null;
  private readonly events = new EventTarget();
  private signalOffs: Array<() => void> = [];
  private readonly macIds = new Map<string, string>();
  private macsSeq = 0;

  constructor(
    readonly platform: Platform,
    readonly root: HTMLElement,
    private fragment: Fragment | null,
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

  // ------------------------------------------------------------ Macs & pins

  /** This device's aggregate status (approved on at least one Mac → "approved"). */
  get status(): DeviceStatus {
    return aggregateStatus(this.macs);
  }

  get devicePub(): string {
    return this.signer ? b64(this.signer.pub) : "";
  }

  mac(pub: string): Mac | undefined {
    return this.macs.find((m) => m.pub === pub);
  }

  /** Display name for a Mac: the server's name, else the name it was pinned with. */
  macName(pub: string): string {
    return this.mac(pub)?.name || this.pins.get(pub)?.name || "your Mac";
  }

  /** The PINNED key of a Mac, or null when this device has not verified that Mac. */
  pinBytes(pub: string): Bytes | null {
    if (!this.pins.has(pub)) return null;
    try {
      return unb64Len(pub, PUB_SIZE);
    } catch {
      return null;
    }
  }

  /** Approved on that Mac AND its key is pinned: this device can connect / sign for it. */
  canUse(pub: string): boolean {
    return this.mac(pub)?.deviceStatus === "approved" && this.pins.has(pub);
  }

  get usableMacs(): Mac[] {
    return this.macs.filter((m) => this.canUse(m.pub));
  }

  private async loadPins(): Promise<PinMap> {
    const store = this.platform.pins();
    if (!store) return new Map();
    try {
      return await store.load();
    } catch {
      return new Map();
    }
  }

  /** Pins a verified Mac key (setup QR, SAS pairing + cert, or join hostMac). */
  async pinMac(hostPub: Uint8Array, name: string): Promise<void> {
    const store = this.platform.pins();
    if (!store) throw new Error("No server address is configured.");
    this.pins = await store.add(hostPub, name);
    void requestPersistence();
    this.emit("pins");
  }

  async unpinMac(pub: string): Promise<void> {
    const store = this.platform.pins();
    if (store) this.pins = await store.remove(pub);
    this.emit("pins");
  }

  /** Records locally that this device is now approved on a Mac (after a verified cert). */
  markApproved(pub: string): void {
    const prev = this.status;
    const m = this.mac(pub);
    if (m) m.deviceStatus = "approved";
    this.emit("macs");
    if (prev !== this.status) this.onStatusChanged(prev);
    void this.refreshMe();
  }

  private async toMacs(hosts: HostInfo[], statusOf: (h: HostInfo) => DeviceStatus): Promise<Mac[]> {
    const out: Mac[] = [];
    for (const h of hosts) {
      let id = this.macIds.get(h.pub);
      if (!id) {
        id = await computeMacId(unb64Len(h.pub, PUB_SIZE));
        this.macIds.set(h.pub, id);
      }
      out.push({ ...h, macId: id, deviceStatus: statusOf(h) });
    }
    return out;
  }

  private async setMacs(hosts: HostInfo[], statusOf: (h: HostInfo) => DeviceStatus): Promise<void> {
    const seq = ++this.macsSeq;
    const next = await this.toMacs(hosts, statusOf);
    if (seq !== this.macsSeq) return; // a newer update won
    const prevStatus = this.status;
    const before = new Map(this.macs.map((m) => [m.pub, m.deviceStatus]));
    this.macs = next;
    for (const m of next) {
      if (before.get(m.pub) === "approved" && m.deviceStatus === "revoked") {
        toast(`This device was removed from “${m.name || "a Mac"}”.`, "info", 7000);
      }
    }
    // Drop inbox entries for Macs that left the account.
    for (const [k, a] of this.approvals) if (!this.mac(a.hostPub)) this.approvals.delete(k);
    this.emit("macs");
    if (prevStatus !== this.status) this.onStatusChanged(prevStatus);
  }

  private applyReady(info: ReadyInfo): Promise<void> {
    return this.setMacs(info.hosts, (h) => (h as ReadyHost).deviceStatus);
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
    // A setup / join QR link opened in a tab that is already running (same
    // document): take the secret out of the address bar first.
    const frag = takeFragment();
    if (frag) {
      if (this.handleFragment(frag)) return;
      if (frag.kind === "join") {
        if (this.me && this.signalState === "ready") this.routeByStatus();
        else void this.boot();
      }
      return;
    }
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

  /** Acts on a setup/join link. Returns true when it showed a view itself. */
  private handleFragment(f: Fragment): boolean {
    if (f.kind === "invalid") {
      toast(
        f.of === "setup"
          ? "This setup link is damaged. On your Mac, show the QR code again and rescan it."
          : "This link to add a Mac is damaged. On the new Mac, show the code again and rescan it.",
        "error",
        9000,
      );
      return false;
    }
    if (f.kind === "setup") {
      this.show(setupView(this, f.frag));
      return true;
    }
    this.pendingJoin?.t.fill(0);
    this.pendingJoin = f.frag;
    return false;
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
    if (this.fragment) {
      const f = this.fragment;
      this.fragment = null;
      if (this.handleFragment(f)) return;
    }
    await this.boot();
  }

  /** Works out who we are (session? approvals?) and shows the right view. */
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
        this.dropPendingJoin();
        this.show(notSetUpView(this));
        return;
      }
    } catch {
      /* fall through to login */
    }
    if (this.platform.kind === "tauri" && (await this.platform.hasToken())) await this.platform.clearToken();
    this.show(loginView(this));
  }

  private dropPendingJoin(): void {
    this.pendingJoin?.t.fill(0);
    this.pendingJoin = null;
  }

  /** Shows the main view for this device's approvals. */
  routeByStatus(): void {
    if (location.hash === "#link" && this.me) {
      this.show(linkApproveView(this));
      return;
    }
    if (location.hash !== "") this.replaceHash("");
    if (this.pendingJoin) {
      const f = this.pendingJoin;
      this.pendingJoin = null;
      if (this.usableMacs.length > 0) {
        this.show(addMacView(this, f));
      } else {
        f.t.fill(0);
        this.show(joinNeedsApprovalView(this));
      }
      return;
    }
    switch (this.status) {
      case "approved":
        this.show(this.usableMacs.length > 0 ? homeView(this) : missingPinView(this));
        return;
      case "revoked":
        if (this.macs.length <= 1) {
          this.show(revokedView(this));
          return;
        }
        break;
      default:
        break;
    }
    // Not approved on any Mac yet. With one Mac, ask it straight away (as
    // before); with several, let the owner choose which Mac to ask.
    if (this.macs.length > 1) this.show(homeView(this));
    else this.show(pairView(this, this.macs[0]?.pub ?? null));
  }

  goSession(pub: string): void {
    if (!this.canUse(pub)) return;
    this.setHash("#session");
    this.show(sessionView(this, pub));
  }

  goPair(pub: string): void {
    this.show(pairView(this, pub));
  }

  goAddMac(): void {
    this.show(addMacView(this, null));
  }

  /** Leaves the session (or link) screen and returns to Home. */
  goHome(): void {
    if (location.hash === "#session" || location.hash === "#link") {
      this.replaceHash("");
    }
    this.routeByStatus();
  }

  // ------------------------------------------------------------ signaling

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
    this.pins = await this.loadPins();
    const sig = new Signal(this.platform, this.signer);
    this.signal = sig;
    const offs = this.signalOffs;
    offs.push(sig.on("ready", (m) => void this.applyReady(parseReady(m))));
    offs.push(sig.on("host-status", (m) => this.onHostStatus(m)));
    offs.push(sig.on("devices-changed", () => void this.refreshMe()));
    offs.push(sig.on("hosts-changed", () => void this.refreshMe()));
    offs.push(sig.on("host-joined", () => void this.refreshMe()));
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
    await this.applyReady(info);
    return info;
  }

  private onHostStatus(m: Msg): void {
    let pub = typeof m["hostPub"] === "string" ? m["hostPub"] : "";
    if (pub === "" && this.macs.length === 1) pub = this.macs[0]!.pub; // older single-Mac server
    const mac = this.mac(pub);
    if (!mac) {
      if (pub !== "") void this.refreshMe(); // a Mac we don't know yet
      return;
    }
    if (typeof m["online"] === "boolean") mac.online = m["online"];
    if (typeof m["state"] === "string") mac.state = m["state"].slice(0, 40);
    if (typeof m["sessionDeviceName"] === "string" && m["sessionDeviceName"] !== "") mac.sessionDeviceName = m["sessionDeviceName"].slice(0, 200);
    else delete mac.sessionDeviceName;
    if (typeof m["name"] === "string" && m["name"] !== "") mac.name = m["name"].slice(0, 200);
    this.emit("macs");
  }

  async refreshMe(): Promise<void> {
    let me: Me;
    try {
      me = await this.api.me();
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) {
        await this.toLogin();
      }
      return;
    }
    this.me = me;
    await this.setMacs(me.hosts, (() => {
      const of = statusFromMe(me, this.devicePub);
      return (h: HostInfo) => of(h.pub);
    })());
    this.emit("me");
  }

  private onStatusChanged(prev: DeviceStatus): void {
    this.emit("status");
    // Views that manage approval themselves (pairing, setup) listen to "status".
    if (this.status === "revoked" && prev !== "revoked" && this.macs.length <= 1) {
      toast("This device was removed from your Mac's trusted devices.", "info");
      this.show(revokedView(this));
    }
  }

  /**
   * Resolves with `host-joined` for that Mac (§10.2 step 5) — or with the
   * server's `error {for:"join", hostPub}` — and rejects on timeout/abort.
   */
  waitHostJoined(hostPub: string, timeoutMs: number, abort?: AbortSignal): Promise<Msg> {
    const sig = this.signal;
    if (!sig) return Promise.reject(new Error("Not connected to the server."));
    return waitFor(
      sig,
      ["host-joined", "error"],
      (m) => m["hostPub"] === hostPub && (m.type === "host-joined" || m["for"] === "join"),
      timeoutMs,
      abort,
    );
  }

  // ------------------------------------------------------------ approvals inbox

  private async onApprovalNeeded(m: Msg): Promise<void> {
    let req: ApprovalRequest;
    try {
      req = parseApprovalNeeded(m);
    } catch {
      return; // malformed: ignore
    }
    let hostPub = typeof m["hostPub"] === "string" ? m["hostPub"] : "";
    if (hostPub === "" && this.pins.size === 1) hostPub = [...this.pins.keys()][0]!; // older single-Mac server
    const requestId = b64(req.requestId);
    const key = `${hostPub}|${requestId}`;
    if (this.approvals.has(key)) return;
    const a: Approval = { key, hostPub, requestId, req, sas: null, error: null, state: "open", receivedAt: Date.now() };
    // Verify with THAT Mac's pinned key — never with a key the server supplies.
    const pin = this.pinBytes(hostPub);
    if (!pin) {
      a.error = "This device can't check the request because it doesn't know that Mac's security key.";
    } else {
      try {
        a.sas = await checkApprovalRequest(pin, req);
      } catch (e) {
        a.error = `Security check failed: ${errorMessage(e)}. Do not approve.`;
      }
    }
    this.approvals.set(key, a);
    this.emit("approvals");
    if (this.viewName !== "home") toast(`“${req.name}” is asking to use “${this.macName(hostPub)}”. Open Home to review.`, "info", 8000);
  }

  private onApprovalClosed(m: Msg): void {
    const id = m["requestId"];
    if (typeof id !== "string") return;
    let changed = false;
    for (const [k, a] of this.approvals) {
      if (a.requestId === id && aboutMac(m, a.hostPub)) {
        this.approvals.delete(k);
        changed = true;
      }
    }
    if (changed) this.emit("approvals");
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
    const pin = this.pinBytes(a.hostPub);
    if (!this.signer || !pin || !this.signal) throw new Error("Not connected.");
    a.state = "sending";
    this.emit("approvals");
    try {
      const msg = await pairApproveMsg(this.signer, pin, a.req);
      if (!this.signal.send(msg)) throw new Error("Not connected to the server. Try again.");
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
    if (!this.signal.send(pairDenyMsg(a.hostPub, a.requestId))) throw new Error("Not connected to the server. Try again.");
    this.approvals.delete(key);
    this.emit("approvals");
  }

  // ------------------------------------------------------------ device & Mac management

  /** Macs where `device` is approved AND this device can sign for (approved + pinned). */
  revokableMacs(device: DeviceInfo): Mac[] {
    return this.macs.filter((m) => this.canUse(m.pub) && device.approvals.some((a) => a.hostPub === m.pub && a.status === "approved"));
  }

  /** Sends a signed revoke-request to every Mac the device is approved on (that we can sign for). Returns how many. */
  async revokeDevice(device: DeviceInfo): Promise<number> {
    if (!this.signer || !this.signal) throw new Error("Not connected.");
    const target = unb64Len(device.pub, PUB_SIZE);
    const ts = nowSeconds();
    let sent = 0;
    for (const m of this.revokableMacs(device)) {
      const pin = this.pinBytes(m.pub);
      if (!pin) continue;
      const msg = await revokeRequestMsg(this.signer, pin, target, ts);
      if (!this.signal.send(msg)) throw new Error("Not connected to the server. Try again.");
      sent++;
    }
    return sent;
  }

  async killSwitch(pub: string, action: "kill" | "resume"): Promise<void> {
    const pin = this.pinBytes(pub);
    if (!this.signer || !this.signal || !pin || !this.canUse(pub)) throw new Error("This device can't control that Mac.");
    const msg = await killRequestMsg(this.signer, pin, action, nowSeconds());
    if (!this.signal.send(msg)) throw new Error("Not connected to the server. Try again.");
  }

  /** "device proof" for state-changing API calls (fresh single-use nonce). */
  async deviceProof(): Promise<DeviceProof> {
    const origin = this.platform.origin();
    if (!this.signer || !origin) throw new Error("This device's key is not available.");
    return this.api.deviceProof(this.signer, origin);
  }

  /** This device's name and kind exactly as the server registered them (signed into the join setupMac). */
  async registeredDevice(): Promise<{ name: string; kind: string }> {
    const find = () => this.me?.devices.find((d) => d.pub === this.devicePub);
    if (!find()) await this.refreshMe();
    const d = find();
    if (!d) throw new Error("This device isn't registered with your account yet. Approve it on one of your Macs first.");
    return { name: d.name, kind: d.kind || this.platform.deviceKind };
  }

  /** Unbinds a Mac from the account (POST /api/hosts/remove) and forgets its key here. */
  async removeMac(pub: string): Promise<void> {
    const proof = await this.deviceProof();
    try {
      await this.api.hostsRemove(proof, pub);
    } catch (e) {
      if (e instanceof ApiError && e.code === "last-host") throw new Error("This is the only Mac in your account, so it can't be removed.");
      if (e instanceof ApiError && e.code === "not-found") {
        /* already gone: just tidy up here */
      } else throw e;
    }
    await this.unpinMac(pub);
    this.macs = this.macs.filter((m) => m.pub !== pub);
    for (const [k, a] of this.approvals) if (a.hostPub === pub) this.approvals.delete(k);
    this.emit("macs");
    this.emit("approvals");
    await this.refreshMe();
  }

  /** Forgets the device key (and optionally all pinned Mac keys) and starts pairing again. */
  async resetDevice(forgetPins: boolean): Promise<void> {
    this.closeSignal();
    await this.platform.resetDeviceKey();
    if (forgetPins) {
      await this.platform.pins()?.clear();
      this.pins = new Map();
    }
    this.macs = this.macs.map((m) => ({ ...m, deviceStatus: "unknown" }));
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
    this.dropPendingJoin();
    this.me = null;
    this.macs = [];
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
