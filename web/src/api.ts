// HTTP API client (docs/PROTOCOL.md §6).

import { b64, unb64Len } from "./b64";
import { signClientAuth, type Signer } from "./hr1";
import type { Platform } from "./platform";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly retryAfter: number | null = null,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export interface ServerStatus {
  claimed: boolean;
  rpId: string;
  origin: string;
}

/** One Mac of the account, as the server reports it (§10.4). Untrusted display data. */
export interface HostInfo {
  pub: string;
  name: string;
  online: boolean;
  state: string; // "available" | "in-session" | "blocked"
  sessionDeviceName?: string;
  claimedAt?: number | string;
  lastSeen?: number | string;
}

/** A device's approval status on one Mac (§10.4 `approvals`). */
export interface DeviceApproval {
  hostPub: string;
  status: string; // "pending" | "approved" | "revoked"
}

export interface DeviceInfo {
  pub: string;
  name: string;
  kind: string;
  createdAt?: number | string;
  lastSeen?: number | string;
  approvals: DeviceApproval[];
}

export interface PasskeyInfo {
  id: string;
  name: string;
  createdAt?: number | string;
}

export interface Me {
  hosts: HostInfo[];
  devices: DeviceInfo[];
  passkeys: PasskeyInfo[];
}

export interface PendingHost {
  hostPub: string;
  name: string;
}

export interface JoinFlow {
  flowId: string;
  name: string;
  macId: string;
}

const MAX_HOSTS = 20;
const MAX_TEXT = 200;

function text(v: unknown): string {
  return typeof v === "string" ? v.slice(0, MAX_TEXT) : "";
}

function isKey(v: unknown): v is string {
  if (typeof v !== "string") return false;
  try {
    return b64(unb64Len(v, 32)) === v;
  } catch {
    return false;
  }
}

function time(v: unknown): number | string | undefined {
  return typeof v === "number" || typeof v === "string" ? v : undefined;
}

/** Sanitises one host record (drops it if its key is not a canonical 32-byte b64 key). */
export function parseHostInfo(v: unknown): HostInfo | null {
  if (!v || typeof v !== "object") return null;
  const o = v as Record<string, unknown>;
  if (!isKey(o["pub"])) return null;
  const h: HostInfo = { pub: o["pub"], name: text(o["name"]), online: o["online"] === true, state: text(o["state"]) };
  if (typeof o["sessionDeviceName"] === "string" && o["sessionDeviceName"] !== "") h.sessionDeviceName = text(o["sessionDeviceName"]);
  const ca = time(o["claimedAt"]);
  if (ca !== undefined) h.claimedAt = ca;
  const ls = time(o["lastSeen"]);
  if (ls !== undefined) h.lastSeen = ls;
  return h;
}

/** Sanitises a host list, de-duplicated by key, at most 20 entries. */
export function parseHostList(v: unknown): HostInfo[] {
  const out: HostInfo[] = [];
  const seen = new Set<string>();
  for (const x of Array.isArray(v) ? v : []) {
    const h = parseHostInfo(x);
    if (!h || seen.has(h.pub)) continue;
    seen.add(h.pub);
    out.push(h);
    if (out.length >= MAX_HOSTS) break;
  }
  return out;
}

/**
 * Normalises GET /api/me. Accepts the §10.4 shape ({hosts, devices[].approvals})
 * and the older single-Mac shape ({host, devices[].status}).
 */
export function normalizeMe(raw: unknown): Me {
  const m = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
  let hosts = parseHostList(m["hosts"]);
  if (!Array.isArray(m["hosts"])) {
    const legacy = parseHostInfo(m["host"]);
    hosts = legacy ? [legacy] : [];
  }
  const single = hosts.length === 1 ? hosts[0]!.pub : null;
  const devices: DeviceInfo[] = [];
  for (const x of Array.isArray(m["devices"]) ? m["devices"] : []) {
    if (!x || typeof x !== "object") continue;
    const d = x as Record<string, unknown>;
    if (!isKey(d["pub"])) continue;
    const approvals: DeviceApproval[] = [];
    if (Array.isArray(d["approvals"])) {
      for (const a of d["approvals"]) {
        if (!a || typeof a !== "object") continue;
        const ar = a as Record<string, unknown>;
        if (isKey(ar["hostPub"]) && typeof ar["status"] === "string") approvals.push({ hostPub: ar["hostPub"], status: ar["status"] });
      }
    } else if (typeof d["status"] === "string" && single) {
      approvals.push({ hostPub: single, status: d["status"] });
    }
    const dev: DeviceInfo = { pub: d["pub"], name: text(d["name"]), kind: text(d["kind"]), approvals };
    const ca = time(d["createdAt"]);
    if (ca !== undefined) dev.createdAt = ca;
    const ls = time(d["lastSeen"]);
    if (ls !== undefined) dev.lastSeen = ls;
    devices.push(dev);
  }
  const passkeys: PasskeyInfo[] = [];
  for (const x of Array.isArray(m["passkeys"]) ? m["passkeys"] : []) {
    if (!x || typeof x !== "object") continue;
    const p = x as Record<string, unknown>;
    if (typeof p["id"] !== "string") continue;
    const pk: PasskeyInfo = { id: p["id"], name: text(p["name"]) };
    const ca = time(p["createdAt"]);
    if (ca !== undefined) pk.createdAt = ca;
    passkeys.push(pk);
  }
  return { hosts, devices, passkeys };
}

export interface Flow {
  flowId: string;
  options: unknown;
}

export interface DeviceProof {
  devicePub: string;
  nonce: string;
  sig: string;
}

function friendlyMessage(status: number, code: string, retryAfter: number | null): string {
  if (status === 429) {
    const mins = retryAfter ? Math.max(1, Math.ceil(retryAfter / 60)) : null;
    return mins
      ? `Too many attempts. For your security, please wait ${mins} minute${mins === 1 ? "" : "s"} and try again.`
      : "Too many attempts. For your security, please wait a few minutes and try again.";
  }
  if (status === 401) return "You're signed out. Please sign in again.";
  if (status === 403) return "This action isn't allowed.";
  if (status >= 500) return "The server had a problem. Please try again in a moment.";
  if (code && /^[a-z0-9_ -]{1,60}$/i.test(code)) return `Request failed (${code}).`;
  return `Request failed (HTTP ${status}).`;
}

export class Api {
  constructor(private readonly platform: Pick<Platform, "request">) {}

  async call<T>(path: string, body?: unknown, method?: "GET" | "POST"): Promise<T> {
    let res: Response;
    try {
      res = await this.platform.request(path, method ?? (body === undefined ? "GET" : "POST"), body);
    } catch (e) {
      if (e instanceof ApiError) throw e;
      throw new ApiError(0, "network", "Can't reach the server. Check your internet connection.");
    }
    const text = await res.text().catch(() => "");
    let data: unknown = null;
    if (text !== "") {
      try {
        data = JSON.parse(text);
      } catch {
        data = null;
      }
    }
    if (!res.ok) {
      const ra = Number(res.headers.get("Retry-After"));
      const retryAfter = Number.isFinite(ra) && ra > 0 ? ra : null;
      let code = "";
      let message = "";
      if (data && typeof data === "object") {
        const d = data as Record<string, unknown>;
        if (typeof d["code"] === "string") code = d["code"];
        else if (typeof d["error"] === "string") code = d["error"];
        if (typeof d["message"] === "string") message = d["message"];
      }
      throw new ApiError(res.status, code, message && message.length < 200 ? message : friendlyMessage(res.status, code, retryAfter), retryAfter);
    }
    return data as T;
  }

  status(): Promise<ServerStatus> {
    return this.call<ServerStatus>("/api/status");
  }

  async me(): Promise<Me> {
    return normalizeMe(await this.call<unknown>("/api/me"));
  }

  turn(): Promise<{ iceServers: RTCIceServer[]; ttl?: number }> {
    return this.call("/api/turn", {});
  }

  setupBegin(hostPub: string, claim: string): Promise<Flow> {
    return this.call<Flow>("/api/setup/begin", { hostPub, claim });
  }

  setupFinish(body: {
    flowId: string;
    credential: unknown;
    device: { pub: string; name: string; kind: string };
    setupMac: string;
  }): Promise<unknown> {
    return this.call("/api/setup/finish", body);
  }

  loginBegin(): Promise<Flow> {
    return this.call<Flow>("/api/login/begin", {});
  }

  loginFinish(flowId: string, credential: unknown): Promise<unknown> {
    return this.call("/api/login/finish", { flowId, credential });
  }

  logout(): Promise<unknown> {
    return this.call("/api/logout", {});
  }

  linkStart(name: string): Promise<{ code: string; pollToken: string; expiresIn: number }> {
    return this.call("/api/link/start", { name });
  }

  linkApprove(code: string): Promise<unknown> {
    return this.call("/api/link/approve", { code });
  }

  linkPoll(pollToken: string): Promise<{ status: "pending" | "approved" | "expired"; token?: string }> {
    return this.call("/api/link/poll", { pollToken });
  }

  /** "device proof": a fresh single-use server nonce signed with HR1/client-auth. */
  async deviceProof(signer: Signer, origin: string): Promise<DeviceProof> {
    const r = await this.call<{ nonce: string }>("/api/nonce");
    const nonce = unb64Len(r.nonce, 32);
    const sig = await signClientAuth(signer, origin, nonce);
    return { devicePub: b64(signer.pub), nonce: r.nonce, sig: b64(sig) };
  }

  passkeysBegin(proof: DeviceProof): Promise<Flow> {
    return this.call<Flow>("/api/passkeys/begin", { ...proof });
  }

  passkeysFinish(proof: DeviceProof, flowId: string, credential: unknown, name?: string): Promise<unknown> {
    return this.call("/api/passkeys/finish", { ...proof, flowId, credential, ...(name ? { name } : {}) });
  }

  passkeysDelete(proof: DeviceProof, id: string): Promise<unknown> {
    return this.call("/api/passkeys/delete", { ...proof, id });
  }

  // ------------------------------------------------------------ multiple Macs (§10.2)

  /** Typed path: finds a Mac waiting to be added by its 9-digit Mac ID (device proof in the query, it's a GET). */
  async hostsPending(proof: DeviceProof, macId: string): Promise<PendingHost> {
    if (!/^\d{9}$/.test(macId)) throw new Error("A Mac ID has 9 digits.");
    const q = new URLSearchParams({ macId, devicePub: proof.devicePub, nonce: proof.nonce, sig: proof.sig });
    const r = await this.call<Record<string, unknown> | null>(`/api/hosts/pending?${q.toString()}`, undefined, "GET");
    if (!r || !isKey(r["hostPub"])) throw new ApiError(502, "bad-response", "The server sent an unexpected answer. Please try again.");
    return { hostPub: r["hostPub"], name: text(r["name"]) };
  }

  /** Proves knowledge of the join code (claim = Kc) for that pending Mac. */
  async joinBegin(proof: DeviceProof, hostPub: string, claim: string): Promise<JoinFlow> {
    const r = await this.call<Record<string, unknown> | null>("/api/hosts/join/begin", { hostPub, claim, ...proof });
    if (!r || typeof r["flowId"] !== "string" || r["flowId"] === "") {
      throw new ApiError(502, "bad-response", "The server sent an unexpected answer. Please try again.");
    }
    return { flowId: r["flowId"], name: text(r["name"]), macId: typeof r["macId"] === "string" ? r["macId"] : "" };
  }

  /** Sends the setup MAC; the server forwards it to the Mac (setup-device). */
  async joinFinish(proof: DeviceProof, flowId: string, setupMac: string): Promise<Record<string, unknown>> {
    const r = await this.call<unknown>("/api/hosts/join/finish", { flowId, setupMac, ...proof });
    return r && typeof r === "object" ? (r as Record<string, unknown>) : {};
  }

  /** Unbinds a Mac from the account. */
  hostsRemove(proof: DeviceProof, hostPub: string): Promise<unknown> {
    return this.call("/api/hosts/remove", { hostPub, ...proof });
  }
}
