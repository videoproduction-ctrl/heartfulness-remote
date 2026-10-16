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

export interface HostInfo {
  pub: string;
  name: string;
  online: boolean;
  state: string; // "available" | "in-session" | "blocked"
  sessionDeviceName?: string;
}

export interface DeviceInfo {
  pub: string;
  name: string;
  kind: string;
  status: string; // "pending" | "approved" | "revoked"
  createdAt?: number | string;
  lastSeen?: number | string;
}

export interface PasskeyInfo {
  id: string;
  name: string;
  createdAt?: number | string;
}

export interface Me {
  host: HostInfo | null;
  devices: DeviceInfo[];
  passkeys: PasskeyInfo[];
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
    const m = await this.call<Partial<Me>>("/api/me");
    return {
      host: m.host ?? null,
      devices: Array.isArray(m.devices) ? m.devices : [],
      passkeys: Array.isArray(m.passkeys) ? m.passkeys : [],
    };
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
}
