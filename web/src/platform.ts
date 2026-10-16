// Platform abstraction: the same client runs in a normal browser (cookie
// session, WebCrypto device key in IndexedDB) or inside the Tauri app (bearer
// token and device key held by the native side, see tauri/).

import { type Bytes, b64, toBytes, unb64, unb64Len } from "./b64";
import { PUB_SIZE, SIG_SIZE, type Signer } from "./hr1";
import { kvDel, kvGet, kvSet, requestPersistence } from "./store";

export type PlatformKind = "browser" | "tauri";

/** Device "kind" sent in pair-start / setup (signed into HR1/setup and HR1/pair-approve). */
export const KIND_BROWSER = "browser";
export const KIND_APP = "app";

export interface Platform {
  readonly kind: PlatformKind;
  readonly deviceKind: string;
  /** The server's public origin: used for API calls and signed into HR1/client-auth. */
  origin(): string | null;
  init(): Promise<void>;
  setOrigin(origin: string): Promise<void>;
  /** Returns the device key, creating it when `create` is true and none exists. */
  signer(create: boolean): Promise<Signer | null>;
  /** Discards the device key (a new one is created on next use). */
  resetDeviceKey(): Promise<void>;
  request(path: string, method: "GET" | "POST", body?: unknown): Promise<Response>;
  wsURL(): string;
  wsAuthMessage(): Promise<Record<string, unknown>>;
  hasToken(): Promise<boolean>;
  setToken(token: string): Promise<void>;
  clearToken(): Promise<void>;
  openURL(url: string): Promise<void>;
  pinnedHost(): Promise<Bytes | null>;
  pinHost(hostPub: Uint8Array): Promise<void>;
  forgetHost(): Promise<void>;
}

/**
 * Turns what the user typed ("heartfulness-remote.dedyn.io") into an origin
 * ("https://heartfulness-remote.dedyn.io"). Only https is accepted, except
 * plain http to localhost for development.
 */
export function normalizeOrigin(input: string): string {
  let s = input.trim();
  if (s === "") throw new Error("Please enter your server address.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new Error("That doesn't look like a web address.");
  }
  const local = u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) {
    throw new Error("The address must start with https://");
  }
  if (u.username || u.password) throw new Error("The address must not contain a user name or password.");
  if ((u.pathname !== "/" && u.pathname !== "") || u.search || u.hash) {
    throw new Error("Enter only the server address, without a path.");
  }
  return u.origin;
}

const REQUEST_TIMEOUT_MS = 20_000;

function wsFromOrigin(origin: string): string {
  return `${origin.replace(/^http/, "ws")}/ws/client`;
}

function pinKey(origin: string): string {
  return `hostPub@${origin}`;
}

async function readPin(origin: string | null): Promise<Bytes | null> {
  if (!origin) return null;
  const v = await kvGet<string>(pinKey(origin));
  if (typeof v !== "string") return null;
  try {
    return unb64Len(v, PUB_SIZE);
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ browser

interface StoredDeviceKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  pub: string;
}

class BrowserPlatform implements Platform {
  readonly kind = "browser" as const;
  readonly deviceKind = KIND_BROWSER;
  private cached: Signer | null = null;

  origin(): string {
    return location.origin;
  }

  async init(): Promise<void> {}

  async setOrigin(): Promise<void> {
    throw new Error("The browser always uses the address it was opened from.");
  }

  async signer(create: boolean): Promise<Signer | null> {
    if (this.cached) return this.cached;
    const run = async (): Promise<Signer | null> => {
      let stored = await kvGet<StoredDeviceKey>("deviceKey");
      if (!stored && create) {
        // Non-extractable: the private key can be used but never read out.
        const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
        const pub = b64(await crypto.subtle.exportKey("raw", kp.publicKey));
        stored = { privateKey: kp.privateKey, publicKey: kp.publicKey, pub };
        await kvSet("deviceKey", stored);
        void requestPersistence();
      }
      if (!stored) return null;
      const priv = stored.privateKey;
      const s: Signer = {
        pub: unb64Len(stored.pub, PUB_SIZE),
        async sign(data: Bytes): Promise<Bytes> {
          return toBytes(await crypto.subtle.sign({ name: "Ed25519" }, priv, data));
        },
      };
      return s;
    };
    // Serialise key creation across tabs when the Web Locks API is available.
    const locks = (navigator as Navigator & { locks?: LockManager }).locks;
    const s = locks ? await locks.request("hr-device-key", run) : await run();
    if (s) this.cached = s;
    return s;
  }

  async resetDeviceKey(): Promise<void> {
    this.cached = null;
    await kvDel("deviceKey");
  }

  request(path: string, method: "GET" | "POST", body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { "X-HR": "1", Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    return fetch(path, {
      method,
      headers,
      body: body === undefined ? null : JSON.stringify(body),
      credentials: "same-origin",
      mode: "same-origin",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  }

  wsURL(): string {
    return wsFromOrigin(location.origin);
  }

  async wsAuthMessage(): Promise<Record<string, unknown>> {
    return { type: "auth" };
  }

  async hasToken(): Promise<boolean> {
    return false;
  }

  async setToken(): Promise<void> {}

  async clearToken(): Promise<void> {}

  async openURL(url: string): Promise<void> {
    location.assign(url);
  }

  pinnedHost(): Promise<Bytes | null> {
    return readPin(this.origin());
  }

  async pinHost(hostPub: Uint8Array): Promise<void> {
    await kvSet(pinKey(this.origin()), b64(hostPub));
    void requestPersistence();
  }

  async forgetHost(): Promise<void> {
    await kvDel(pinKey(this.origin()));
  }
}

// ------------------------------------------------------------------ Tauri

type Invoke = <T>(cmd: string, args?: Record<string, unknown>) => Promise<T>;

function tauriInvoke(): Invoke | null {
  const w = globalThis as unknown as { __TAURI__?: { core?: { invoke?: Invoke } } };
  const core = w.__TAURI__?.core;
  const inv = core?.invoke;
  return typeof inv === "function" ? (inv.bind(core) as Invoke) : null;
}

class TauriPlatform implements Platform {
  readonly kind = "tauri" as const;
  readonly deviceKind = KIND_APP;
  private serverOrigin: string | null = null;
  private token: string | null | undefined = undefined;
  private cached: Signer | null = null;

  constructor(private readonly invoke: Invoke) {}

  origin(): string | null {
    return this.serverOrigin;
  }

  async init(): Promise<void> {
    const cfg = await this.invoke<unknown>("config_get");
    let o: unknown = null;
    if (typeof cfg === "string") o = cfg;
    else if (cfg && typeof cfg === "object") o = (cfg as { origin?: unknown }).origin;
    if (typeof o === "string" && o !== "") {
      try {
        this.serverOrigin = normalizeOrigin(o);
      } catch {
        this.serverOrigin = null;
      }
    }
  }

  async setOrigin(origin: string): Promise<void> {
    const o = normalizeOrigin(origin);
    await this.invoke("config_set", { origin: o });
    this.serverOrigin = o;
  }

  async signer(): Promise<Signer | null> {
    if (this.cached) return this.cached;
    const pubB64 = await this.invoke<string>("device_key_public");
    const pub = unb64Len(pubB64, PUB_SIZE);
    const invoke = this.invoke;
    this.cached = {
      pub,
      async sign(data: Bytes): Promise<Bytes> {
        const sig = await invoke<string>("device_key_sign", { data: b64(data) });
        const out = unb64(sig);
        if (out.length !== SIG_SIZE) throw new Error("The app returned a malformed signature.");
        return out;
      },
    };
    return this.cached;
  }

  async resetDeviceKey(): Promise<void> {
    this.cached = null;
    await this.invoke("device_key_reset");
  }

  private async getToken(): Promise<string | null> {
    if (this.token === undefined) {
      const t = await this.invoke<string | null>("token_get");
      this.token = typeof t === "string" && t !== "" ? t : null;
    }
    return this.token;
  }

  async request(path: string, method: "GET" | "POST", body?: unknown): Promise<Response> {
    const o = this.serverOrigin;
    if (!o) throw new Error("No server address is configured.");
    const headers: Record<string, string> = { "X-HR": "1", Accept: "application/json" };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const t = await this.getToken();
    if (t) headers["Authorization"] = `Bearer ${t}`;
    return fetch(o + path, {
      method,
      headers,
      body: body === undefined ? null : JSON.stringify(body),
      credentials: "omit",
      mode: "cors",
      cache: "no-store",
      redirect: "error",
      referrerPolicy: "no-referrer",
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  }

  wsURL(): string {
    if (!this.serverOrigin) throw new Error("No server address is configured.");
    return wsFromOrigin(this.serverOrigin);
  }

  async wsAuthMessage(): Promise<Record<string, unknown>> {
    const t = await this.getToken();
    return t ? { type: "auth", token: t } : { type: "auth" };
  }

  async hasToken(): Promise<boolean> {
    return (await this.getToken()) !== null;
  }

  async setToken(token: string): Promise<void> {
    await this.invoke("token_set", { token });
    this.token = token;
  }

  async clearToken(): Promise<void> {
    this.token = null;
    await this.invoke("token_clear");
  }

  async openURL(url: string): Promise<void> {
    await this.invoke("open_url", { url });
  }

  pinnedHost(): Promise<Bytes | null> {
    return readPin(this.serverOrigin);
  }

  async pinHost(hostPub: Uint8Array): Promise<void> {
    if (!this.serverOrigin) throw new Error("No server address is configured.");
    await kvSet(pinKey(this.serverOrigin), b64(hostPub));
  }

  async forgetHost(): Promise<void> {
    if (this.serverOrigin) await kvDel(pinKey(this.serverOrigin));
  }
}

export function detectPlatform(): Platform {
  const inv = tauriInvoke();
  return inv ? new TauriPlatform(inv) : new BrowserPlatform();
}
