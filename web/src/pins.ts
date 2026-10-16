// Pinned Mac (host) keys, one map per server origin (PROTOCOL.md §10).
//
// A host key is pinned only when it is known to be authentic: it came from
// the Mac's own screen (setup QR), was confirmed with the SAS during pairing
// plus a valid certificate, or was confirmed by the join hostMac. Everything
// that talks to a Mac (session answers, approval requests) is verified with
// THAT Mac's pin — never with a key the server supplies.
//
// Storage: kv["hosts@<origin>"] = {v:1, hosts:{<b64 hostPub>: {name, macId, pinnedAt}}}.
// Older versions stored a single pin as kv["hostPub@<origin>"] = <b64 hostPub>;
// it is migrated transparently on first load.

import { b64, unb64Len } from "./b64";
import { macId as computeMacId, PUB_SIZE } from "./hr1";

export interface Pin {
  /** Display name when pinned (the live name comes from the server). */
  name: string;
  /** 9-digit Mac ID, computed locally from the key. */
  macId: string;
  /** Unix seconds. */
  pinnedAt: number;
}

/** b64 host key → pin. Keys are canonical b64 of 32-byte keys. */
export type PinMap = Map<string, Pin>;

/** Minimal async key/value store (IndexedDB in the app, a Map in tests). */
export interface KV {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
}

/** Serialises read-modify-write cycles (e.g. Web Locks across tabs). */
export type Lock = <T>(fn: () => Promise<T>) => Promise<T>;

const noLock: Lock = (fn) => fn();

export const pinsKey = (origin: string) => `hosts@${origin}`;
export const legacyPinKey = (origin: string) => `hostPub@${origin}`;

interface Stored {
  v: 1;
  hosts: Record<string, Pin>;
}

const MAX_NAME = 200;

function canonicalPub(k: string): string | null {
  try {
    return b64(unb64Len(k, PUB_SIZE));
  } catch {
    return null;
  }
}

async function parse(raw: unknown): Promise<PinMap> {
  const out: PinMap = new Map();
  if (!raw || typeof raw !== "object") return out;
  const hosts = (raw as { hosts?: unknown }).hosts;
  if (!hosts || typeof hosts !== "object") return out;
  for (const [k, v] of Object.entries(hosts as Record<string, unknown>)) {
    const pub = canonicalPub(k);
    if (!pub || out.has(pub)) continue;
    const o = v && typeof v === "object" ? (v as Record<string, unknown>) : {};
    const name = typeof o["name"] === "string" ? o["name"].slice(0, MAX_NAME) : "";
    const pinnedAt = typeof o["pinnedAt"] === "number" && Number.isFinite(o["pinnedAt"]) ? o["pinnedAt"] : 0;
    // The Mac ID is cheap to recompute; never trust a stored one blindly.
    const id = await computeMacId(unb64Len(pub, PUB_SIZE));
    out.set(pub, { name, macId: id, pinnedAt });
  }
  return out;
}

function serialise(m: PinMap): Stored {
  const hosts: Record<string, Pin> = {};
  for (const [k, v] of m) hosts[k] = { name: v.name, macId: v.macId, pinnedAt: v.pinnedAt };
  return { v: 1, hosts };
}

function nowS(): number {
  return Math.floor(Date.now() / 1000);
}

export class PinStore {
  constructor(
    private readonly kv: KV,
    private readonly origin: string,
    private readonly lock: Lock = noLock,
  ) {}

  /** All pins for this origin; migrates the old single-pin format on the way. */
  load(): Promise<PinMap> {
    return this.lock(async () => {
      const map = await parse(await this.kv.get<unknown>(pinsKey(this.origin)));
      const legacy = await this.kv.get<unknown>(legacyPinKey(this.origin));
      if (legacy !== undefined) {
        const pub = typeof legacy === "string" ? canonicalPub(legacy) : null;
        if (pub && !map.has(pub)) {
          map.set(pub, { name: "", macId: await computeMacId(unb64Len(pub, PUB_SIZE)), pinnedAt: nowS() });
        }
        // Write the new format first, then drop the old key (never lose a pin).
        await this.kv.set(pinsKey(this.origin), serialise(map));
        await this.kv.del(legacyPinKey(this.origin));
      }
      return map;
    });
  }

  /** Pins (or re-pins) a host key. Returns the updated map. */
  add(hostPub: Uint8Array, name: string): Promise<PinMap> {
    return this.lock(async () => {
      if (hostPub.length !== PUB_SIZE) throw new Error("host key must be 32 bytes");
      const map = await parse(await this.kv.get<unknown>(pinsKey(this.origin)));
      const k = b64(hostPub);
      const prev = map.get(k);
      map.set(k, {
        name: name.slice(0, MAX_NAME) || prev?.name || "",
        macId: await computeMacId(hostPub),
        pinnedAt: prev?.pinnedAt || nowS(),
      });
      await this.kv.set(pinsKey(this.origin), serialise(map));
      return map;
    });
  }

  /** Forgets one host key. Returns the updated map. */
  remove(hostPubB64: string): Promise<PinMap> {
    return this.lock(async () => {
      const map = await parse(await this.kv.get<unknown>(pinsKey(this.origin)));
      const k = canonicalPub(hostPubB64);
      if (k && map.delete(k)) await this.kv.set(pinsKey(this.origin), serialise(map));
      return map;
    });
  }

  /** Forgets every pinned host key for this origin (including the old format). */
  clear(): Promise<void> {
    return this.lock(async () => {
      await this.kv.del(pinsKey(this.origin));
      await this.kv.del(legacyPinKey(this.origin));
    });
  }
}
