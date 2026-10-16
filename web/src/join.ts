// Adding another Mac to the account ("join", PROTOCOL.md §10.2).
//
//   typed path:  GET /api/hosts/pending?macId → check macId(hostPub) == typed
//   both paths:  join/begin {hostPub, claim: Kc}  →  join/finish {flowId, setupMac(Ka)}
//                → host-joined {hostPub, cert, hostMac} → verify cert AND hostMac → pin
//
// The server learns Kc (to check the claim commit) but never T or Ka, so it can
// neither forge the setup MAC towards the Mac nor the hostMac towards us.

import { ApiError, type Api, type DeviceProof } from "./api";
import { type Bytes, b64, unb64Len } from "./b64";
import { b64Field, type Cert, joinKeys, macId, ProtocolError, PUB_SIZE, setupMac, verifyCert, verifyHostConfirmMac } from "./hr1";

export const HOST_JOINED_TIMEOUT_MS = 60_000;

export interface JoinDeps {
  api: Pick<Api, "hostsPending" | "joinBegin" | "joinFinish">;
  /** A fresh device proof (single-use nonce) per call. */
  proof(): Promise<DeviceProof>;
  devicePub: Bytes;
  /** This device's name and kind exactly as the server registered them. */
  device(): Promise<{ name: string; kind: string }>;
  /** Resolves with the `host-joined` message for that Mac. */
  hostJoined(hostPub: string, timeoutMs: number, abort?: AbortSignal): Promise<Record<string, unknown>>;
}

export type JoinErrorCode = "not-found" | "mac-id-mismatch" | "bad-code" | "expired" | "timeout";

export class JoinError extends Error {
  constructor(
    readonly code: JoinErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "JoinError";
  }
}

export interface FoundMac {
  hostPub: Bytes;
  macId: string;
  name: string;
}

export interface PreparedJoin extends FoundMac {
  flowId: string;
  /** Ka (HKDF of T). The caller wipes it when done. */
  ka: Bytes;
}

/** Typed path: looks up the waiting Mac and checks that its key really has the typed Mac ID. */
export async function findPendingMac(api: JoinDeps["api"], typedMacId: string): Promise<FoundMac> {
  let p: { hostPub: string; name: string };
  try {
    p = await api.hostsPending(typedMacId);
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 410)) {
      throw new JoinError("not-found", "No Mac with this Mac ID is waiting to be added. On the new Mac, open Heartfulness Remote and check the Mac ID it shows.");
    }
    throw e;
  }
  const hostPub = unb64Len(p.hostPub, PUB_SIZE);
  const id = await macId(hostPub);
  if (id !== typedMacId) {
    throw new JoinError("mac-id-mismatch", "Security check failed: the server answered with a different Mac than the one you typed. Nothing was added.");
  }
  return { hostPub, macId: id, name: p.name };
}

function beginError(e: unknown): unknown {
  if (!(e instanceof ApiError)) return e;
  if (e.status === 404) return new JoinError("not-found", "This Mac isn't waiting to be added any more. On the Mac, open Heartfulness Remote to show a new code.");
  if (e.status === 410) return new JoinError("expired", "The code has expired. On the Mac, open Heartfulness Remote to show a new code.");
  if (e.status === 400 || e.status === 403 || e.status === 409) {
    return new JoinError("bad-code", "The code doesn't match this Mac. Check the code on the Mac's screen and try again.");
  }
  return e;
}

/** Proves knowledge of the code to the server (claim = Kc). Wipes Kc; returns Ka for finishJoin. */
export async function beginJoin(deps: JoinDeps, hostPub: Bytes, t: Uint8Array): Promise<PreparedJoin> {
  const { kc, ka } = await joinKeys(t);
  try {
    const proof = await deps.proof();
    const flow = await deps.api.joinBegin(proof, b64(hostPub), b64(kc));
    return { hostPub, macId: await macId(hostPub), name: flow.name, flowId: flow.flowId, ka };
  } catch (e) {
    ka.fill(0);
    throw beginError(e);
  } finally {
    kc.fill(0);
  }
}

/**
 * Checks `host-joined {hostPub, cert, hostMac}`: a valid certificate for
 * exactly this device from exactly this Mac, AND hostMac = HMAC(Ka,
 * TBS("HR1/join-confirm", hostPub, devicePub)). Throws ProtocolError otherwise.
 */
export async function verifyHostJoined(msg: Record<string, unknown>, hostPub: Bytes, devicePub: Bytes, ka: Bytes): Promise<Cert> {
  if (msg["hostPub"] !== undefined && msg["hostPub"] !== b64(hostPub)) throw new ProtocolError("the confirmation came from a different Mac");
  const cert = await verifyCert(msg["cert"], hostPub, devicePub);
  const hm = b64Field(msg, "hostMac", 32);
  if (!(await verifyHostConfirmMac(ka, hostPub, devicePub, hm))) throw new ProtocolError("the Mac's confirmation code is not valid");
  return cert;
}

/** Sends the setup MAC and waits for the Mac's verified confirmation. */
export async function finishJoin(deps: JoinDeps, p: PreparedJoin, abort?: AbortSignal): Promise<Cert> {
  const hp = b64(p.hostPub);
  const dev = await deps.device();
  const mac = await setupMac(p.ka, p.hostPub, deps.devicePub, dev.name, dev.kind);
  // Listen before asking, so a fast confirmation can't be missed.
  const joined = deps.hostJoined(hp, HOST_JOINED_TIMEOUT_MS, abort);
  joined.catch(() => undefined);
  const proof = await deps.proof();
  let res: Record<string, unknown>;
  try {
    res = await deps.api.joinFinish(proof, p.flowId, b64(mac));
  } catch (e) {
    throw beginError(e);
  }
  let msg: Record<string, unknown>;
  if (res["cert"] !== undefined && res["hostMac"] !== undefined) {
    msg = res; // a server may also return the confirmation directly
  } else {
    try {
      msg = await joined;
    } catch (e) {
      if (e instanceof Error && e.message === "timeout") {
        throw new JoinError("timeout", "The Mac didn't confirm in time. Make sure it still shows the code and is connected to the internet, then try again.");
      }
      throw e;
    }
  }
  return verifyHostJoined(msg, p.hostPub, deps.devicePub, p.ka);
}
