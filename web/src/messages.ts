// Routed signaling messages that target one Mac (PROTOCOL.md §7.3 + §10.3).
// Every client→server message that targets a Mac carries that Mac's `hostPub`;
// offer / ice / session-end also carry `sessionId` (the server maps it).
// The server fills `devicePub` / `requestId` from the authenticated connection.

import { type Bytes, b64 } from "./b64";
import { type ApprovalRequest, signKillRequest, signPairApprove, signRevokeRequest, type Signer } from "./hr1";
import type { Msg } from "./signal";

export function pairStartMsg(hostPub: string, name: string, kind: string, commit: Uint8Array): Msg {
  return { type: "pair-start", hostPub, name, kind, commit: b64(commit) };
}

/** pair-reveal is matched by requestId; §10.3 does not add hostPub to it. */
export function pairRevealMsg(requestId: string, devicePub: Uint8Array, nd: Uint8Array): Msg {
  return { type: "pair-reveal", requestId, devicePub: b64(devicePub), nd: b64(nd) };
}

/** Signs HR1/pair-approve with the approving Mac's PINNED key. */
export async function pairApproveMsg(signer: Signer, pinnedHostPub: Bytes, req: ApprovalRequest): Promise<Msg> {
  const sig = await signPairApprove(signer, pinnedHostPub, req);
  return { type: "pair-approve", hostPub: b64(pinnedHostPub), requestId: b64(req.requestId), approverPub: b64(signer.pub), sig: b64(sig) };
}

export function pairDenyMsg(hostPub: string, requestId: string): Msg {
  return { type: "pair-deny", hostPub, requestId };
}

export function sessionRequestMsg(hostPub: string, sessionId: string, devicePub: Uint8Array, clientNonce: Uint8Array, relayOnly: boolean): Msg {
  const m: Msg = { type: "session-request", hostPub, sessionId, devicePub: b64(devicePub), clientNonce: b64(clientNonce) };
  if (relayOnly) m["relayOnly"] = true;
  return m;
}

export function offerMsg(hostPub: string, sessionId: string, sdp: string, sig: Uint8Array): Msg {
  return { type: "offer", hostPub, sessionId, sdp, sig: b64(sig) };
}

export function iceMsg(hostPub: string, sessionId: string, candidate: RTCIceCandidateInit | null): Msg {
  return { type: "ice", hostPub, sessionId, candidate };
}

export function sessionEndMsg(hostPub: string, sessionId: string, reason: string): Msg {
  return { type: "session-end", hostPub, sessionId, reason };
}

/** HR1/revoke-request(hostPub, targetPub, ts), sent to that Mac. */
export async function revokeRequestMsg(signer: Signer, hostPub: Bytes, targetPub: Bytes, ts: number): Promise<Msg> {
  const sig = await signRevokeRequest(signer, hostPub, targetPub, ts);
  return { type: "revoke-request", hostPub: b64(hostPub), targetPub: b64(targetPub), ts, approverPub: b64(signer.pub), sig: b64(sig) };
}

/** HR1/kill-request(hostPub, action, ts), sent to that Mac. */
export async function killRequestMsg(signer: Signer, hostPub: Bytes, action: "kill" | "resume", ts: number): Promise<Msg> {
  const sig = await signKillRequest(signer, hostPub, action, ts);
  return { type: "kill-request", hostPub: b64(hostPub), action, ts, approverPub: b64(signer.pub), sig: b64(sig) };
}

/**
 * True if a server→client message is about the Mac `hostPub`: it names that
 * Mac, or (older single-Mac servers) names none. A message naming another Mac
 * never matches. Routing data only — authenticity always comes from
 * signatures checked with the pinned key.
 */
export function aboutMac(m: Record<string, unknown>, hostPub: string): boolean {
  const hp = m["hostPub"];
  return hp === undefined || hp === hostPub;
}
