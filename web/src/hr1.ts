// HR1 protocol cryptography (docs/PROTOCOL.md §2–§3, §5, §7.3).
// Only composes WebCrypto primitives: Ed25519, SHA-256, HMAC-SHA256,
// HKDF-SHA256. Nothing here implements a cryptographic primitive.

import {
  type Bytes,
  base32Lower,
  bytes,
  equalBytes,
  EncodingError,
  b64,
  toBytes,
  unb64Len,
  utf8,
} from "./b64";

export const LABEL = {
  hostAuth: "HR1/host-auth",
  clientAuth: "HR1/client-auth",
  pairChallenge: "HR1/pair-challenge",
  pairApprove: "HR1/pair-approve",
  cert: "HR1/cert",
  revoked: "HR1/revoked",
  revokeRequest: "HR1/revoke-request",
  killRequest: "HR1/kill-request",
  offer: "HR1/offer",
  answer: "HR1/answer",
  pairCommit: "HR1/pair-commit",
  sas: "HR1/sas",
  setup: "HR1/setup",
  infoClaim: "HR1/claim",
  infoSetupAuth: "HR1/setup-auth",
} as const;

export const NONCE_SIZE = 32;
export const ID_SIZE = 16;
export const PUB_SIZE = 32;
export const SIG_SIZE = 64;
export const MAX_CLOCK_SKEW_S = 300;

export class ProtocolError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "ProtocolError";
  }
}

/** TBS(label, f1..fn) = UTF8(label) || 0x00 || Σ(u32be(len(fi)) || fi). */
export function tbs(label: string, ...fields: Uint8Array[]): Bytes {
  const l = utf8(label);
  let n = l.length + 1;
  for (const f of fields) n += 4 + f.length;
  const out = bytes(n);
  out.set(l, 0);
  let o = l.length;
  out[o++] = 0;
  const dv = new DataView(out.buffer);
  for (const f of fields) {
    dv.setUint32(o, f.length, false);
    o += 4;
    out.set(f, o);
    o += f.length;
  }
  return out;
}

/** Integer field: decimal ASCII (same as Go strconv.FormatInt(v, 10)). */
export function int(v: number): Bytes {
  if (!Number.isSafeInteger(v)) throw new ProtocolError("integer field out of range");
  return utf8(String(v));
}

/** Text field: UTF-8. */
export const str = utf8;

export async function sha256(data: Uint8Array): Promise<Bytes> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", toBytes(data)));
}

export async function sha256Text(s: string): Promise<Bytes> {
  return sha256(utf8(s));
}

async function importEd25519Public(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", toBytes(raw), { name: "Ed25519" }, false, ["verify"]);
}

/** Verifies an Ed25519 signature over TBS(label, fields…). Never throws. */
export async function verify(pub: Uint8Array, sig: Uint8Array, label: string, ...fields: Uint8Array[]): Promise<boolean> {
  if (pub.length !== PUB_SIZE || sig.length !== SIG_SIZE) return false;
  try {
    const key = await importEd25519Public(pub);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, toBytes(sig), tbs(label, ...fields));
  } catch {
    return false;
  }
}

/** Anything that can produce Ed25519 signatures with a device key. */
export interface Signer {
  readonly pub: Bytes;
  sign(data: Bytes): Promise<Bytes>;
}

export async function signTBS(signer: Signer, label: string, ...fields: Uint8Array[]): Promise<Bytes> {
  const sig = await signer.sign(tbs(label, ...fields));
  if (sig.length !== SIG_SIZE) throw new ProtocolError("device key returned a malformed signature");
  return sig;
}

/** pair commit = H(TBS("HR1/pair-commit", devicePub, nd)). */
export async function pairCommit(devicePub: Uint8Array, nd: Uint8Array): Promise<Bytes> {
  return sha256(tbs(LABEL.pairCommit, devicePub, nd));
}

/** SAS = u32be(H(TBS("HR1/sas", hostPub, devicePub, nd, na))[0:4]) mod 1e6, 6 digits. */
export async function sas(hostPub: Uint8Array, devicePub: Uint8Array, nd: Uint8Array, na: Uint8Array): Promise<string> {
  const h = await sha256(tbs(LABEL.sas, hostPub, devicePub, nd, na));
  const v = new DataView(h.buffer).getUint32(0, false) % 1_000_000;
  return String(v).padStart(6, "0");
}

/** "123456" → "123 456". */
export function formatSAS(s: string): string {
  return s.length === 6 ? `${s.slice(0, 3)} ${s.slice(3)}` : s;
}

async function hkdf32(ikm: Uint8Array, info: string): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", toBytes(ikm), "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: bytes(0), info: utf8(info) },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/** Kc = HKDF(T, ∅, "HR1/claim", 32); Ka = HKDF(T, ∅, "HR1/setup-auth", 32). */
export async function setupKeys(t: Uint8Array): Promise<{ kc: Bytes; ka: Bytes }> {
  if (t.length !== 32) throw new ProtocolError("setup secret must be 32 bytes");
  const [kc, ka] = await Promise.all([hkdf32(t, LABEL.infoClaim), hkdf32(t, LABEL.infoSetupAuth)]);
  return { kc, ka };
}

/** claim commit = H(Kc). */
export function claimCommit(kc: Uint8Array): Promise<Bytes> {
  return sha256(kc);
}

/** setup MAC = HMAC-SHA256(Ka, TBS("HR1/setup", hostPub, devicePub, name, kind)). */
export async function setupMac(ka: Uint8Array, hostPub: Uint8Array, devicePub: Uint8Array, name: string, kind: string): Promise<Bytes> {
  const key = await crypto.subtle.importKey("raw", toBytes(ka), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, tbs(LABEL.setup, hostPub, devicePub, str(name), str(kind)));
  return new Uint8Array(mac);
}

/** Display fingerprint: base32(H(pub)[0:10]) lowercase in groups of 4, e.g. "abcd-efgh-ijkl-mnop". */
export async function fingerprint(pub: Uint8Array): Promise<string> {
  const h = await sha256(pub);
  const s = base32Lower(h.subarray(0, 10));
  const parts: string[] = [];
  for (let i = 0; i < s.length; i += 4) parts.push(s.slice(i, i + 4));
  return parts.join("-");
}

/**
 * Returns the single DTLS sha-256 fingerprint of an SDP (upper-case).
 * Rejects SDPs without one, with several distinct ones, or with any
 * fingerprint line using another hash algorithm (PROTOCOL.md §7.3).
 */
export function sdpFingerprint(sdp: string): string {
  if (typeof sdp !== "string") throw new ProtocolError("sdp missing");
  let found = "";
  for (const raw of sdp.split("\n")) {
    const line = raw.replace(/\r+$/, "");
    if (!line.startsWith("a=fingerprint:")) continue;
    const rest = line.slice("a=fingerprint:".length);
    const sp = rest.indexOf(" ");
    if (sp < 0) throw new ProtocolError("sdp must contain exactly one distinct sha-256 fingerprint");
    const alg = rest.slice(0, sp);
    const val = rest.slice(sp + 1).trim().toUpperCase();
    if (alg.toLowerCase() !== "sha-256") throw new ProtocolError("sdp must contain exactly one distinct sha-256 fingerprint");
    if (found !== "" && found !== val) throw new ProtocolError("sdp must contain exactly one distinct sha-256 fingerprint");
    found = val;
  }
  if (found === "") throw new ProtocolError("sdp must contain exactly one distinct sha-256 fingerprint");
  return found;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

export function freshTimestamp(ts: number, now: number = nowSeconds()): boolean {
  return Number.isSafeInteger(ts) && Math.abs(now - ts) <= MAX_CLOCK_SKEW_S;
}

// ---------------------------------------------------------------- certs

export interface Cert {
  hostPub: string;
  devicePub: string;
  name: string;
  kind: string;
  issuedAt: number;
  sig: string;
}

function asRecord(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new ProtocolError(`${what}: not an object`);
  return v as Record<string, unknown>;
}

function asString(o: Record<string, unknown>, k: string): string {
  const v = o[k];
  if (typeof v !== "string") throw new ProtocolError(`field ${k} missing`);
  return v;
}

/** Field accessor for signaling messages: a b64 field of exact length. */
export function b64Field(o: Record<string, unknown>, k: string, n: number): Bytes {
  try {
    return unb64Len(asString(o, k), n);
  } catch (e) {
    if (e instanceof EncodingError) throw new ProtocolError(`field ${k}: ${e.message}`);
    throw e;
  }
}

/**
 * Verifies a host-issued device certificate against the expected (pinned or
 * SAS-confirmed) host key, and optionally the expected device key.
 */
export async function verifyCert(raw: unknown, hostPub: Uint8Array, devicePub?: Uint8Array): Promise<Cert> {
  const o = asRecord(raw, "cert");
  const hp = b64Field(o, "hostPub", PUB_SIZE);
  const dp = b64Field(o, "devicePub", PUB_SIZE);
  const sig = b64Field(o, "sig", SIG_SIZE);
  const name = asString(o, "name");
  const kind = asString(o, "kind");
  const issuedAt = o["issuedAt"];
  if (typeof issuedAt !== "number" || !Number.isSafeInteger(issuedAt)) throw new ProtocolError("cert: bad issuedAt");
  if (!equalBytes(hp, hostPub)) throw new ProtocolError("cert issued by a different host");
  if (devicePub && !equalBytes(dp, devicePub)) throw new ProtocolError("cert is for a different device");
  if (!(await verify(hostPub, sig, LABEL.cert, hp, dp, str(name), str(kind), int(issuedAt)))) {
    throw new ProtocolError("cert signature is invalid");
  }
  return { hostPub: b64(hp), devicePub: b64(dp), name, kind, issuedAt, sig: b64(sig) };
}

// ---------------------------------------------------------------- client-auth

export async function signClientAuth(signer: Signer, origin: string, nonce: Uint8Array): Promise<Bytes> {
  return signTBS(signer, LABEL.clientAuth, str(origin), nonce);
}

// ---------------------------------------------------------------- pairing (§5)

export interface PairChallenge {
  requestId: Bytes;
  hostPub: Bytes;
  na: Bytes;
  sig: Bytes;
}

export function parsePairChallenge(msg: Record<string, unknown>): PairChallenge {
  return {
    requestId: b64Field(msg, "requestId", ID_SIZE),
    hostPub: b64Field(msg, "hostPub", PUB_SIZE),
    na: b64Field(msg, "na", NONCE_SIZE),
    sig: b64Field(msg, "sig", SIG_SIZE),
  };
}

/** Host signature over HR1/pair-challenge(requestId, commit, na, hostPub). */
export function verifyPairChallenge(hostPub: Uint8Array, sig: Uint8Array, requestId: Uint8Array, commit: Uint8Array, na: Uint8Array): Promise<boolean> {
  return verify(hostPub, sig, LABEL.pairChallenge, requestId, commit, na, hostPub);
}

export interface ApprovalRequest {
  requestId: Bytes;
  name: string;
  kind: string;
  devicePub: Bytes;
  nd: Bytes;
  commit: Bytes;
  na: Bytes;
  hostSig: Bytes;
}

export function parseApprovalNeeded(msg: Record<string, unknown>): ApprovalRequest {
  return {
    requestId: b64Field(msg, "requestId", ID_SIZE),
    name: asString(msg, "name"),
    kind: asString(msg, "kind"),
    devicePub: b64Field(msg, "devicePub", PUB_SIZE),
    nd: b64Field(msg, "nd", NONCE_SIZE),
    commit: b64Field(msg, "commit", 32),
    na: b64Field(msg, "na", NONCE_SIZE),
    hostSig: b64Field(msg, "hostSig", SIG_SIZE),
  };
}

/**
 * Checks an approval-needed message with the PINNED host key: the host's
 * challenge signature, and that the revealed (devicePub, nd) matches the
 * commitment. Returns the SAS to show, or throws.
 */
export async function checkApprovalRequest(pinnedHostPub: Uint8Array, a: ApprovalRequest): Promise<string> {
  if (!(await verifyPairChallenge(pinnedHostPub, a.hostSig, a.requestId, a.commit, a.na))) {
    throw new ProtocolError("the request was not signed by your Mac");
  }
  const c = await pairCommit(a.devicePub, a.nd);
  if (!equalBytes(c, a.commit)) throw new ProtocolError("the device's key does not match its commitment");
  return sas(pinnedHostPub, a.devicePub, a.nd, a.na);
}

/** HR1/pair-approve(requestId, hostPub, devicePub, nd, na, name, kind). */
export function signPairApprove(signer: Signer, hostPub: Uint8Array, a: ApprovalRequest): Promise<Bytes> {
  return signTBS(signer, LABEL.pairApprove, a.requestId, hostPub, a.devicePub, a.nd, a.na, str(a.name), str(a.kind));
}

// ---------------------------------------------------------------- device management

export function signRevokeRequest(signer: Signer, hostPub: Uint8Array, targetPub: Uint8Array, ts: number): Promise<Bytes> {
  return signTBS(signer, LABEL.revokeRequest, hostPub, targetPub, int(ts));
}

export function signKillRequest(signer: Signer, hostPub: Uint8Array, action: "kill" | "resume", ts: number): Promise<Bytes> {
  return signTBS(signer, LABEL.killRequest, hostPub, str(action), int(ts));
}

// ---------------------------------------------------------------- sessions (§7.3)

export interface SessionBinding {
  sessionId: Uint8Array;
  hostPub: Uint8Array; // PINNED host key
  devicePub: Uint8Array;
  clientNonce: Uint8Array;
  hostNonce: Uint8Array;
}

/** Signs HR1/offer(sessionId, hostPub, devicePub, clientNonce, hostNonce, H(offerSdp)). */
export async function signOffer(signer: Signer, b: SessionBinding, offerSdp: string): Promise<Bytes> {
  sdpFingerprint(offerSdp); // never sign an SDP that violates the fingerprint rule
  const h = await sha256Text(offerSdp);
  return signTBS(signer, LABEL.offer, b.sessionId, b.hostPub, b.devicePub, b.clientNonce, b.hostNonce, h);
}

/**
 * Verifies the host's answer BEFORE it may be applied: exactly one distinct
 * sha-256 fingerprint, and a valid HR1/answer signature by the pinned host key
 * binding this session, both nonces, the exact offer and the exact answer.
 * Throws ProtocolError on any failure.
 */
export async function verifyAnswer(b: SessionBinding, offerSdp: string, answerSdp: string, sig: Uint8Array): Promise<void> {
  sdpFingerprint(answerSdp);
  const [ho, ha] = await Promise.all([sha256Text(offerSdp), sha256Text(answerSdp)]);
  const ok = await verify(b.hostPub, sig, LABEL.answer, b.sessionId, b.hostPub, b.devicePub, b.clientNonce, b.hostNonce, ho, ha);
  if (!ok) throw new ProtocolError("the answer was not signed by your Mac");
}
