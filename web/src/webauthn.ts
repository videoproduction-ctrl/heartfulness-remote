// WebAuthn JSON ⇄ ArrayBuffer conversions, done by hand on purpose (we do not
// rely on PublicKeyCredential.parseCreationOptionsFromJSON, which is missing
// in older Safari/Firefox). Server JSON uses base64url for binary fields.

import { b64, toBytes, unb64 } from "./b64";

type Json = Record<string, unknown>;

function obj(v: unknown, what: string): Json {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error(`Passkey options: ${what} is missing.`);
  return v as Json;
}

/** Lenient base64url decode for WebAuthn fields (tolerates padding and the standard alphabet). */
export function webauthnB64(s: unknown, what: string): ArrayBuffer {
  if (typeof s !== "string") throw new Error(`Passkey options: ${what} is missing.`);
  const clean = s.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
  return unb64(clean).buffer;
}

function descriptors(list: unknown, what: string): PublicKeyCredentialDescriptor[] | undefined {
  if (list === undefined || list === null) return undefined;
  if (!Array.isArray(list)) throw new Error(`Passkey options: ${what} is malformed.`);
  return list.map((d, i) => {
    const o = obj(d, `${what}[${i}]`);
    const out: PublicKeyCredentialDescriptor = {
      type: "public-key",
      id: webauthnB64(o["id"], `${what}[${i}].id`),
    };
    if (Array.isArray(o["transports"])) out.transports = o["transports"].filter((t): t is AuthenticatorTransport => typeof t === "string");
    return out;
  });
}

/** Accepts either {publicKey:{…}} (go-webauthn CredentialCreation) or the bare options. */
function unwrap(json: unknown): Json {
  const o = obj(json, "options");
  return o["publicKey"] && typeof o["publicKey"] === "object" ? obj(o["publicKey"], "publicKey") : o;
}

export function creationOptionsFromJSON(json: unknown): PublicKeyCredentialCreationOptions {
  const o = unwrap(json);
  const user = obj(o["user"], "user");
  const rp = obj(o["rp"], "rp");
  const out: PublicKeyCredentialCreationOptions = {
    ...(o as object),
    rp: rp as unknown as PublicKeyCredentialRpEntity,
    user: {
      ...(user as object),
      id: webauthnB64(user["id"], "user.id"),
      name: String(user["name"] ?? ""),
      displayName: String(user["displayName"] ?? user["name"] ?? ""),
    },
    challenge: webauthnB64(o["challenge"], "challenge"),
    pubKeyCredParams: Array.isArray(o["pubKeyCredParams"])
      ? (o["pubKeyCredParams"] as PublicKeyCredentialParameters[])
      : [
          { type: "public-key", alg: -8 },
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
  };
  const ex = descriptors(o["excludeCredentials"], "excludeCredentials");
  if (ex) out.excludeCredentials = ex;
  else delete (out as Partial<PublicKeyCredentialCreationOptions>).excludeCredentials;
  // Passkeys must verify the user (biometrics / device PIN).
  const sel = (o["authenticatorSelection"] && typeof o["authenticatorSelection"] === "object" ? o["authenticatorSelection"] : {}) as AuthenticatorSelectionCriteria;
  out.authenticatorSelection = { ...sel, userVerification: "required", residentKey: sel.residentKey ?? "required", requireResidentKey: true };
  return out;
}

export function requestOptionsFromJSON(json: unknown): PublicKeyCredentialRequestOptions {
  const o = unwrap(json);
  const out: PublicKeyCredentialRequestOptions = {
    ...(o as object),
    challenge: webauthnB64(o["challenge"], "challenge"),
    userVerification: "required",
  };
  const allow = descriptors(o["allowCredentials"], "allowCredentials");
  if (allow) out.allowCredentials = allow;
  else delete (out as Partial<PublicKeyCredentialRequestOptions>).allowCredentials;
  return out;
}

function bufToB64(v: unknown): string {
  if (v instanceof ArrayBuffer) return b64(v);
  if (ArrayBuffer.isView(v)) return b64(toBytes(v));
  throw new Error("Passkey response is malformed.");
}

/** Recursively replaces ArrayBuffers by base64url strings (for extension results). */
function jsonSafe(v: unknown, depth = 0): unknown {
  if (depth > 8) return null;
  if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return bufToB64(v);
  if (Array.isArray(v)) return v.map((x) => jsonSafe(x, depth + 1));
  if (v && typeof v === "object") {
    const out: Json = {};
    for (const [k, x] of Object.entries(v)) out[k] = jsonSafe(x, depth + 1);
    return out;
  }
  return v;
}

/** The structural subset of PublicKeyCredential we serialise (eases testing). */
export interface CredentialLike {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  authenticatorAttachment?: string | null;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject?: ArrayBuffer;
    getTransports?: () => string[];
    authenticatorData?: ArrayBuffer;
    signature?: ArrayBuffer;
    userHandle?: ArrayBuffer | null;
  };
  getClientExtensionResults?: () => unknown;
}

/** Serialises a registration or authentication credential to the WebAuthn JSON format. */
export function credentialToJSON(cred: CredentialLike): Json {
  const r = cred.response;
  const response: Json = { clientDataJSON: bufToB64(r.clientDataJSON) };
  if (r.attestationObject !== undefined) {
    response["attestationObject"] = bufToB64(r.attestationObject);
    let transports: string[] = [];
    try {
      transports = typeof r.getTransports === "function" ? r.getTransports() : [];
    } catch {
      transports = [];
    }
    response["transports"] = transports;
  } else {
    response["authenticatorData"] = bufToB64(r.authenticatorData);
    response["signature"] = bufToB64(r.signature);
    if (r.userHandle !== undefined && r.userHandle !== null && r.userHandle.byteLength > 0) {
      response["userHandle"] = bufToB64(r.userHandle);
    }
  }
  const out: Json = {
    id: cred.id,
    rawId: bufToB64(cred.rawId),
    type: cred.type,
    response,
    clientExtensionResults: jsonSafe(typeof cred.getClientExtensionResults === "function" ? cred.getClientExtensionResults() : {}) ?? {},
  };
  if (cred.authenticatorAttachment) out["authenticatorAttachment"] = cred.authenticatorAttachment;
  return out;
}

export function webauthnAvailable(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function" && !!navigator.credentials;
}

function explain(e: unknown): Error {
  const name = e instanceof DOMException ? e.name : "";
  if (name === "NotAllowedError") return new Error("The passkey request was cancelled or timed out.");
  if (name === "InvalidStateError") return new Error("This passkey already exists on this device.");
  if (name === "SecurityError") return new Error("Passkeys need a secure (https) connection to the right address.");
  if (name === "NotSupportedError") return new Error("This device doesn't support passkeys.");
  return e instanceof Error ? e : new Error("Passkey error.");
}

export async function createPasskey(optionsJSON: unknown): Promise<Json> {
  const publicKey = creationOptionsFromJSON(optionsJSON);
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (e) {
    throw explain(e);
  }
  if (!cred) throw new Error("No passkey was created.");
  return credentialToJSON(cred as unknown as CredentialLike);
}

export async function getPasskey(optionsJSON: unknown): Promise<Json> {
  const publicKey = requestOptionsFromJSON(optionsJSON);
  let cred: Credential | null;
  try {
    cred = await navigator.credentials.get({ publicKey });
  } catch (e) {
    throw explain(e);
  }
  if (!cred) throw new Error("No passkey was selected.");
  return credentialToJSON(cred as unknown as CredentialLike);
}
