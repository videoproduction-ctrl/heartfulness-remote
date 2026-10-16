// WebAuthn JSON ⇄ ArrayBuffer conversions.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, utf8 } from "../src/b64";
import { type CredentialLike, creationOptionsFromJSON, credentialToJSON, requestOptionsFromJSON, webauthnB64 } from "../src/webauthn";

const bytes = (b: ArrayBuffer | ArrayBufferView | BufferSource | undefined) => {
  assert.ok(b instanceof ArrayBuffer, "expected an ArrayBuffer");
  return [...new Uint8Array(b)];
};

test("creation options from go-webauthn JSON", () => {
  const challenge = new Uint8Array([1, 2, 3, 250, 251, 252]);
  const userId = utf8("owner-1");
  const json = {
    publicKey: {
      rp: { name: "Heartfulness Remote", id: "remote.example.test" },
      user: { id: b64(userId), name: "owner", displayName: "Owner" },
      challenge: b64(challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      timeout: 300000,
      excludeCredentials: [{ type: "public-key", id: b64(new Uint8Array([9, 9])), transports: ["internal", "hybrid"] }],
      authenticatorSelection: { residentKey: "required", userVerification: "preferred" },
      attestation: "none",
    },
  };
  const o = creationOptionsFromJSON(json);
  assert.deepEqual(bytes(o.challenge), [...challenge]);
  assert.deepEqual(bytes(o.user.id), [...userId]);
  assert.equal(o.user.name, "owner");
  assert.equal(o.rp.id, "remote.example.test");
  assert.equal(o.timeout, 300000);
  assert.equal(o.excludeCredentials?.length, 1);
  assert.deepEqual(bytes(o.excludeCredentials![0]!.id), [9, 9]);
  assert.deepEqual(o.excludeCredentials![0]!.transports, ["internal", "hybrid"]);
  // User verification is always required (no passwords, no UV-less passkeys).
  assert.equal(o.authenticatorSelection?.userVerification, "required");
  assert.equal(o.authenticatorSelection?.residentKey, "required");
  // Bare options (no publicKey wrapper) are accepted too.
  const bare = creationOptionsFromJSON(json.publicKey);
  assert.deepEqual(bytes(bare.challenge), [...challenge]);
  assert.throws(() => creationOptionsFromJSON({ publicKey: { rp: {}, user: { id: "AA" } } }), /challenge/);
});

test("request options for a discoverable login", () => {
  const ch = new Uint8Array(32).fill(7);
  const o = requestOptionsFromJSON({ publicKey: { challenge: b64(ch), rpId: "remote.example.test", timeout: 60000, allowCredentials: null } });
  assert.deepEqual(bytes(o.challenge), [...ch]);
  assert.equal(o.userVerification, "required");
  assert.equal(o.rpId, "remote.example.test");
  assert.equal("allowCredentials" in o, false);
  const withAllow = requestOptionsFromJSON({ challenge: b64(ch), allowCredentials: [{ type: "public-key", id: "AQI" }] });
  assert.deepEqual(bytes(withAllow.allowCredentials![0]!.id), [1, 2]);
});

test("lenient base64 for WebAuthn fields (padding / std alphabet tolerated)", () => {
  assert.deepEqual([...new Uint8Array(webauthnB64("+/8=", "x"))], [0xfb, 0xff]);
  assert.deepEqual([...new Uint8Array(webauthnB64("-_8", "x"))], [0xfb, 0xff]);
  assert.throws(() => webauthnB64(undefined, "challenge"), /challenge/);
});

function ab(...v: number[]): ArrayBuffer {
  return new Uint8Array(v).buffer;
}

test("registration credential to JSON", () => {
  const cred: CredentialLike = {
    id: "AQID",
    rawId: ab(1, 2, 3),
    type: "public-key",
    authenticatorAttachment: "platform",
    response: {
      clientDataJSON: ab(123, 125),
      attestationObject: ab(0xa0),
      getTransports: () => ["internal", "hybrid"],
    },
    getClientExtensionResults: () => ({ credProps: { rk: true }, blob: ab(255) }),
  };
  const j = credentialToJSON(cred);
  assert.deepEqual(j, {
    id: "AQID",
    rawId: "AQID",
    type: "public-key",
    authenticatorAttachment: "platform",
    response: { clientDataJSON: "e30", attestationObject: "oA", transports: ["internal", "hybrid"] },
    clientExtensionResults: { credProps: { rk: true }, blob: "_w" },
  });
  // JSON-serialisable.
  assert.equal(typeof JSON.stringify(j), "string");
});

test("authentication credential to JSON", () => {
  const cred: CredentialLike = {
    id: "BAU",
    rawId: ab(4, 5),
    type: "public-key",
    response: {
      clientDataJSON: ab(1),
      authenticatorData: ab(2, 3),
      signature: ab(4, 5, 6),
      userHandle: ab(7),
    },
  };
  assert.deepEqual(credentialToJSON(cred), {
    id: "BAU",
    rawId: "BAU",
    type: "public-key",
    response: { clientDataJSON: "AQ", authenticatorData: "AgM", signature: "BAUG", userHandle: "Bw" },
    clientExtensionResults: {},
  });
  const noHandle = credentialToJSON({ ...cred, response: { ...cred.response, userHandle: null } });
  assert.equal("userHandle" in (noHandle["response"] as object), false);
});
