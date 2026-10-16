// HR1 crypto checked against the cross-language vectors (testdata/vectors.json).
import { test } from "node:test";
import assert from "node:assert/strict";
import vectors from "../../testdata/vectors.json";
import { b64, bytes, hex, toBytes, unb64, utf8 } from "../src/b64";
import {
  LABEL,
  type ApprovalRequest,
  type SessionBinding,
  checkApprovalRequest,
  claimCommit,
  fingerprint,
  formatSAS,
  freshTimestamp,
  int,
  pairCommit,
  parseApprovalNeeded,
  parsePairChallenge,
  sas,
  sdpFingerprint,
  setupKeys,
  setupMac,
  sha256Text,
  signClientAuth,
  signKillRequest,
  signOffer,
  signPairApprove,
  signRevokeRequest,
  tbs,
  verify,
  verifyAnswer,
  verifyCert,
  verifyPairChallenge,
} from "../src/hr1";
import { signerFromSeed } from "./helpers";

const V = vectors;
const I = V.inputs;
const hostPub = unb64(V.hostPub);
const devicePub = unb64(V.devicePub);
const host = () => signerFromSeed(V.hostSeedHex, hostPub);
const device = () => signerFromSeed(V.deviceSeedHex, devicePub);
const vec = (label: string) => {
  const v = V.tbs.find((t) => t.label === label);
  assert.ok(v, `vector ${label} present`);
  return v;
};

test("TBS layout is unambiguous (matches Go TestTBSLayout)", () => {
  assert.deepEqual([...tbs("L", utf8("ab"), bytes(0))], [0x4c, 0, 0, 0, 0, 2, 0x61, 0x62, 0, 0, 0, 0]);
  assert.notEqual(hex(tbs("L", utf8("ab"), utf8("c"))), hex(tbs("L", utf8("a"), utf8("bc"))));
  assert.equal(new TextDecoder().decode(int(1760000000)), "1760000000");
  assert.equal(new TextDecoder().decode(int(-5)), "-5");
  assert.throws(() => int(1.5));
});

test("every TBS vector encodes byte-identically", () => {
  assert.equal(V.tbs.length, 8);
  for (const tv of V.tbs) {
    const fields = tv.fieldsB64.map(unb64);
    assert.equal(hex(tbs(tv.label, ...fields)), tv.tbsHex, tv.label);
  }
});

test("every vector signature verifies with the right key, and only that key", async () => {
  for (const tv of V.tbs) {
    const fields = tv.fieldsB64.map(unb64);
    const key = tv.signer === "device" ? devicePub : hostPub;
    const other = tv.signer === "device" ? hostPub : devicePub;
    const sig = unb64(tv.sig);
    assert.equal(await verify(key, sig, tv.label, ...fields), true, `${tv.label} verifies`);
    assert.equal(await verify(other, sig, tv.label, ...fields), false, `${tv.label} wrong key`);
    const bad = toBytes(sig);
    bad[10]! ^= 1;
    assert.equal(await verify(key, bad, tv.label, ...fields), false, `${tv.label} tampered sig`);
    assert.equal(await verify(key, sig, tv.label + "x", ...fields), false, `${tv.label} label bound`);
    if (fields.length > 0) {
      const f0 = toBytes(fields[0]!);
      f0[0]! ^= 1;
      assert.equal(await verify(key, sig, tv.label, f0, ...fields.slice(1)), false, `${tv.label} field bound`);
    }
    assert.equal(await verify(key.subarray(0, 31), sig, tv.label, ...fields), false, "short key rejected");
  }
});

test("deterministic Ed25519 signing reproduces the vector signatures", async () => {
  const h = await host();
  const d = await device();
  for (const tv of V.tbs) {
    const fields = tv.fieldsB64.map(unb64);
    const s = tv.signer === "device" ? d : h;
    assert.equal(b64(await s.sign(tbs(tv.label, ...fields))), tv.sig, tv.label);
  }
});

test("pair commit, SAS and fingerprint", async () => {
  const nd = unb64(I.nd);
  const na = unb64(I.na);
  assert.equal(b64(await pairCommit(devicePub, nd)), V.pairCommit);
  const s = await sas(hostPub, devicePub, nd, na);
  assert.equal(s, V.sas);
  assert.match(s, /^\d{6}$/);
  assert.equal(formatSAS("123456"), "123 456");
  assert.equal(formatSAS(V.sas), `${V.sas.slice(0, 3)} ${V.sas.slice(3)}`);
  assert.equal(await fingerprint(hostPub), V.hostFingerprint);
  // Different na → (almost certainly) different SAS.
  const na2 = toBytes(na);
  na2[0]! ^= 0xff;
  assert.notEqual(await sas(hostPub, devicePub, nd, na2), V.sas);
});

test("setup keys, claim commit and setup MAC", async () => {
  const { kc, ka } = await setupKeys(unb64(V.setup.t));
  assert.equal(b64(kc), V.setup.kc);
  assert.equal(b64(ka), V.setup.ka);
  assert.equal(b64(await claimCommit(kc)), V.setup.claimCommit);
  const mac = await setupMac(ka, hostPub, devicePub, V.setup.name, V.setup.kind);
  assert.equal(b64(mac), V.setup.setupMac);
  // Kc must not produce the setup MAC.
  assert.notEqual(b64(await setupMac(kc, hostPub, devicePub, V.setup.name, V.setup.kind)), V.setup.setupMac);
  await assert.rejects(setupKeys(bytes(31)));
});

test("cert verification", async () => {
  const c = await verifyCert(V.cert, hostPub, devicePub);
  assert.equal(c.name, "Phone ✓");
  await assert.rejects(verifyCert({ ...V.cert, name: "Phone x" }, hostPub), /signature/);
  await assert.rejects(verifyCert({ ...V.cert, issuedAt: 1760000001 }, hostPub), /signature/);
  await assert.rejects(verifyCert(V.cert, devicePub), /different host/);
  await assert.rejects(verifyCert(V.cert, hostPub, hostPub), /different device/);
  await assert.rejects(verifyCert({ ...V.cert, sig: V.cert.sig.slice(2) }, hostPub));
  await assert.rejects(verifyCert({ ...V.cert, issuedAt: "1760000000" }, hostPub));
  await assert.rejects(verifyCert(null, hostPub));
});

test("SDP fingerprint rule: exactly one distinct sha-256 fingerprint", () => {
  assert.equal(sdpFingerprint(I.offerSdp), "AA:BB");
  assert.equal(sdpFingerprint(I.answerSdp), "CC:DD");
  assert.equal(sdpFingerprint("v=0\r\na=fingerprint:sha-256 aa:bb\r\nm=video\r\na=fingerprint:sha-256 AA:BB\r\n"), "AA:BB");
  assert.equal(sdpFingerprint("v=0\na=fingerprint:SHA-256 AA:BB\n"), "AA:BB");
  for (const bad of [
    "v=0\r\n",
    "",
    "a=fingerprint:sha-1 AA\r\n",
    "a=fingerprint:sha-256 AA\r\na=fingerprint:sha-256 BB\r\n",
    "a=fingerprint:sha-256 AA\r\na=fingerprint:sha-1 BB\r\n",
    "a=fingerprint:sha-256\r\n",
  ]) {
    assert.throws(() => sdpFingerprint(bad), `rejects ${JSON.stringify(bad)}`);
  }
});

function binding(): SessionBinding {
  return {
    sessionId: unb64(I.sessionId),
    hostPub,
    devicePub,
    clientNonce: unb64(I.clientNonce),
    hostNonce: unb64(I.hostNonce),
  };
}

test("offer signing reproduces the vector and covers H(offerSdp)", async () => {
  const sig = await signOffer(await device(), binding(), I.offerSdp);
  assert.equal(b64(sig), vec(LABEL.offer).sig);
  assert.equal(b64(await sha256Text(I.offerSdp)), vec(LABEL.offer).fieldsB64[5]);
  await assert.rejects(signOffer(await device(), binding(), "v=0\r\n"), /fingerprint/);
});

test("answer verification: pinned key, nonces, both SDP hashes, fingerprint rule", async () => {
  const sig = unb64(vec(LABEL.answer).sig);
  await verifyAnswer(binding(), I.offerSdp, I.answerSdp, sig);
  // Tampered answer SDP (e.g. a server swapping the DTLS fingerprint).
  await assert.rejects(verifyAnswer(binding(), I.offerSdp, I.answerSdp.replace("CC:DD", "CC:DE"), sig), /signed/);
  // Different offer.
  await assert.rejects(verifyAnswer(binding(), I.offerSdp.replace("AA", "AB"), I.answerSdp, sig), /signed/);
  // Wrong pinned host key.
  await assert.rejects(verifyAnswer({ ...binding(), hostPub: devicePub }, I.offerSdp, I.answerSdp, sig), /signed/);
  // Replayed into another session / with other nonces.
  const other = toBytes(unb64(I.hostNonce));
  other[0]! ^= 1;
  await assert.rejects(verifyAnswer({ ...binding(), hostNonce: other }, I.offerSdp, I.answerSdp, sig), /signed/);
  // An answer with two distinct fingerprints is rejected before signature checks.
  await assert.rejects(
    verifyAnswer(binding(), I.offerSdp, I.answerSdp + "a=fingerprint:sha-256 EE:FF\r\n", sig),
    /fingerprint/,
  );
});

test("pair challenge, approval check and pair-approve signature", async () => {
  const ch = vec(LABEL.pairChallenge);
  const msg = {
    type: "pair-challenge",
    requestId: I.requestId,
    hostPub: V.hostPub,
    na: I.na,
    sig: ch.sig,
  };
  const p = parsePairChallenge(msg);
  const commit = unb64(V.pairCommit);
  assert.equal(await verifyPairChallenge(p.hostPub, p.sig, p.requestId, commit, p.na), true);
  assert.equal(await verifyPairChallenge(devicePub, p.sig, p.requestId, commit, p.na), false);
  assert.throws(() => parsePairChallenge({ ...msg, na: "AAAA" }));

  const approval: ApprovalRequest = parseApprovalNeeded({
    type: "approval-needed",
    requestId: I.requestId,
    name: "Chrome on Windows",
    kind: "browser",
    devicePub: V.devicePub,
    nd: I.nd,
    commit: V.pairCommit,
    na: I.na,
    hostSig: ch.sig,
  });
  assert.equal(await checkApprovalRequest(hostPub, approval), V.sas);
  // Unpinned host key → rejected.
  await assert.rejects(checkApprovalRequest(devicePub, approval), /not signed/);
  // Revealed key does not match the commitment → rejected.
  const nd2 = toBytes(approval.nd);
  nd2[0]! ^= 1;
  await assert.rejects(checkApprovalRequest(hostPub, { ...approval, nd: nd2 }), /commitment/);

  // The approving device signs exactly the vector transcript.
  const sig = await signPairApprove(await device(), hostPub, approval);
  assert.equal(b64(sig), vec(LABEL.pairApprove).sig);
});

test("client-auth, revoke-request and kill-request signatures", async () => {
  const d = await device();
  assert.equal(b64(await signClientAuth(d, I.origin, unb64(I.nonce))), vec(LABEL.clientAuth).sig);
  assert.equal(b64(await signRevokeRequest(d, hostPub, devicePub, 1760000000)), vec(LABEL.revokeRequest).sig);
  assert.equal(b64(await signKillRequest(d, hostPub, "kill", 1760000000)), vec(LABEL.killRequest).sig);
});

test("timestamp freshness (±300 s)", () => {
  assert.equal(freshTimestamp(1100, 1000), true);
  assert.equal(freshTimestamp(1400, 1000), false);
  assert.equal(freshTimestamp(600, 1000), false);
  assert.equal(freshTimestamp(1300, 1000), true);
});
