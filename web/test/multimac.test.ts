// Multiple Macs (PROTOCOL.md §10): Mac ID, join codes, join keys, setup MAC and
// hostMac against testdata/vectors.json "join"; the pin store and its
// migration; routed message shapes; /api/me + ready normalisation; join flow.
import { test } from "node:test";
import assert from "node:assert/strict";
import vectors from "../../testdata/vectors.json";
import { Api, ApiError, normalizeMe, type DeviceProof } from "../src/api";
import { aggregateStatus, statusFromMe } from "../src/app";
import { b64, base32Upper, bytes, toBytes, unb64, unbase32 } from "../src/b64";
import { parseFragment, parseJoinFragment } from "../src/fragment";
import {
  LABEL,
  claimCommit,
  formatJoinCodeInput,
  formatMacId,
  formatMacIdInput,
  hostConfirmMac,
  joinCode,
  joinKeys,
  macId,
  normalizeJoinCode,
  parseApprovalNeeded,
  parseJoinCode,
  parseMacIdInput,
  setupKeys,
  setupMac,
  verify,
  verifyHostConfirmMac,
} from "../src/hr1";
import { beginJoin, findPendingMac, finishJoin, JoinError, type JoinDeps, verifyHostJoined } from "../src/join";
import {
  aboutMac,
  iceMsg,
  killRequestMsg,
  offerMsg,
  pairApproveMsg,
  pairDenyMsg,
  pairRevealMsg,
  pairStartMsg,
  revokeRequestMsg,
  sessionEndMsg,
  sessionRequestMsg,
} from "../src/messages";
import { type KV, legacyPinKey, PinStore, pinsKey } from "../src/pins";
import { serverRefusalText } from "../src/rtc";
import { parseReady } from "../src/signal";
import { macStatus } from "../src/views/home";
import { signerFromSeed } from "./helpers";

const V = vectors;
const J = V.join;
const I = V.inputs;
const hostPub = unb64(V.hostPub);
const devicePub = unb64(V.devicePub);
const device = () => signerFromSeed(V.deviceSeedHex, devicePub);
const vec = (label: string) => V.tbs.find((t) => t.label === label)!;

// ------------------------------------------------------------------ crypto vectors

test("Mac ID matches the Go vector and formats as 3×3 digits", async () => {
  assert.equal(await macId(hostPub), J.macId);
  assert.match(J.macId, /^\d{9}$/);
  assert.equal(formatMacId(J.macId), `${J.macId.slice(0, 3)} ${J.macId.slice(3, 6)} ${J.macId.slice(6)}`);
  assert.equal(formatMacId("12345"), "12345", "only 9-digit IDs are grouped");
  assert.notEqual(await macId(devicePub), J.macId, "depends on the key");
  await assert.rejects(macId(hostPub.subarray(0, 31)));
});

test("typed Mac IDs: spaces/dashes allowed, exactly 9 digits", () => {
  assert.equal(parseMacIdInput(" 967 244 390 "), "967244390");
  assert.equal(parseMacIdInput("967-244-390"), "967244390");
  assert.equal(parseMacIdInput("967244390"), "967244390");
  for (const bad of ["", "96724439", "9672443901", "967 244 39a", "967.244.390"]) assert.equal(parseMacIdInput(bad), null, bad);
  assert.equal(formatMacIdInput("9672"), "967 2");
  assert.equal(formatMacIdInput("967 244 3901234"), "967 244 390");
  assert.equal(formatMacIdInput("abc"), "");
});

test("join code: base32 of T in groups of 4 (Go JoinCode)", () => {
  const t = unb64(J.t);
  assert.equal(t.length, 10);
  assert.equal(joinCode(t), J.code);
  assert.match(J.code, /^[A-Z2-7]{4}(-[A-Z2-7]{4}){3}$/);
  assert.equal(base32Upper(t), J.code.replace(/-/g, ""));
});

test("join code parsing normalises like Go ParseJoinCode (case, spaces, dashes, 0→O 1→I 8→B)", () => {
  const t = b64(unb64(J.t));
  assert.equal(b64(parseJoinCode(J.code)), t);
  assert.equal(b64(parseJoinCode(J.code.toLowerCase())), t);
  assert.equal(b64(parseJoinCode(J.code.replace(/-/g, " "))), t);
  assert.equal(b64(parseJoinCode(J.code.replace(/-/g, ""))), t);
  assert.equal(b64(parseJoinCode(`\t${J.code}\t`)), t);
  assert.equal(b64(parseJoinCode(J.code.replace(/O/g, "0"))), t, "0 is read as O");
  // A code containing I and B, typed with 1 and 8.
  const ib = new Uint8Array([0x42, 0x10, 0x84, 0x21, 0x08, 0x42, 0x10, 0x84, 0x21, 0x08]); // "IIII…" pattern
  const code = joinCode(ib);
  assert.match(code, /I/);
  assert.equal(b64(parseJoinCode(code.replace(/I/g, "1"))), b64(ib));
  const bb = unbase32("BBBBBBBBBBBBBBBB");
  assert.equal(b64(parseJoinCode("8888-8888-8888-8888")), b64(bb));
  assert.equal(normalizeJoinCode("ab-c 0 1 8"), "ABCOIB");
  for (const bad of ["", "ABCD-EFGH", J.code + "A", J.code.slice(0, -1), J.code.replace("4", "9"), J.code.replace("D", "."), "AAAA-AAAA-AAAA-AAA="]) {
    assert.throws(() => parseJoinCode(bad), bad);
  }
  assert.equal(formatJoinCodeInput("4dq6fy"), "4DQ6-FY");
  assert.equal(formatJoinCodeInput(J.code.toLowerCase().replace(/-/g, " ") + "zzzz"), J.code);
  assert.equal(formatJoinCodeInput("4dq6-9.9"), "4DQ6", "characters that can't be in a code are dropped");
});

test("base32 decoding is strict", () => {
  assert.deepEqual([...unbase32("")], []);
  assert.equal(b64(unbase32(base32Upper(unb64(J.t)))), J.t);
  for (const bad of ["A", "AAA", "AAAAAA", "ab", "A1", "AB"]) assert.throws(() => unbase32(bad), bad);
  assert.deepEqual([...unbase32("AE")], [0x01]);
});

test("join keys, claim commit, setup MAC and hostMac match the Go vectors", async () => {
  const t = unb64(J.t);
  const { kc, ka } = await joinKeys(t);
  assert.equal(b64(kc), J.kc);
  assert.equal(b64(ka), J.ka);
  assert.equal(b64(await claimCommit(kc)), J.claimCommit);
  assert.equal(b64(await setupMac(ka, hostPub, devicePub, V.setup.name, V.setup.kind)), J.setupMac);
  const hm = await hostConfirmMac(ka, hostPub, devicePub);
  assert.equal(b64(hm), J.hostMac);
  assert.equal(await verifyHostConfirmMac(ka, hostPub, devicePub, hm), true);
  // Bound to Ka, hostPub, devicePub and the label; Kc can't produce it.
  const bad = toBytes(hm);
  bad[0]! ^= 1;
  assert.equal(await verifyHostConfirmMac(ka, hostPub, devicePub, bad), false);
  assert.equal(await verifyHostConfirmMac(kc, hostPub, devicePub, hm), false);
  assert.equal(await verifyHostConfirmMac(ka, devicePub, hostPub, hm), false);
  assert.equal(await verifyHostConfirmMac(ka, hostPub, devicePub, hm.subarray(0, 31)), false);
  assert.notEqual(b64(await setupMac(ka, hostPub, devicePub, V.setup.name, V.setup.kind)), b64(hm), "labels separate setup MAC and hostMac");
  // Secret sizes are not interchangeable.
  await assert.rejects(joinKeys(unb64(V.setup.t)));
  await assert.rejects(setupKeys(t));
  await assert.rejects(joinKeys(bytes(11)));
});

test("join link fragment #join=<T>.<hostPub>", () => {
  const f = parseJoinFragment(`#join=${J.t}.${V.hostPub}`);
  assert.ok(f && f !== "invalid");
  assert.equal(b64(f.t), J.t);
  assert.equal(b64(f.hostPub), V.hostPub);
  assert.equal(parseJoinFragment("#setup=x"), null);
  for (const bad of ["#join=", `#join=${J.t}`, `#join=${V.setup.t}.${V.hostPub}`, `#join=${J.t}.AAAA`, `#join=${J.t}.${V.hostPub}.x`]) {
    assert.equal(parseJoinFragment(bad), "invalid", bad);
  }
  assert.deepEqual(parseFragment(`#join=${J.t}`), { kind: "invalid", of: "join" });
  assert.equal(parseFragment(`#join=${J.t}.${V.hostPub}`)?.kind, "join");
  assert.equal(parseFragment(`#setup=${V.setup.t}.${V.hostPub}`)?.kind, "setup");
  assert.deepEqual(parseFragment("#setup=zz"), { kind: "invalid", of: "setup" });
  assert.equal(parseFragment("#session"), null);
});

// ------------------------------------------------------------------ pins

function memKV(init: Record<string, unknown> = {}): KV & { data: Map<string, unknown> } {
  const data = new Map<string, unknown>(Object.entries(init));
  return {
    data,
    async get<T>(k: string) {
      return structuredClone(data.get(k)) as T | undefined;
    },
    async set(k: string, v: unknown) {
      data.set(k, structuredClone(v));
    },
    async del(k: string) {
      data.delete(k);
    },
  };
}

const ORIGIN = "https://hr.example.test";

test("the old single pin is migrated transparently (and only once)", async () => {
  const kv = memKV({ [legacyPinKey(ORIGIN)]: V.hostPub, [legacyPinKey("https://other.test")]: V.devicePub });
  const store = new PinStore(kv, ORIGIN);
  const pins = await store.load();
  assert.deepEqual([...pins.keys()], [V.hostPub]);
  assert.equal(pins.get(V.hostPub)!.macId, J.macId);
  assert.equal(kv.data.has(legacyPinKey(ORIGIN)), false, "old key removed");
  assert.ok(kv.data.has(pinsKey(ORIGIN)), "new key written");
  assert.ok(kv.data.has(legacyPinKey("https://other.test")), "other servers untouched");
  const again = await new PinStore(kv, ORIGIN).load();
  assert.deepEqual([...again.keys()], [V.hostPub]);
});

test("migration merges with existing pins; a malformed old pin is dropped", async () => {
  const kv = memKV({ [legacyPinKey(ORIGIN)]: V.hostPub });
  const store = new PinStore(kv, ORIGIN);
  await kv.del(legacyPinKey(ORIGIN));
  await store.add(devicePub, "Edit Bay Mac");
  await kv.set(legacyPinKey(ORIGIN), V.hostPub);
  const both = await store.load();
  assert.deepEqual([...both.keys()].sort(), [V.devicePub, V.hostPub].sort());
  assert.equal(both.get(V.devicePub)!.name, "Edit Bay Mac");

  const kv2 = memKV({ [legacyPinKey(ORIGIN)]: "not-a-key" });
  assert.equal((await new PinStore(kv2, ORIGIN).load()).size, 0);
  assert.equal(kv2.data.has(legacyPinKey(ORIGIN)), false);
});

test("pin store: add / remove / clear, per origin, ignores tampered entries", async () => {
  const kv = memKV();
  const a = new PinStore(kv, ORIGIN);
  const b = new PinStore(kv, "https://b.example.test");
  let m = await a.add(hostPub, "Studio Mac");
  assert.equal(m.get(V.hostPub)!.name, "Studio Mac");
  const pinnedAt = m.get(V.hostPub)!.pinnedAt;
  assert.ok(pinnedAt > 1_700_000_000);
  m = await a.add(hostPub, ""); // re-pin keeps the name and the date
  assert.equal(m.get(V.hostPub)!.name, "Studio Mac");
  assert.equal(m.get(V.hostPub)!.pinnedAt, pinnedAt);
  await a.add(devicePub, "x".repeat(500));
  assert.equal((await a.load()).get(V.devicePub)!.name.length, 200);
  assert.equal((await b.load()).size, 0, "pins are per server origin");
  await assert.rejects(a.add(hostPub.subarray(0, 16), "short"));

  // Stored macIds are recomputed; non-canonical / wrong-size keys are ignored.
  const raw = kv.data.get(pinsKey(ORIGIN)) as { hosts: Record<string, { macId: string }> };
  raw.hosts[V.hostPub]!.macId = "000000000";
  raw.hosts["AAAA"] = { macId: "1" };
  raw.hosts[V.hostPub + "="] = { macId: "1" };
  kv.data.set(pinsKey(ORIGIN), raw);
  const loaded = await a.load();
  assert.deepEqual([...loaded.keys()].sort(), [V.devicePub, V.hostPub].sort());
  assert.equal(loaded.get(V.hostPub)!.macId, J.macId);

  m = await a.remove(V.devicePub);
  assert.deepEqual([...m.keys()], [V.hostPub]);
  await a.clear();
  assert.equal((await a.load()).size, 0);
  // Garbage in storage → empty map, never a throw.
  kv.data.set(pinsKey(ORIGIN), "garbage");
  assert.equal((await a.load()).size, 0);
});

test("pin updates are serialised through the lock", async () => {
  const kv = memKV();
  let held = 0;
  let maxHeld = 0;
  const lock = async <T>(fn: () => Promise<T>): Promise<T> => {
    while (held) await new Promise((r) => setTimeout(r, 1));
    held++;
    maxHeld = Math.max(maxHeld, held);
    try {
      return await fn();
    } finally {
      held--;
    }
  };
  const s = new PinStore(kv, ORIGIN, lock);
  await Promise.all([s.add(hostPub, "A"), s.add(devicePub, "B")]);
  assert.equal(maxHeld, 1);
  assert.equal((await s.load()).size, 2, "no lost update");
});

// ------------------------------------------------------------------ message shapes (§10.3)

test("client→server messages that target a Mac carry its hostPub", async () => {
  const d = await device();
  const commit = unb64(V.pairCommit);
  assert.deepEqual(pairStartMsg(V.hostPub, "Laptop", "browser", commit), { type: "pair-start", hostPub: V.hostPub, name: "Laptop", kind: "browser", commit: V.pairCommit });
  assert.deepEqual(pairRevealMsg(I.requestId, devicePub, unb64(I.nd)), { type: "pair-reveal", requestId: I.requestId, devicePub: V.devicePub, nd: I.nd });
  assert.deepEqual(pairDenyMsg(V.hostPub, I.requestId), { type: "pair-deny", hostPub: V.hostPub, requestId: I.requestId });

  const req = parseApprovalNeeded({
    type: "approval-needed", hostPub: V.hostPub, requestId: I.requestId, name: "Chrome on Windows", kind: "browser",
    devicePub: V.devicePub, nd: I.nd, commit: V.pairCommit, na: I.na, hostSig: vec(LABEL.pairChallenge).sig,
  });
  const ap = await pairApproveMsg(d, hostPub, req);
  assert.deepEqual(Object.keys(ap).sort(), ["approverPub", "hostPub", "requestId", "sig", "type"]);
  assert.equal(ap["type"], "pair-approve");
  assert.equal(ap["hostPub"], V.hostPub);
  assert.equal(ap["requestId"], I.requestId);
  assert.equal(ap["approverPub"], V.devicePub);
  assert.equal(ap["sig"], vec(LABEL.pairApprove).sig);

  const sr = sessionRequestMsg(V.hostPub, I.sessionId, devicePub, unb64(I.clientNonce), false);
  assert.deepEqual(sr, { type: "session-request", hostPub: V.hostPub, sessionId: I.sessionId, devicePub: V.devicePub, clientNonce: I.clientNonce });
  assert.equal(sessionRequestMsg(V.hostPub, I.sessionId, devicePub, unb64(I.clientNonce), true)["relayOnly"], true);
  const sig = new Uint8Array(64).fill(7);
  assert.deepEqual(offerMsg(V.hostPub, I.sessionId, "v=0", sig), { type: "offer", hostPub: V.hostPub, sessionId: I.sessionId, sdp: "v=0", sig: b64(sig) });
  assert.deepEqual(iceMsg(V.hostPub, I.sessionId, null), { type: "ice", hostPub: V.hostPub, sessionId: I.sessionId, candidate: null });
  assert.deepEqual(sessionEndMsg(V.hostPub, I.sessionId, "user"), { type: "session-end", hostPub: V.hostPub, sessionId: I.sessionId, reason: "user" });
});

test("revoke-request and kill-request are signed for exactly that Mac", async () => {
  const d = await device();
  const rv = await revokeRequestMsg(d, hostPub, devicePub, 1760000000);
  assert.deepEqual(rv, { type: "revoke-request", hostPub: V.hostPub, targetPub: V.devicePub, ts: 1760000000, approverPub: V.devicePub, sig: vec(LABEL.revokeRequest).sig });
  const kl = await killRequestMsg(d, hostPub, "kill", 1760000000);
  assert.deepEqual(kl, { type: "kill-request", hostPub: V.hostPub, action: "kill", ts: 1760000000, approverPub: V.devicePub, sig: vec(LABEL.killRequest).sig });
  // A request signed for one Mac does not verify for another.
  const other = unb64(I.nonce);
  const sigB = unb64(kl["sig"] as string);
  assert.equal(await verify(devicePub, sigB, LABEL.killRequest, hostPub, new TextEncoder().encode("kill"), new TextEncoder().encode("1760000000")), true);
  assert.equal(await verify(devicePub, sigB, LABEL.killRequest, other, new TextEncoder().encode("kill"), new TextEncoder().encode("1760000000")), false);
});

test("aboutMac: a message naming another Mac never matches", () => {
  assert.equal(aboutMac({ hostPub: V.hostPub }, V.hostPub), true);
  assert.equal(aboutMac({ hostPub: V.devicePub }, V.hostPub), false);
  assert.equal(aboutMac({ hostPub: "" }, V.hostPub), false);
  assert.equal(aboutMac({}, V.hostPub), true, "older single-Mac servers send none");
});

// ------------------------------------------------------------------ server shapes (§10.4)

test("ready: hosts with this device's status; older single-host shape still works", () => {
  const r = parseReady({
    type: "ready",
    device: { pub: V.devicePub },
    hosts: [
      { pub: V.hostPub, macId: "000000000", name: "Studio Mac", online: true, state: "available", sessionDeviceName: "", deviceStatus: "approved", cert: V.cert },
      { pub: V.devicePub, name: "Edit Bay", online: false, state: "", deviceStatus: "weird" },
      { pub: V.hostPub, name: "dup", online: false, state: "", deviceStatus: "revoked" },
      { pub: "not-a-key", name: "bad", deviceStatus: "approved" },
      null,
    ],
  });
  assert.equal(r.hosts.length, 2);
  assert.deepEqual(r.hosts[0], { pub: V.hostPub, name: "Studio Mac", online: true, state: "available", deviceStatus: "approved" });
  assert.equal(r.hosts[1]!.deviceStatus, "unknown");
  const legacy = parseReady({ type: "ready", device: { status: "pending" }, host: { pub: V.hostPub, name: "Mac", online: true, state: "in-session", sessionDeviceName: "Phone" } });
  assert.deepEqual(legacy.hosts, [{ pub: V.hostPub, name: "Mac", online: true, state: "in-session", sessionDeviceName: "Phone", deviceStatus: "pending" }]);
  assert.deepEqual(parseReady({ type: "ready", device: { status: "approved" }, host: { pub: "", name: "" } }).hosts, []);
});

test("/api/me: hosts + per-Mac approvals; older {host, devices[].status} still works", () => {
  const me = normalizeMe({
    hosts: [
      { pub: V.hostPub, macId: J.macId, name: "Studio Mac", online: true, state: "available", sessionDeviceName: "", claimedAt: 1760000000, lastSeen: 1760000100 },
      { pub: "bogus", name: "x" },
    ],
    devices: [
      { pub: V.devicePub, name: "Phone ✓", kind: "browser", createdAt: 1, lastSeen: 2, approvals: [{ hostPub: V.hostPub, status: "approved" }, { hostPub: "x", status: "approved" }] },
      { pub: "bad", name: "bad" },
    ],
    passkeys: [{ id: "pk1", name: "iPhone", createdAt: 3 }, { name: "no id" }],
  });
  assert.equal(me.hosts.length, 1);
  assert.equal(me.hosts[0]!.claimedAt, 1760000000);
  assert.equal(me.devices.length, 1);
  assert.deepEqual(me.devices[0]!.approvals, [{ hostPub: V.hostPub, status: "approved" }]);
  assert.deepEqual(me.passkeys, [{ id: "pk1", name: "iPhone", createdAt: 3 }]);

  const legacy = normalizeMe({ host: { pub: V.hostPub, name: "Mac", online: false, state: "" }, devices: [{ pub: V.devicePub, name: "P", kind: "browser", status: "approved" }] });
  assert.equal(legacy.hosts.length, 1);
  assert.deepEqual(legacy.devices[0]!.approvals, [{ hostPub: V.hostPub, status: "approved" }]);
  assert.deepEqual(normalizeMe(null), { hosts: [], devices: [], passkeys: [] });

  const of = statusFromMe(me, V.devicePub);
  assert.equal(of(V.hostPub), "approved");
  assert.equal(of(V.devicePub), "unknown");
  assert.equal(statusFromMe(me, "someone-else")(V.hostPub), "unknown");
});

test("aggregate device status and card status texts", () => {
  assert.equal(aggregateStatus([]), "unknown");
  assert.equal(aggregateStatus([{ deviceStatus: "revoked" }, { deviceStatus: "approved" }]), "approved");
  assert.equal(aggregateStatus([{ deviceStatus: "revoked" }, { deviceStatus: "pending" }]), "pending");
  assert.equal(aggregateStatus([{ deviceStatus: "revoked" }, { deviceStatus: "unknown" }]), "revoked");
  assert.equal(macStatus({ online: true, state: "available" }, true).title, "Online");
  assert.equal(macStatus({ online: false, state: "available" }, true).title, "Offline");
  assert.equal(macStatus({ online: true, state: "blocked" }, true).title, "Blocked");
  const busy = macStatus({ online: true, state: "in-session", sessionDeviceName: "Studio Laptop" }, true);
  assert.equal(busy.title, "Someone connected");
  assert.match(busy.detail, /Studio Laptop/);
  assert.equal(macStatus({ online: true, state: "available" }, false).kind, "checking");
});

// ------------------------------------------------------------------ HTTP shapes (§10.2)

function fakeApi(handler: (path: string, method: string, body: unknown) => { status?: number; json?: unknown }) {
  const calls: Array<{ path: string; method: string; body: unknown }> = [];
  const api = new Api({
    async request(path: string, method: "GET" | "POST", body?: unknown) {
      calls.push({ path, method, body });
      const r = handler(path, method, body);
      return new Response(r.json === undefined ? "" : JSON.stringify(r.json), { status: r.status ?? 200 });
    },
  });
  return { api, calls };
}

const PROOF: DeviceProof = { devicePub: V.devicePub, nonce: I.nonce, sig: "c2ln" };

test("hosts API: pending lookup, join begin/finish and remove send the §10.2 shapes", async () => {
  const { api, calls } = fakeApi((path) => {
    if (path.startsWith("/api/hosts/pending")) return { json: { hostPub: V.hostPub, name: "Studio Mac" } };
    if (path === "/api/hosts/join/begin") return { json: { flowId: "f1", name: "Studio Mac", macId: J.macId } };
    return { json: { ok: true } };
  });
  assert.deepEqual(await api.hostsPending(PROOF, J.macId), { hostPub: V.hostPub, name: "Studio Mac" });
  // A GET: the device proof travels in the query string.
  const q = new URLSearchParams(calls[0]!.path.split("?")[1]);
  assert.equal(calls[0]!.path.split("?")[0], "/api/hosts/pending");
  assert.equal(calls[0]!.method, "GET");
  assert.equal(calls[0]!.body, undefined);
  assert.deepEqual(Object.fromEntries(q), { macId: J.macId, ...PROOF });
  await assert.rejects(api.hostsPending(PROOF, "12 3"), /9 digits/);
  assert.deepEqual(await api.joinBegin(PROOF, V.hostPub, J.kc), { flowId: "f1", name: "Studio Mac", macId: J.macId });
  assert.deepEqual(calls[1], { path: "/api/hosts/join/begin", method: "POST", body: { hostPub: V.hostPub, claim: J.kc, ...PROOF } });
  await api.joinFinish(PROOF, "f1", J.setupMac);
  assert.deepEqual(calls[2], { path: "/api/hosts/join/finish", method: "POST", body: { flowId: "f1", setupMac: J.setupMac, ...PROOF } });
  await api.hostsRemove(PROOF, V.hostPub);
  assert.deepEqual(calls[3], { path: "/api/hosts/remove", method: "POST", body: { hostPub: V.hostPub, ...PROOF } });

  const bad = fakeApi(() => ({ json: { hostPub: "nope" } }));
  await assert.rejects(bad.api.hostsPending(PROOF, J.macId), ApiError);
});

// ------------------------------------------------------------------ join flow

interface FakeOpts {
  pendingHost?: string;
  pendingStatus?: number;
  beginStatus?: number;
  beginCode?: string;
  finishReply?: Record<string, unknown>;
  joined?: Record<string, unknown> | "timeout";
}

function joinDeps(o: FakeOpts = {}) {
  const seen: Record<string, unknown> = {};
  let proofs = 0;
  const err = (status: number, code = "x") => new ApiError(status, code, `HTTP ${status}`);
  const deps: JoinDeps = {
    api: {
      async hostsPending(proof: DeviceProof, id: string) {
        seen["pendingId"] = id;
        seen["pendingProof"] = proof;
        if (o.pendingStatus) throw err(o.pendingStatus, o.pendingStatus === 404 ? "not-found" : "x");
        return { hostPub: o.pendingHost ?? V.hostPub, name: "Studio Mac" };
      },
      async joinBegin(_p: DeviceProof, hp: string, claim: string) {
        seen["beginHost"] = hp;
        seen["claim"] = claim;
        if (o.beginStatus) throw err(o.beginStatus, o.beginCode);
        return { flowId: "flow-1", name: "Studio Mac", macId: J.macId };
      },
      async joinFinish(_p: DeviceProof, flowId: string, mac: string) {
        seen["flowId"] = flowId;
        seen["setupMac"] = mac;
        return o.finishReply ?? { ok: true };
      },
    },
    async proof() {
      proofs++;
      return PROOF;
    },
    devicePub,
    async device() {
      return { name: V.setup.name, kind: V.setup.kind };
    },
    hostJoined(hp: string) {
      seen["waitedFor"] = hp;
      if (o.joined === "timeout") return Promise.reject(new Error("timeout"));
      return Promise.resolve(o.joined ?? { type: "host-joined", hostPub: V.hostPub, cert: V.cert, hostMac: J.hostMac });
    },
  };
  return { deps, seen, proofs: () => proofs };
}

test("typed join: Mac ID checked locally, claim = Kc, setupMac with Ka, cert + hostMac verified", async () => {
  const { deps, seen, proofs } = joinDeps();
  const found = await findPendingMac(deps, J.macId);
  assert.deepEqual(seen["pendingProof"], PROOF);
  assert.equal(b64(found.hostPub), V.hostPub);
  assert.equal(found.macId, J.macId);
  const t = parseJoinCode(J.code.toLowerCase().replace(/-/g, " "));
  const p = await beginJoin(deps, found.hostPub, t);
  assert.equal(seen["claim"], J.kc, "the server only ever sees Kc");
  assert.equal(seen["beginHost"], V.hostPub);
  assert.equal(b64(p.ka), J.ka);
  const cert = await finishJoin(deps, p);
  assert.equal(seen["setupMac"], J.setupMac);
  assert.equal(seen["flowId"], "flow-1");
  assert.equal(seen["waitedFor"], V.hostPub);
  assert.equal(cert.devicePub, V.devicePub);
  assert.equal(proofs(), 3, "a fresh device proof per request");
});

test("typed join: a server answering with another key (Mac ID mismatch) or 404 is refused", async () => {
  await assert.rejects(findPendingMac(joinDeps({ pendingHost: V.devicePub }).deps, J.macId), (e: unknown) => e instanceof JoinError && e.code === "mac-id-mismatch");
  await assert.rejects(findPendingMac(joinDeps({ pendingStatus: 404 }).deps, J.macId), (e: unknown) => e instanceof JoinError && e.code === "not-found");
  const { deps } = joinDeps({ beginStatus: 403, beginCode: "bad-claim" });
  await assert.rejects(beginJoin(deps, hostPub, unb64(J.t)), (e: unknown) => e instanceof JoinError && e.code === "bad-code");
  await assert.rejects(beginJoin(joinDeps({ beginStatus: 403, beginCode: "device-not-approved" }).deps, hostPub, unb64(J.t)), /approved on one of your Macs/);
  await assert.rejects(beginJoin(joinDeps({ beginStatus: 409, beginCode: "already-joined" }).deps, hostPub, unb64(J.t)), /already in your account/);
  await assert.rejects(beginJoin(joinDeps({ beginStatus: 409, beginCode: "too-many-hosts" }).deps, hostPub, unb64(J.t)), /20 Macs/);
  await assert.rejects(beginJoin(joinDeps({ beginStatus: 410 }).deps, hostPub, unb64(J.t)), (e: unknown) => e instanceof JoinError && e.code === "expired");
  await assert.rejects(beginJoin(joinDeps({ beginStatus: 500 }).deps, hostPub, unb64(J.t)), ApiError);
});

test("join: a forged or missing hostMac, or a cert for someone else, is never accepted", async () => {
  const run = async (joined: FakeOpts["joined"]) => {
    const { deps } = joinDeps({ joined });
    return finishJoin(deps, await beginJoin(deps, hostPub, unb64(J.t)));
  };
  const badMac = toBytes(unb64(J.hostMac));
  badMac[5]! ^= 1;
  await assert.rejects(run({ hostPub: V.hostPub, cert: V.cert, hostMac: b64(badMac) }), /confirmation code is not valid/);
  await assert.rejects(run({ hostPub: V.hostPub, cert: V.cert }), /hostMac/);
  await assert.rejects(run({ hostPub: V.devicePub, cert: V.cert, hostMac: J.hostMac }), /different Mac/);
  await assert.rejects(run({ hostPub: V.hostPub, cert: { ...V.cert, name: "Someone else" }, hostMac: J.hostMac }), /signature/);
  await assert.rejects(run("timeout"), (e: unknown) => e instanceof JoinError && e.code === "timeout");
  // The server reports a failed join on the WebSocket: error {for:"join", hostPub}.
  await assert.rejects(run({ type: "error", code: "too-many-hosts", for: "join", hostPub: V.hostPub }), /20 Macs/);
  await assert.rejects(run({ type: "error", code: "internal", for: "join", hostPub: V.hostPub }), /couldn't be added \(internal\)/);
  // A server may return the confirmation in the HTTP reply instead.
  const { deps } = joinDeps({ finishReply: { hostPub: V.hostPub, cert: V.cert, hostMac: J.hostMac }, joined: "timeout" });
  const cert = await finishJoin(deps, await beginJoin(deps, hostPub, unb64(J.t)));
  assert.equal(cert.hostPub, V.hostPub);
  // Direct check of the verifier with the vector values.
  const ka = unb64(J.ka);
  await verifyHostJoined({ cert: V.cert, hostMac: J.hostMac }, hostPub, devicePub, ka);
  await assert.rejects(verifyHostJoined({ cert: V.cert, hostMac: J.hostMac }, hostPub, devicePub, unb64(J.kc)));
});

test("server refusals of a session request are explained", () => {
  const generic = serverRefusalText("???");
  for (const c of ["host-offline", "not-approved", "unknown-host", "duplicate-session"]) assert.notEqual(serverRefusalText(c), generic, c);
});
