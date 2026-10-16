// Compatibility with the Go host agent / server (reason strings, file errors)
// and with the Tauri shell's exact command surface (tauri/src-tauri/src/main.rs).
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import { b64, randomBytes, unb64 } from "../src/b64";
import { FilesController, rejectReason } from "../src/filexfer";
import { signClientAuth, signKillRequest, signOffer, signPairApprove, signRevokeRequest, type Signer } from "../src/hr1";
import { detectPlatform } from "../src/platform";
import { byeText, type RemoteSession } from "../src/rtc";
import { denialText, pairErrorText } from "../src/views/pair";

test("every session end reason the Go agent/server sends has a specific message", () => {
  const generic = byeText("???");
  // agent/internal/core/session.go + agent.go endSession(...) reasons, server hub.go session-end reasons
  const reasons = [
    "replaced", "offer-rejected", "no-common-codec", "offer-timeout", "connect-timeout", "idle", "connection-failed",
    "connection-closed", "revoked", "killed", "host-disconnected", "browser-disabled", "trust-reset", "host-shutdown",
    "host-offline", "host-reconnected", "timeout",
  ];
  for (const r of reasons) assert.notEqual(byeText(r), generic, r);
  assert.match(byeText("killed"), /blocked/);
  assert.match(byeText("host-shutdown"), /closed on your Mac/);
});

test("pairing denial / error codes map to plain language", () => {
  const generic = denialText("denied");
  for (const r of ["expired", "commit-mismatch", "too-many-pending", "rate-limited", "invalid", "revoked", "unavailable", "host-offline"]) {
    assert.notEqual(denialText(r), generic, r);
  }
  assert.match(generic, /declined/);
  assert.match(pairErrorText("host-offline"), /offline/);
  assert.match(pairErrorText("pairing-in-progress"), /already waiting/);
  assert.match(pairErrorText("<script>"), /\(error\)/, "unknown codes are not echoed verbatim unless safe");
});

test("file reasons from agent/internal/core/datachannels.go", () => {
  const generic = rejectReason({});
  for (const r of ["outside-home", "not-a-file", "not-found", "permission-denied", "invalid-path", "busy", "file-changed", "read-failed", "timeout", "incomplete", "checksum mismatch", "not enough disk space", "file too large"]) {
    const t = rejectReason(r);
    assert.notEqual(t, generic, r);
    assert.doesNotMatch(t, /reported:/, r);
  }
});

test("a download that fails before starting (file-error with only reqId) is reported", () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    const sent: Array<Record<string, unknown>> = [];
    const notes: Array<[string, string]> = [];
    const session = { sendControl: (m: Record<string, unknown>) => (sent.push(m), true), file: null } as unknown as RemoteSession;
    const f = new FilesController(session, () => undefined, (msg, level) => notes.push([msg, level]));
    f.download("Projects/secret.mov");
    assert.equal(sent[0]!["t"], "get");
    assert.equal(sent[0]!["path"], "Projects/secret.mov");
    assert.equal(f.handleControl({ t: "file-error", reqId: sent[0]!["reqId"], reason: "not-found" }), true);
    assert.equal(notes.length, 1);
    assert.equal(notes[0]![1], "error");
    assert.match(notes[0]![0], /secret\.mov/);
    assert.match(notes[0]![0], /no longer exists/);
    // Unknown / id-less errors are ignored quietly.
    assert.equal(f.handleControl({ t: "file-error", reqId: "nope", reason: "busy" }), true);
    assert.equal(notes.length, 1);
    f.dispose();
  } finally {
    mock.timers.reset();
  }
});

// ------------------------------------------------------------------ Tauri

const TAURI_COMMANDS = new Set(["device_key_public", "device_key_sign", "token_get", "token_set", "token_clear", "config_get", "config_set", "open_url"]);
const TAURI_SIGN_LABELS = ["HR1/client-auth", "HR1/pair-approve", "HR1/revoke-request", "HR1/kill-request", "HR1/offer"];

function fakeTauri() {
  const calls: Array<[string, Record<string, unknown> | undefined]> = [];
  const state = { origin: "https://a.example.test" as string | null, token: "tok-1" as string | null };
  const pub = randomBytes(32);
  const invoke = async (cmd: string, args?: Record<string, unknown>): Promise<unknown> => {
    calls.push([cmd, args]);
    if (!TAURI_COMMANDS.has(cmd)) throw new Error(`unknown command ${cmd}`);
    switch (cmd) {
      case "config_get":
        return state.origin;
      case "config_set": {
        const o = String(args?.["origin"]).toLowerCase().replace(/\/$/, "");
        if (o !== state.origin) state.token = null; // changing origin clears the token
        state.origin = o;
        return o;
      }
      case "token_get":
        return state.token;
      case "token_set":
        state.token = String(args?.["token"]);
        return null;
      case "token_clear":
        state.token = null;
        return null;
      case "device_key_public":
        return b64(pub);
      case "device_key_sign": {
        const data = unb64(String(args?.["data"]));
        const label = new TextDecoder().decode(data.slice(0, data.indexOf(0)));
        if (!TAURI_SIGN_LABELS.includes(label)) throw new Error(`not allowed: ${label}`);
        return b64(new Uint8Array(64));
      }
      default:
        return null;
    }
  };
  return { calls, state, pub, invoke };
}

test("Tauri platform uses exactly the shell's commands, bearer auth and the canonical origin", async () => {
  const t = fakeTauri();
  const g = globalThis as unknown as { __TAURI__?: unknown; fetch: typeof fetch };
  const realFetch = g.fetch;
  const fetches: Array<[string, RequestInit | undefined]> = [];
  g.__TAURI__ = { core: { invoke: t.invoke } };
  g.fetch = (async (url: string, init?: RequestInit) => {
    fetches.push([url, init]);
    return new Response("{}", { status: 200 });
  }) as typeof fetch;
  try {
    const p = detectPlatform();
    assert.equal(p.kind, "tauri");
    assert.equal(p.deviceKind, "app");
    await p.init();
    assert.equal(p.origin(), "https://a.example.test");

    await p.request("/api/me", "GET");
    const [url, init] = fetches[0]!;
    assert.equal(url, "https://a.example.test/api/me");
    const headers = init!.headers as Record<string, string>;
    assert.equal(headers["Authorization"], "Bearer tok-1");
    assert.equal(headers["X-HR"], "1");
    assert.equal(init!.credentials, "omit");
    assert.deepEqual(await p.wsAuthMessage(), { type: "auth", token: "tok-1" });
    assert.equal(p.wsURL(), "wss://a.example.test/ws/client");

    // Changing the server: uses config_set's answer and forgets the old token.
    await p.setOrigin("B.example.test");
    assert.deepEqual(t.calls.find((c) => c[0] === "config_set")![1], { origin: "https://b.example.test" });
    assert.equal(p.origin(), "https://b.example.test");
    assert.deepEqual(await p.wsAuthMessage(), { type: "auth" });

    await p.setToken("tok-2");
    assert.deepEqual(await p.wsAuthMessage(), { type: "auth", token: "tok-2" });
    await p.clearToken();
    assert.equal(await p.hasToken(), false);

    await p.openURL("https://b.example.test/#link");
    assert.deepEqual(t.calls.at(-1), ["open_url", { url: "https://b.example.test/#link" }]);

    // Every TBS the web client signs with the device key uses an allowed label.
    const signer = (await p.signer(true)) as Signer;
    assert.deepEqual(signer.pub, t.pub);
    const host = randomBytes(32);
    await signClientAuth(signer, "https://b.example.test", randomBytes(32));
    await signPairApprove(signer, host, {
      requestId: randomBytes(16), name: "Phone", kind: "browser", devicePub: randomBytes(32),
      nd: randomBytes(32), commit: randomBytes(32), na: randomBytes(32), hostSig: randomBytes(64),
    });
    await signRevokeRequest(signer, host, randomBytes(32), 1_700_000_000);
    await signKillRequest(signer, host, "kill", 1_700_000_000);
    await signOffer(signer, { sessionId: randomBytes(16), hostPub: host, devicePub: signer.pub, clientNonce: randomBytes(32), hostNonce: randomBytes(32) }, `v=0\r\na=fingerprint:sha-256 ${Array(32).fill("AB").join(":")}\r\n`);
    assert.equal(t.calls.filter((c) => c[0] === "device_key_sign").length, 5);

    // No reset command exists natively; resetting must not call one.
    await p.resetDeviceKey();
    for (const [cmd] of t.calls) assert.ok(TAURI_COMMANDS.has(cmd), `only known commands (${cmd})`);
  } finally {
    delete g.__TAURI__;
    g.fetch = realFetch;
  }
});
