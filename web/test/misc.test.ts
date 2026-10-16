// Setup-link parsing, origin normalisation, link codes, device names, stats and clipboard loop prevention.
import { test } from "node:test";
import assert from "node:assert/strict";
import vectors from "../../testdata/vectors.json";
import { b64, unb64 } from "../src/b64";
import { ClipboardSync, MAX_CLIP_BYTES } from "../src/clipboard";
import { cleanDeviceName, defaultDeviceName, isApple } from "../src/device-name";
import { parseSetupFragment } from "../src/fragment";
import { formatLinkCodeInput, normalizeLinkCode } from "../src/linkcode";
import { normalizeOrigin } from "../src/platform";
import { rejectText } from "../src/rtc";
import { latencyLevel, rates, type RawStat, snapshot } from "../src/stats";

test("setup fragment #setup=<T>.<hostPub>", () => {
  const f = parseSetupFragment(`#setup=${vectors.setup.t}.${vectors.hostPub}`);
  assert.ok(f && f !== "invalid");
  assert.equal(b64(f.t), vectors.setup.t);
  assert.equal(b64(f.hostPub), vectors.hostPub);
  assert.equal(parseSetupFragment("#link"), null);
  assert.equal(parseSetupFragment(""), null);
  for (const bad of ["#setup=", "#setup=abc", `#setup=${vectors.setup.t}`, `#setup=${vectors.setup.t}.AAAA`, `#setup=${vectors.setup.t}.${vectors.hostPub}.x`]) {
    assert.equal(parseSetupFragment(bad), "invalid", bad);
  }
});

test("server origin normalisation (Tauri first run)", () => {
  assert.equal(normalizeOrigin("heartfulness-remote.dedyn.io"), "https://heartfulness-remote.dedyn.io");
  assert.equal(normalizeOrigin("  https://Heartfulness-Remote.dedyn.io/ "), "https://heartfulness-remote.dedyn.io");
  assert.equal(normalizeOrigin("https://example.test:8443"), "https://example.test:8443");
  assert.equal(normalizeOrigin("http://localhost:8080"), "http://localhost:8080");
  assert.throws(() => normalizeOrigin("http://example.test"), /https/);
  assert.throws(() => normalizeOrigin("ftp://example.test"), /https/);
  assert.throws(() => normalizeOrigin("https://user:pw@example.test"));
  assert.throws(() => normalizeOrigin("https://example.test/some/path"));
  assert.throws(() => normalizeOrigin(""));
});

test("link codes", () => {
  assert.equal(normalizeLinkCode("abcd-efgh"), "ABCD-EFGH");
  assert.equal(normalizeLinkCode(" ab cd ef gh "), "ABCD-EFGH");
  assert.equal(normalizeLinkCode("ABCDEFG"), "");
  assert.equal(normalizeLinkCode("ABCDEFGHI"), "");
  assert.equal(formatLinkCodeInput("abcde"), "ABCD-E");
  assert.equal(formatLinkCodeInput("abcd-efghij"), "ABCD-EFGH");
});

test("default device names", () => {
  const iphone = "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1";
  const ipad = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15";
  const edge = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0";
  const chromeMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
  const android = "Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36";
  const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
  assert.equal(defaultDeviceName({ userAgent: iphone }), "iPhone Safari");
  assert.equal(defaultDeviceName({ userAgent: ipad, maxTouchPoints: 5 }), "iPad Safari");
  assert.equal(defaultDeviceName({ userAgent: ipad, maxTouchPoints: 0 }), "Mac Safari");
  assert.equal(defaultDeviceName({ userAgent: edge }), "Windows Edge");
  assert.equal(defaultDeviceName({ userAgent: chromeMac }), "Mac Chrome");
  assert.equal(defaultDeviceName({ userAgent: android }), "Android phone Chrome");
  assert.equal(defaultDeviceName({ userAgent: firefox }), "Linux Firefox");
  assert.equal(defaultDeviceName({ userAgent: edge, app: true }), "Windows PC (app)");
  assert.equal(defaultDeviceName({ userAgent: "" }), "Web browser");
  assert.equal(isApple(iphone), true);
  assert.equal(isApple(edge), false);
  assert.equal(cleanDeviceName("  My\u0000  phone‮\n "), "My phone");
  assert.equal([...cleanDeviceName("x".repeat(100))].length, 48);
});

test("latency colours: green < 40 ms, amber < 100 ms, red ≥ 100 ms", () => {
  assert.equal(latencyLevel(0), "good");
  assert.equal(latencyLevel(39.9), "good");
  assert.equal(latencyLevel(40), "ok");
  assert.equal(latencyLevel(99.9), "ok");
  assert.equal(latencyLevel(100), "bad");
  assert.equal(latencyLevel(null), "unknown");
  assert.equal(latencyLevel(Number.NaN), "unknown");
});

test("stats snapshot: selected pair, relay detection, rates", () => {
  const stats = (bytes: number, frames: number, relay: boolean): RawStat[] => [
    { id: "T1", type: "transport", selectedCandidatePairId: "CP1" },
    { id: "CP1", type: "candidate-pair", localCandidateId: "L1", remoteCandidateId: "R1", currentRoundTripTime: 0.023, nominated: true, state: "succeeded" },
    { id: "CP2", type: "candidate-pair", localCandidateId: "L2", remoteCandidateId: "R1", currentRoundTripTime: 0.5 },
    { id: "L1", type: "local-candidate", candidateType: relay ? "relay" : "srflx" },
    { id: "L2", type: "local-candidate", candidateType: "relay" },
    { id: "R1", type: "remote-candidate", candidateType: "host" },
    { id: "V", type: "inbound-rtp", kind: "video", bytesReceived: bytes, framesDecoded: frames, codecId: "C1", frameWidth: 2560, frameHeight: 1440 },
    { id: "A", type: "inbound-rtp", kind: "audio", bytesReceived: 1000 },
    { id: "C1", type: "codec", mimeType: "video/H265" },
  ];
  const a = snapshot(stats(1_000_000, 100, false), 0);
  assert.equal(a.iceRttMs, 23);
  assert.equal(a.relay, false);
  assert.equal(a.codec, "H265");
  assert.equal(a.width, 2560);
  const b = snapshot(stats(2_250_000, 160, true), 1000);
  assert.equal(b.relay, true);
  const r = rates(a, b);
  assert.equal(r.mbps, 10);
  assert.equal(r.fps, 60);
  // Firefox style: no transport stats, `selected` flag on the pair.
  const ff = snapshot(
    [
      { id: "P", type: "candidate-pair", selected: true, localCandidateId: "L", remoteCandidateId: "R", currentRoundTripTime: 0.15 },
      { id: "L", type: "local-candidate", candidateType: "host" },
      { id: "R", type: "remote-candidate", candidateType: "relay" },
    ],
    0,
  );
  assert.equal(ff.iceRttMs, 150);
  assert.equal(ff.relay, true);
});

test("session reject reasons are explained", () => {
  assert.match(rejectText("blocked"), /blocked/);
  assert.match(rejectText("busy"), /Someone else/);
  assert.match(rejectText("not-trusted"), /approved again/);
  assert.match(rejectText("browser-disabled"), /app/);
  assert.match(rejectText("???"), /couldn't start/);
});

test("clipboard sync never loops and respects the 1 MiB limit", () => {
  (globalThis as unknown as { document: { hasFocus(): boolean } }).document = { hasFocus: () => false };
  const sent: string[] = [];
  const notes: string[] = [];
  const c = new ClipboardSync(true, (t) => (sent.push(t), true), (m) => notes.push(m));
  // Mac → here, then a local paste of the same text must not bounce back.
  c.onRemote("from mac");
  assert.equal(c.offer("from mac"), false);
  // New local text goes out once.
  assert.equal(c.offer("local 1"), true);
  assert.equal(c.offer("local 1"), false);
  // The Mac echoing our own text back doesn't count as new remote text…
  c.onRemote("local 1");
  assert.equal(c.offer("local 1"), false);
  // …but an explicit "send now" is always allowed.
  assert.equal(c.offer("local 1", true), true);
  assert.deepEqual(sent, ["local 1", "local 1"]);
  assert.equal(c.offer("x".repeat(MAX_CLIP_BYTES + 1)), false);
  assert.equal(notes.length, 1);
  // Disabled: nothing is sent automatically.
  c.enabled = false;
  assert.equal(c.offer("other"), false);
  assert.ok(unb64("AA").length === 1);
});
