// File transfer chunker, backpressure, assembly and SHA-256 verification.
import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, randomBytes, utf8 } from "../src/b64";
import {
  Assembler,
  CHUNK_SIZE,
  type ChannelLike,
  formatBytes,
  frame,
  frames,
  HIGH_WATER,
  isSafeEntryName,
  joinPath,
  LOW_WATER,
  MAX_TRANSFER_BYTES,
  parentPath,
  parseFrame,
  safeDownloadName,
  sendFrames,
  sha256B64,
  TransferCancelled,
} from "../src/files";

test("SHA-256 (WebCrypto) known vectors, base64url", async () => {
  assert.equal(await sha256B64(utf8("abc")), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
  assert.equal(await sha256B64(new Uint8Array(0)), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
});

test("frames are 16-byte id ‖ chunk with chunks ≤ 16 KiB", () => {
  const id = randomBytes(16);
  for (const n of [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1, 3 * CHUNK_SIZE + 123]) {
    const data = randomBytes(n);
    const fs = [...frames(id, data)];
    assert.equal(fs.length, Math.ceil(n / CHUNK_SIZE), `count for ${n}`);
    let off = 0;
    for (const { frame: f, end } of fs) {
      assert.ok(f.length <= 16 + CHUNK_SIZE);
      const p = parseFrame(f.buffer);
      assert.ok(p);
      assert.equal(p.id, b64(id));
      assert.deepEqual([...p.chunk], [...data.subarray(off, off + p.chunk.length)]);
      off += p.chunk.length;
      assert.equal(end, off);
    }
    assert.equal(off, n);
  }
  assert.throws(() => frame(randomBytes(15), new Uint8Array(1)));
  assert.throws(() => frame(id, new Uint8Array(CHUNK_SIZE + 1)));
  assert.equal(parseFrame(new Uint8Array(10).buffer), null);
  assert.equal(parseFrame(new Uint8Array(16 + CHUNK_SIZE + 1).buffer), null);
});

test("assembler reassembles and verifies SHA-256", async () => {
  const data = randomBytes(50_000);
  const id = randomBytes(16);
  const sha = await sha256B64(data);
  const a = new Assembler(b64(id), "clip.mov", data.length);
  for (const { frame: f } of frames(id, data)) a.push(parseFrame(f.buffer)!.chunk);
  assert.equal(a.complete, true);
  const blob = await a.finish(sha);
  assert.equal(blob.size, data.length);
  assert.deepEqual(new Uint8Array(await blob.arrayBuffer()), data);
});

test("assembler rejects corruption, truncation and overflow", async () => {
  const data = randomBytes(1000);
  const sha = await sha256B64(data);
  const bad = new Assembler("x", "f", 1000);
  const copy = data.slice();
  copy[500]! ^= 1;
  bad.push(copy);
  await assert.rejects(bad.finish(sha), /checksum/);
  const short = new Assembler("x", "f", 1000);
  short.push(data.subarray(0, 999));
  await assert.rejects(short.finish(sha), /incomplete/);
  const over = new Assembler("x", "f", 10);
  assert.throws(() => over.push(new Uint8Array(11)), /more data/);
  assert.throws(() => new Assembler("x", "f", MAX_TRANSFER_BYTES + 1), /too large/);
  assert.throws(() => new Assembler("x", "f", -1));
  const empty = new Assembler("x", "f", 0);
  assert.equal((await empty.finish(await sha256B64(new Uint8Array(0)))).size, 0);
});

class FakeChannel implements ChannelLike {
  readyState = "open";
  bufferedAmount = 0;
  bufferedAmountLowThreshold = 0;
  sent: Uint8Array[] = [];
  maxBuffered = 0;
  private listeners = new Map<string, Set<() => void>>();
  send(d: Uint8Array): void {
    this.sent.push(d.slice());
    this.bufferedAmount += d.length;
    this.maxBuffered = Math.max(this.maxBuffered, this.bufferedAmount);
    // The network drains asynchronously.
    setTimeout(() => this.drain(d.length), 0);
  }
  private drain(n: number): void {
    const before = this.bufferedAmount;
    this.bufferedAmount -= n;
    if (before > this.bufferedAmountLowThreshold && this.bufferedAmount <= this.bufferedAmountLowThreshold) {
      for (const l of [...(this.listeners.get("bufferedamountlow") ?? [])]) l();
    }
  }
  addEventListener(t: string, fn: () => void): void {
    if (!this.listeners.has(t)) this.listeners.set(t, new Set());
    this.listeners.get(t)!.add(fn);
  }
  removeEventListener(t: string, fn: () => void): void {
    this.listeners.get(t)?.delete(fn);
  }
}

test("sendFrames respects bufferedAmount backpressure and reports progress", async () => {
  const ch = new FakeChannel();
  const data = randomBytes(3 * 1024 * 1024 + 77);
  const id = randomBytes(16);
  let progress = 0;
  await sendFrames(ch, id, data, (n) => (progress = n), () => false);
  assert.equal(progress, data.length);
  assert.equal(ch.bufferedAmountLowThreshold, LOW_WATER);
  assert.ok(ch.maxBuffered <= HIGH_WATER + 16 + CHUNK_SIZE, `max buffered ${ch.maxBuffered}`);
  let total = 0;
  for (const f of ch.sent) {
    const p = parseFrame(f)!;
    assert.equal(p.id, b64(id));
    total += p.chunk.length;
  }
  assert.equal(total, data.length);
});

test("sendFrames stops on cancel and on a closed channel", async () => {
  const ch = new FakeChannel();
  let sent = 0;
  await assert.rejects(
    sendFrames(ch, randomBytes(16), randomBytes(200_000), () => sent++, () => sent >= 3),
    (e: unknown) => e instanceof TransferCancelled,
  );
  assert.equal(sent, 3);
  const closed = new FakeChannel();
  closed.readyState = "closed";
  await assert.rejects(sendFrames(closed, randomBytes(16), randomBytes(10), () => undefined, () => false), /closed/);
});

test("path and file name helpers", () => {
  assert.equal(joinPath("", "Movies"), "Movies");
  assert.equal(joinPath("Movies", "a.mov"), "Movies/a.mov");
  assert.equal(parentPath("Movies/2026/a"), "Movies/2026");
  assert.equal(parentPath("Movies"), "");
  assert.equal(parentPath(""), "");
  for (const ok of ["a.mov", ".hidden", "My File (1).txt", "ü"]) assert.equal(isSafeEntryName(ok), true, ok);
  for (const bad of ["", ".", "..", "a/b", "a\\b", "a\u0000b", 5, null]) assert.equal(isSafeEntryName(bad), false, String(bad));
  assert.equal(safeDownloadName("../../etc/passwd"), "_.._etc_passwd");
  assert.equal(safeDownloadName("..."), "download");
  assert.equal(safeDownloadName("ok name.mov"), "ok name.mov");
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(5 * 1024 * 1024 * 1024), "5.0 GB");
});
