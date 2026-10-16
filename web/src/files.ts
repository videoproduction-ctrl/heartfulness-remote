// File transfer helpers for the `file` data channel (docs/PROTOCOL.md §8):
// binary frames = 16-byte transfer id ‖ chunk (≤ 16 KiB). Integrity is
// checked with SHA-256 (WebCrypto) over the whole file in both directions.

import { type Bytes, b64, bytes } from "./b64";
import { sha256 } from "./hr1";

export const CHUNK_SIZE = 16 * 1024;
export const ID_LEN = 16;
/**
 * WebCrypto has no streaming SHA-256, so the whole file is hashed in memory.
 * Keep transfers below this size so phones and browsers don't run out of memory.
 */
export const MAX_TRANSFER_BYTES = 2 * 1024 * 1024 * 1024;
export const HIGH_WATER = 1024 * 1024;
export const LOW_WATER = 256 * 1024;

export function frame(id: Uint8Array, chunk: Uint8Array): Bytes {
  if (id.length !== ID_LEN) throw new Error("transfer id must be 16 bytes");
  if (chunk.length > CHUNK_SIZE) throw new Error("chunk too large");
  const out = bytes(ID_LEN + chunk.length);
  out.set(id, 0);
  out.set(chunk, ID_LEN);
  return out;
}

/** Splits `data` into frames of at most CHUNK_SIZE payload bytes. An empty file yields no frames. */
export function* frames(id: Uint8Array, data: Uint8Array, chunkSize = CHUNK_SIZE): Generator<{ frame: Bytes; end: number }> {
  if (chunkSize <= 0 || chunkSize > CHUNK_SIZE) throw new Error("bad chunk size");
  for (let off = 0; off < data.length; off += chunkSize) {
    const end = Math.min(off + chunkSize, data.length);
    yield { frame: frame(id, data.subarray(off, end)), end };
  }
}

export function parseFrame(buf: ArrayBuffer | ArrayBufferView): { id: string; chunk: Uint8Array } | null {
  const u = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  if (u.length < ID_LEN || u.length > ID_LEN + CHUNK_SIZE) return null;
  return { id: b64(u.subarray(0, ID_LEN)), chunk: u.subarray(ID_LEN) };
}

export async function sha256B64(data: Uint8Array): Promise<string> {
  return b64(await sha256(data));
}

/** Minimal RTCDataChannel surface used for sending (lets tests use a fake). */
export interface ChannelLike {
  readonly readyState: string;
  readonly bufferedAmount: number;
  bufferedAmountLowThreshold: number;
  send(data: Bytes): void;
  addEventListener(type: "bufferedamountlow" | "close", fn: () => void): void;
  removeEventListener(type: "bufferedamountlow" | "close", fn: () => void): void;
}

function waitLow(ch: ChannelLike): Promise<void> {
  return new Promise<void>((resolve) => {
    const on = () => {
      ch.removeEventListener("bufferedamountlow", on);
      ch.removeEventListener("close", on);
      resolve();
    };
    ch.addEventListener("bufferedamountlow", on);
    ch.addEventListener("close", on);
    if (ch.bufferedAmount <= ch.bufferedAmountLowThreshold) on();
  });
}

export class TransferCancelled extends Error {
  constructor() {
    super("cancelled");
    this.name = "TransferCancelled";
  }
}

/**
 * Sends `data` as frames, pausing whenever more than HIGH_WATER bytes are
 * queued in the channel (backpressure) until it drains below LOW_WATER.
 */
export async function sendFrames(
  ch: ChannelLike,
  id: Uint8Array,
  data: Uint8Array,
  onProgress: (sentBytes: number) => void,
  isCancelled: () => boolean,
): Promise<void> {
  ch.bufferedAmountLowThreshold = LOW_WATER;
  for (const { frame: f, end } of frames(id, data)) {
    if (isCancelled()) throw new TransferCancelled();
    if (ch.bufferedAmount > HIGH_WATER) await waitLow(ch);
    if (isCancelled()) throw new TransferCancelled();
    if (ch.readyState !== "open") throw new Error("The connection closed during the transfer.");
    ch.send(f);
    onProgress(end);
  }
}

/** Collects a download's chunks and verifies its SHA-256 before handing it out. */
export class Assembler {
  private buf: Bytes;
  received = 0;

  constructor(
    readonly id: string,
    readonly name: string,
    readonly size: number,
  ) {
    if (!Number.isSafeInteger(size) || size < 0) throw new Error("Invalid file size.");
    if (size > MAX_TRANSFER_BYTES) throw new Error("This file is too large to download in the browser (limit 2 GB).");
    this.buf = bytes(size);
  }

  push(chunk: Uint8Array): void {
    if (this.received + chunk.length > this.size) throw new Error("Received more data than announced.");
    this.buf.set(chunk, this.received);
    this.received += chunk.length;
  }

  get complete(): boolean {
    return this.received === this.size;
  }

  async finish(expectedSha256: string): Promise<Blob> {
    if (!this.complete) throw new Error("The file arrived incomplete.");
    const got = await sha256B64(this.buf);
    if (got !== expectedSha256) throw new Error("The file was damaged in transfer (checksum mismatch).");
    const blob = new Blob([this.buf], { type: "application/octet-stream" });
    this.buf = bytes(0);
    return blob;
  }
}

// ---------------------------------------------------------------- paths & names

/** Entry names from the Mac must be single path components. */
export function isSafeEntryName(name: unknown): name is string {
  return typeof name === "string" && name !== "" && name !== "." && name !== ".." && !/[/\\\u0000]/.test(name) && name.length <= 1024;
}

export function joinPath(dir: string, name: string): string {
  return dir === "" ? name : `${dir}/${name}`;
}

export function parentPath(path: string): string {
  const i = path.lastIndexOf("/");
  return i < 0 ? "" : path.slice(0, i);
}

export function safeDownloadName(name: string): string {
  const n = name.replace(/[/\\\u0000-\u001f\u007f]/g, "_").replace(/^\.+/, "").trim();
  return n.slice(0, 200) || "download";
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "";
  if (n < 1024) return `${n} B`;
  const u = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${u[i]}`;
}
