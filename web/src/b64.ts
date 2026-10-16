// Byte encodings used by the HR1 protocol (docs/PROTOCOL.md §2).
// These are encodings, not cryptography.

/** A byte array backed by a plain ArrayBuffer (what WebCrypto accepts). */
export type Bytes = Uint8Array<ArrayBuffer>;

const B64URL = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const B64URL_REV: Int16Array = (() => {
  const t = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64URL.length; i++) t[B64URL.charCodeAt(i)] = i;
  return t;
})();

export function bytes(n: number): Bytes {
  return new Uint8Array(new ArrayBuffer(n));
}

/** Copies any byte view (or ArrayBuffer) into a fresh ArrayBuffer-backed Uint8Array. */
export function toBytes(v: ArrayBuffer | ArrayBufferView): Bytes {
  if (v instanceof ArrayBuffer) return new Uint8Array(v.slice(0));
  const out = bytes(v.byteLength);
  out.set(new Uint8Array(v.buffer, v.byteOffset, v.byteLength));
  return out;
}

/** base64url without padding (RFC 4648 §5). */
export function b64(data: ArrayBuffer | ArrayBufferView): string {
  const b = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let out = "";
  let i = 0;
  for (; i + 2 < b.length; i += 3) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8) | b[i + 2]!;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]! + B64URL[n & 63]!;
  }
  const rem = b.length - i;
  if (rem === 1) {
    const n = b[i]! << 16;
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]!;
  } else if (rem === 2) {
    const n = (b[i]! << 16) | (b[i + 1]! << 8);
    out += B64URL[(n >> 18) & 63]! + B64URL[(n >> 12) & 63]! + B64URL[(n >> 6) & 63]!;
  }
  return out;
}

export class EncodingError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "EncodingError";
  }
}

/**
 * Decodes base64url without padding. Rejects padding, the standard-alphabet
 * characters "+" and "/", whitespace, impossible lengths and non-canonical
 * trailing bits (so every byte string has exactly one accepted encoding).
 */
export function unb64(s: string): Bytes {
  if (typeof s !== "string") throw new EncodingError("base64url: not a string");
  const len = s.length;
  if (len % 4 === 1) throw new EncodingError("base64url: bad length");
  const out = bytes(Math.floor((len * 3) / 4));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < len; i++) {
    const c = s.charCodeAt(i);
    const v = c < 128 ? B64URL_REV[c]! : -1;
    if (v < 0) throw new EncodingError("base64url: bad character");
    acc = (acc << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) throw new EncodingError("base64url: non-canonical");
  return out;
}

/** Decodes base64url and checks the decoded length. */
export function unb64Len(s: string, n: number): Bytes {
  const b = unb64(s);
  if (b.length !== n) throw new EncodingError(`expected ${n} bytes, got ${b.length}`);
  return b;
}

export function hex(data: ArrayBuffer | ArrayBufferView): string {
  const b = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

export function unhex(s: string): Bytes {
  if (s.length % 2 !== 0 || /[^0-9a-fA-F]/.test(s)) throw new EncodingError("hex: bad input");
  const out = bytes(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

/** Lowercase RFC 4648 base32 without padding. */
export function base32Lower(data: Uint8Array): string {
  const A = "abcdefghijklmnopqrstuvwxyz234567";
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const x of data) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += A[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += A[(acc << (5 - bits)) & 31];
  return out;
}

/** Uppercase RFC 4648 base32 without padding (join codes, PROTOCOL.md §10.2). */
export function base32Upper(data: Uint8Array): string {
  return base32Lower(data).toUpperCase();
}

const B32_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/**
 * Decodes uppercase RFC 4648 base32 without padding. Strict: only A–Z and
 * 2–7, no impossible lengths, no non-canonical trailing bits.
 */
export function unbase32(s: string): Bytes {
  if (typeof s !== "string") throw new EncodingError("base32: not a string");
  const rem = s.length % 8;
  if (rem === 1 || rem === 3 || rem === 6) throw new EncodingError("base32: bad length");
  const out = bytes(Math.floor((s.length * 5) / 8));
  let o = 0;
  let acc = 0;
  let bits = 0;
  for (let i = 0; i < s.length; i++) {
    const v = B32_UPPER.indexOf(s[i]!);
    if (v < 0) throw new EncodingError("base32: bad character");
    acc = (acc << 5) | v;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (acc >> bits) & 0xff;
    }
    acc &= (1 << bits) - 1;
  }
  if (acc !== 0) throw new EncodingError("base32: non-canonical");
  return out;
}

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

export function utf8(s: string): Bytes {
  return toBytes(enc.encode(s));
}

export function fromUtf8(b: Uint8Array): string {
  return dec.decode(b);
}

export function concat(...parts: Uint8Array[]): Bytes {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = bytes(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!;
  return d === 0;
}

/** Cryptographically secure random bytes (WebCrypto CSPRNG). */
export function randomBytes(n: number): Bytes {
  const b = bytes(n);
  // getRandomValues fills at most 65536 bytes per call.
  for (let off = 0; off < n; off += 65536) crypto.getRandomValues(b.subarray(off, Math.min(n, off + 65536)));
  return b;
}
