import { test } from "node:test";
import assert from "node:assert/strict";
import { b64, base32Lower, concat, equalBytes, fromUtf8, hex, randomBytes, unb64, unb64Len, unhex, utf8 } from "../src/b64";

const enc = (s: string) => new TextEncoder().encode(s);

test("base64url known vectors (RFC 4648, url alphabet, no padding)", () => {
  const cases: Array<[string, string]> = [
    ["", ""],
    ["f", "Zg"],
    ["fo", "Zm8"],
    ["foo", "Zm9v"],
    ["foob", "Zm9vYg"],
    ["fooba", "Zm9vYmE"],
    ["foobar", "Zm9vYmFy"],
  ];
  for (const [plain, coded] of cases) {
    assert.equal(b64(enc(plain)), coded);
    assert.equal(fromUtf8(unb64(coded)), plain);
  }
  assert.equal(b64(new Uint8Array([0xfb, 0xff, 0xbf])), "-_-_");
  assert.deepEqual([...unb64("-_-_")], [0xfb, 0xff, 0xbf]);
});

test("base64url roundtrip for random data of every length 0..300", () => {
  for (let n = 0; n <= 300; n++) {
    const d = randomBytes(n);
    const s = b64(d);
    assert.doesNotMatch(s, /[+/=]/);
    assert.ok(equalBytes(unb64(s), d), `length ${n}`);
  }
});

test("base64url rejects padding, std alphabet, bad length and non-canonical input", () => {
  for (const bad of ["Zg==", "Zm8=", "a+b/", "Z", "Zm9vY", "Zh", "Zm9", "Z g", "éa"]) {
    assert.throws(() => unb64(bad), `rejects ${JSON.stringify(bad)}`);
  }
  // "Zm9" would be canonical only with zero trailing bits ("Zm8").
  assert.equal(fromUtf8(unb64("Zm8")), "fo");
  assert.throws(() => unb64Len("Zm8", 3), /expected 3 bytes/);
  assert.equal(unb64Len("Zm9v", 3).length, 3);
  // Works on views with an offset.
  const big = enc("xxfooyy");
  assert.equal(b64(big.subarray(2, 5)), "Zm9v");
});

test("hex, base32, utf8 and concat helpers", () => {
  assert.equal(hex(new Uint8Array([0, 1, 0xab, 0xff])), "0001abff");
  assert.deepEqual([...unhex("0001abff")], [0, 1, 0xab, 0xff]);
  assert.throws(() => unhex("abc"));
  assert.throws(() => unhex("zz"));
  // RFC 4648 base32 vectors (lower-case, no padding).
  assert.equal(base32Lower(enc("")), "");
  assert.equal(base32Lower(enc("f")), "my");
  assert.equal(base32Lower(enc("fo")), "mzxq");
  assert.equal(base32Lower(enc("foo")), "mzxw6");
  assert.equal(base32Lower(enc("foob")), "mzxw6yq");
  assert.equal(base32Lower(enc("fooba")), "mzxw6ytb");
  assert.equal(base32Lower(enc("foobar")), "mzxw6ytboi");
  assert.equal(fromUtf8(utf8("Phone ✓")), "Phone ✓");
  assert.equal(utf8("✓").length, 3);
  assert.deepEqual([...concat(new Uint8Array([1]), new Uint8Array([]), new Uint8Array([2, 3]))], [1, 2, 3]);
  assert.equal(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2])), true);
  assert.equal(equalBytes(new Uint8Array([1, 2]), new Uint8Array([1, 3])), false);
  assert.equal(equalBytes(new Uint8Array([1]), new Uint8Array([1, 0])), false);
});
