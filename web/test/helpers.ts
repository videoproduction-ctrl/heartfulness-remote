// Test helpers: deterministic Ed25519 keys from the seeds in testdata/vectors.json.
import { type Bytes, concat, toBytes, unhex } from "../src/b64";
import type { Signer } from "../src/hr1";

const PKCS8_ED25519_PREFIX = unhex("302e020100300506032b657004220420");

/** Builds a Signer from a raw 32-byte Ed25519 seed (tests only). */
export async function signerFromSeed(seedHex: string, pub: Bytes): Promise<Signer> {
  const pkcs8 = concat(PKCS8_ED25519_PREFIX, unhex(seedHex));
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  return {
    pub,
    async sign(data: Bytes): Promise<Bytes> {
      return toBytes(await crypto.subtle.sign({ name: "Ed25519" }, key, data));
    },
  };
}

export async function randomSigner(): Promise<Signer & { publicKey: CryptoKey }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"])) as CryptoKeyPair;
  const pub = toBytes(await crypto.subtle.exportKey("raw", kp.publicKey));
  return {
    pub,
    publicKey: kp.publicKey,
    async sign(data: Bytes): Promise<Bytes> {
      return toBytes(await crypto.subtle.sign({ name: "Ed25519" }, kp.privateKey, data));
    },
  };
}
