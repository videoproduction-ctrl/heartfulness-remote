// Parsing of the one-time links shown as QR codes on a Mac:
//   first setup      `#setup=<b64 T>.<b64 hostPub>`   (PROTOCOL.md §4, T = 32 bytes)
//   add another Mac  `#join=<b64 T>.<b64 hostPub>`    (PROTOCOL.md §10.2, T = 10 bytes)

import { type Bytes, unb64Len } from "./b64";

export interface SetupFragment {
  t: Bytes;
  hostPub: Bytes;
}

export type JoinFragment = SetupFragment;

export type Fragment = { kind: "setup"; frag: SetupFragment } | { kind: "join"; frag: JoinFragment } | { kind: "invalid"; of: "setup" | "join" };

function parseSecretLink(hash: string, prefix: string, tLen: number): SetupFragment | "invalid" | null {
  if (!hash.startsWith(prefix)) return null;
  const v = hash.slice(prefix.length);
  const dot = v.indexOf(".");
  if (dot < 0 || v.indexOf(".", dot + 1) >= 0) return "invalid";
  try {
    return { t: unb64Len(v.slice(0, dot), tLen), hostPub: unb64Len(v.slice(dot + 1), 32) };
  } catch {
    return "invalid";
  }
}

/** Returns null when the hash is not a setup link, "invalid" when it is malformed. */
export function parseSetupFragment(hash: string): SetupFragment | "invalid" | null {
  return parseSecretLink(hash, "#setup=", 32);
}

/** Returns null when the hash is not a join link, "invalid" when it is malformed. */
export function parseJoinFragment(hash: string): JoinFragment | "invalid" | null {
  return parseSecretLink(hash, "#join=", 10);
}

/** Classifies a hash as a setup link, a join link, a malformed one of those, or nothing (null). */
export function parseFragment(hash: string): Fragment | null {
  const s = parseSetupFragment(hash);
  if (s === "invalid") return { kind: "invalid", of: "setup" };
  if (s) return { kind: "setup", frag: s };
  const j = parseJoinFragment(hash);
  if (j === "invalid") return { kind: "invalid", of: "join" };
  if (j) return { kind: "join", frag: j };
  return null;
}

/**
 * Reads a setup/join secret from the address bar and removes it immediately
 * (history.replaceState) so it doesn't linger in history, tabs or screenshots.
 */
export function takeFragment(): Fragment | null {
  const hash = location.hash;
  if (!hash.startsWith("#setup=") && !hash.startsWith("#join=")) return null;
  history.replaceState(null, "", location.pathname + location.search);
  return parseFragment(hash);
}
