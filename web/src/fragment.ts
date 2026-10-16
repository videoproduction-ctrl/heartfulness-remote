// Parsing of the one-time setup link `#setup=<b64 T>.<b64 hostPub>` (PROTOCOL.md §4).

import { type Bytes, unb64Len } from "./b64";

export interface SetupFragment {
  t: Bytes;
  hostPub: Bytes;
}

/** Returns null when the hash is not a setup link, "invalid" when it is malformed. */
export function parseSetupFragment(hash: string): SetupFragment | "invalid" | null {
  if (!hash.startsWith("#setup=")) return null;
  const v = hash.slice("#setup=".length);
  const dot = v.indexOf(".");
  if (dot < 0 || v.indexOf(".", dot + 1) >= 0) return "invalid";
  try {
    return { t: unb64Len(v.slice(0, dot), 32), hostPub: unb64Len(v.slice(dot + 1), 32) };
  } catch {
    return "invalid";
  }
}

/**
 * Reads the setup secret from the address bar and removes it immediately
 * (history.replaceState) so it doesn't linger in history, tabs or screenshots.
 */
export function takeSetupFragment(): SetupFragment | "invalid" | null {
  const hash = location.hash;
  if (!hash.startsWith("#setup=")) return null;
  history.replaceState(null, "", location.pathname + location.search);
  return parseSetupFragment(hash);
}
