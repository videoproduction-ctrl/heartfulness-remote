// Desktop-app sign-in codes ("ABCD-EFGH"), typed by the owner on #link.

/** "abcd efgh" / "ABCD-EFGH" / "abcdefgh" → "ABCD-EFGH" (or "" if not 8 code characters). */
export function normalizeLinkCode(s: string): string {
  const c = s.toUpperCase().replace(/[^A-Z0-9]/g, "");
  return c.length === 8 ? `${c.slice(0, 4)}-${c.slice(4)}` : "";
}

/** Formats partial input while typing: "abcde" → "ABCD-E". */
export function formatLinkCodeInput(s: string): string {
  const raw = s.toUpperCase().replace(/[^A-Z0-9]/g, "").slice(0, 8);
  return raw.length > 4 ? `${raw.slice(0, 4)}-${raw.slice(4)}` : raw;
}
