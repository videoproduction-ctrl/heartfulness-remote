// Clipboard sync between this device and the Mac, without loops:
//   Mac → here: writeText while the page is focused (or at the next tap/key
//               press when the browser requires a user gesture);
//   here → Mac: on paste events, on focus when read permission is already
//               granted, or explicitly via "Send clipboard".
// A text that just arrived from one side is never sent back to it.

import { utf8 } from "./b64";

export const MAX_CLIP_BYTES = 1024 * 1024;

export class ClipboardSync {
  enabled: boolean;
  private lastFromRemote: string | null = null;
  private lastSent: string | null = null;
  private pending: string | null = null;

  constructor(
    enabled: boolean,
    private readonly sendClip: (text: string) => boolean,
    private readonly notify: (msg: string) => void = () => undefined,
  ) {
    this.enabled = enabled;
  }

  /** Text received from the Mac. */
  onRemote(text: unknown): void {
    if (!this.enabled || typeof text !== "string") return;
    if (text === this.lastSent) {
      // The Mac echoed what we just sent: it's already on our clipboard.
      this.lastFromRemote = text;
      return;
    }
    this.lastFromRemote = text;
    this.pending = text;
    if (document.hasFocus()) void this.flushPending();
  }

  /** Writes a pending Mac clipboard; call from user gestures and on focus. */
  async flushPending(): Promise<void> {
    const t = this.pending;
    if (t === null || !navigator.clipboard?.writeText) return;
    try {
      await navigator.clipboard.writeText(t);
      if (this.pending === t) this.pending = null;
    } catch {
      /* needs a user gesture (Safari) or focus; retried on the next one */
    }
  }

  /** Decides whether `text` should go to the Mac; sends it if so. */
  offer(text: string, explicit = false): boolean {
    if (!explicit && !this.enabled) return false;
    if (text === "") return false;
    if (!explicit && (text === this.lastFromRemote || text === this.lastSent)) return false;
    if (utf8(text).length > MAX_CLIP_BYTES) {
      this.notify("The clipboard is too large to send (limit 1 MB of text).");
      return false;
    }
    if (!this.sendClip(text)) return false;
    this.lastSent = text;
    return true;
  }

  onPaste(e: ClipboardEvent): void {
    const text = e.clipboardData?.getData("text/plain") ?? "";
    e.preventDefault();
    this.offer(text);
  }

  /** On window focus: read the clipboard only if permission was already granted (never prompt). */
  async onFocus(): Promise<void> {
    void this.flushPending();
    if (!this.enabled || !navigator.clipboard?.readText) return;
    try {
      const st = await navigator.permissions.query({ name: "clipboard-read" as PermissionName });
      if (st.state !== "granted") return;
      this.offer(await navigator.clipboard.readText());
    } catch {
      /* not supported (Firefox, Safari): paste events and "Send clipboard" still work */
    }
  }

  /** Explicit user action ("Send clipboard" / Ctrl+Alt+Shift+V): may show the browser's paste prompt. */
  async sendNow(): Promise<boolean> {
    if (!navigator.clipboard?.readText) {
      this.notify("This browser doesn't allow reading the clipboard. Press Ctrl+V (⌘V) inside the session instead.");
      return false;
    }
    let text: string;
    try {
      text = await navigator.clipboard.readText();
    } catch {
      this.notify("Clipboard access was not allowed.");
      return false;
    }
    if (text === "") {
      this.notify("Your clipboard is empty (or holds no text).");
      return false;
    }
    const ok = this.offer(text, true);
    if (ok) this.notify("Clipboard sent to your Mac.");
    return ok;
  }
}
