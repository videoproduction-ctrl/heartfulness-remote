// Keyboard helpers: Ctrl⇄⌘ remapping and client-side shortcuts.

/**
 * With "Use Ctrl as ⌘" on (the default for Windows/Linux/Android clients),
 * Control and Meta swap places so Ctrl+C on a PC keyboard becomes ⌘C on the
 * Mac (and the Windows key becomes Control).
 */
export function remapCode(code: string, ctrlAsCmd: boolean): string {
  if (!ctrlAsCmd) return code;
  switch (code) {
    case "ControlLeft":
      return "MetaLeft";
    case "ControlRight":
      return "MetaRight";
    case "MetaLeft":
      return "ControlLeft";
    case "MetaRight":
      return "ControlRight";
    default:
      return code;
  }
}

export type ShortcutAction = "fullscreen" | "disconnect" | "keyboard-lock" | "upload" | "send-clipboard" | "quality" | "help";

export interface ShortcutDef {
  code: string;
  key: string;
  action: ShortcutAction;
  label: string;
}

/** All client shortcuts are Ctrl+Alt+Shift+<key> (Ctrl+Option+Shift on a Mac keyboard). */
export const SHORTCUTS: readonly ShortcutDef[] = [
  { code: "KeyF", key: "F", action: "fullscreen", label: "Full screen on/off" },
  { code: "KeyQ", key: "Q", action: "disconnect", label: "Disconnect" },
  { code: "KeyK", key: "K", action: "keyboard-lock", label: "Capture system keys (⌘Tab, Esc…) in full screen" },
  { code: "KeyU", key: "U", action: "upload", label: "Upload files to your Mac" },
  { code: "KeyV", key: "V", action: "send-clipboard", label: "Send this computer's clipboard to your Mac" },
  { code: "KeyS", key: "S", action: "quality", label: "Switch quality (Auto → Sharp → Smooth)" },
  { code: "KeyH", key: "H", action: "help", label: "Show this help" },
];

export interface KeyLike {
  code: string;
  ctrlKey: boolean;
  altKey: boolean;
  shiftKey: boolean;
  metaKey: boolean;
}

export function matchShortcut(e: KeyLike): ShortcutAction | null {
  if (!(e.ctrlKey && e.altKey && e.shiftKey) || e.metaKey) return null;
  const s = SHORTCUTS.find((d) => d.code === e.code);
  return s ? s.action : null;
}

/** Modifier codes, for tracking which keys are currently held. */
export const MODIFIER_CODES = new Set([
  "ShiftLeft",
  "ShiftRight",
  "ControlLeft",
  "ControlRight",
  "AltLeft",
  "AltRight",
  "MetaLeft",
  "MetaRight",
  "CapsLock",
]);

/** Valid KeyboardEvent.code values look like "KeyA", "Digit1", "F12", "NumpadEnter"… */
export function isForwardableCode(code: string): boolean {
  return /^[A-Z][A-Za-z0-9]{1,30}$/.test(code) && code !== "Unidentified";
}
