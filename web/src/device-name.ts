// Friendly default device names, e.g. "iPhone Safari" or "Windows Edge".

export interface UAInfo {
  userAgent: string;
  maxTouchPoints?: number;
  app?: boolean; // running inside the Tauri app
}

export function detectOS(ua: string, maxTouchPoints = 0): string {
  if (/iPhone/.test(ua)) return "iPhone";
  if (/iPad/.test(ua)) return "iPad";
  // iPadOS 13+ reports itself as a Mac; touch support gives it away.
  if (/Macintosh/.test(ua) && maxTouchPoints > 1) return "iPad";
  if (/Android/.test(ua)) return /Mobile/.test(ua) ? "Android phone" : "Android tablet";
  if (/CrOS/.test(ua)) return "Chromebook";
  if (/Windows/.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/.test(ua)) return "Mac";
  if (/Linux/.test(ua)) return "Linux";
  return "";
}

export function detectBrowser(ua: string): string {
  if (/EdgiOS|EdgA|Edg\//.test(ua)) return "Edge";
  if (/OPR\/|OPT\//.test(ua)) return "Opera";
  if (/SamsungBrowser/.test(ua)) return "Samsung Internet";
  if (/FxiOS|Firefox\//.test(ua)) return "Firefox";
  if (/CriOS|Chrome\/|Chromium\//.test(ua)) return "Chrome";
  if (/Safari\//.test(ua)) return "Safari";
  return "";
}

/** True for Apple platforms, where ⌘ is the natural shortcut key. */
export function isApple(ua: string): boolean {
  return /Macintosh|Mac OS X|iPhone|iPad|iPod/.test(ua);
}

export function defaultDeviceName(info: UAInfo): string {
  const os = detectOS(info.userAgent, info.maxTouchPoints ?? 0);
  if (info.app) {
    if (os === "Windows") return "Windows PC (app)";
    if (os === "Mac") return "Mac (app)";
    return os ? `${os} (app)` : "Desktop app";
  }
  const br = detectBrowser(info.userAgent);
  const name = [os, br].filter(Boolean).join(" ");
  return name || "Web browser";
}

export const MAX_NAME_LENGTH = 48;

/** Trims, collapses whitespace, strips control characters and limits length. */
export function cleanDeviceName(s: string): string {
  const t = s.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, "").replace(/\s+/g, " ").trim();
  return [...t].slice(0, MAX_NAME_LENGTH).join("");
}
