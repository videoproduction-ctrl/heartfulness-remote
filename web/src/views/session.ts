// The remote desktop: full-window video, input capture, toolbar, latency
// pill, clipboard sync, files panel and help sheet.

import type { App, View } from "../app";
import { ClipboardSync } from "../clipboard";
import { isApple } from "../device-name";
import { append, h, replace } from "../dom";
import { formatBytes, isSafeEntryName, joinPath, parentPath } from "../files";
import { FilesController, type LsResult, type Transfer } from "../filexfer";
import { type IconName, icon } from "../icons";
import { InputController } from "../input";
import { SHORTCUTS, type ShortcutAction } from "../keymap";
import { byeText, type EndKind, RemoteSession, type Stage } from "../rtc";
import { latencyLevel, rates, type RawStat, type Snapshot, snapshot } from "../stats";
import { button, iconButton, openSheet, type Sheet, spinner, toast } from "../ui";

type Quality = "auto" | "sharp" | "smooth";

interface DisplayInfo {
  id: string | number;
  name: string;
  width: number;
  height: number;
  primary: boolean;
}

interface Prefs {
  ctrlAsCmd: boolean;
  clipboard: boolean;
  quality: Quality;
  muted: boolean;
}

const AUTO_RECONNECT_MAX = 3;

const QUALITY_LABEL: Record<Quality, string> = {
  auto: "Auto",
  sharp: "Sharp — for video editing",
  smooth: "Smooth",
};
const QUALITY_HINT: Record<Quality, string> = {
  auto: "Adapts to your connection",
  sharp: "Crisp detail and true colours, uses more bandwidth",
  smooth: "Highest frame rate, softer detail",
};

function loadPrefs(): Prefs {
  const get = (k: string): string | null => {
    try {
      return localStorage.getItem(`hr.${k}`);
    } catch {
      return null;
    }
  };
  const q = get("quality");
  return {
    ctrlAsCmd: get("ctrlAsCmd") === null ? !isApple(navigator.userAgent) : get("ctrlAsCmd") === "1",
    clipboard: get("clipboard") !== "0",
    quality: q === "sharp" || q === "smooth" ? q : "auto",
    muted: get("muted") === "1",
  };
}

function savePref(k: keyof Prefs, v: string | boolean): void {
  try {
    localStorage.setItem(`hr.${k}`, typeof v === "boolean" ? (v ? "1" : "0") : v);
  } catch {
    /* private mode */
  }
}

type PolicyLike = { allowsFeature?: (f: string) => boolean };
type KeyboardAPI = { lock?: (codes?: string[]) => Promise<void>; unlock?: () => void };

export function sessionView(app: App, hostPub: string): View {
  const prefs = loadPrefs();
  const macName = () => app.macName(hostPub);
  const offs: Array<() => void> = [];
  let destroyed = false;
  let session: RemoteSession | null = null;
  let files: FilesController | null = null;
  let input: InputController | null = null;
  let displays: DisplayInfo[] = [];
  let activeDisplay: string | number | null = null;
  let features = { audio: true, clipboard: true, files: true };
  let keyboardLocked = false;
  /** True once media is flowing for the current session (overlay hidden). */
  let live = false;
  /** Automatic reconnects after a dropped connection (reset once live again). */
  let autoTries = 0;
  let autoTimer: ReturnType<typeof setTimeout> | null = null;
  let wakeLock: { release(): Promise<void> } | null = null;
  let filesSheet: Sheet | null = null;
  let renderFilesPanel: (() => void) | null = null;
  let popoverEl: HTMLElement | null = null;
  let statsTimer: ReturnType<typeof setInterval> | null = null;
  let pingTimer: ReturnType<typeof setInterval> | null = null;
  let prevSnap: Snapshot | null = null;
  let pingRtt: number | null = null;
  let pingAt = 0;
  let pingId = 0;
  const pings = new Map<number, number>();
  const apple = isApple(navigator.userAgent);

  // ---------------------------------------------------------- elements
  const root = h("div", { class: "session", testid: "session-view" });
  const video = h("video", { class: "session-video", testid: "session-video", attrs: { playsinline: true, autoplay: true } });
  video.disablePictureInPicture = true;
  // Safety net: once frames are actually playing on a connected session, the
  // connecting overlay must not stay on top of the picture.
  video.addEventListener("playing", () => {
    if (session?.connected && !session.ended && !overlay.hidden && root.dataset["stage"] !== "ended") {
      live = true;
      setStage("connected");
      overlay.hidden = true;
    }
  });
  (video as HTMLVideoElement & { disableRemotePlayback?: boolean }).disableRemotePlayback = true;
  const surface = h("div", { class: "surface", testid: "session-surface", attrs: { tabindex: 0, "aria-label": "Your Mac's screen" } });
  const stage = h("div", { class: "stage" }, video, surface);
  const kb = h("textarea", {
    class: "kb-capture",
    testid: "keyboard-input",
    attrs: { autocapitalize: "off", autocomplete: "off", autocorrect: "off", spellcheck: "false", rows: 1, "aria-label": "Type on your Mac" },
  });
  kb.dataset["kbCapture"] = "1";
  const uploadInput = h("input", { class: "visually-hidden", testid: "upload-input", attrs: { type: "file", multiple: true, tabindex: -1 } });
  uploadInput.addEventListener("change", () => {
    if (uploadInput.files && uploadInput.files.length) files?.enqueue([...uploadInput.files]);
    uploadInput.value = "";
  });

  const pillRtt = h("span", { class: "pill-rtt", testid: "latency-rtt", text: "– ms" });
  const pillFps = h("span", { class: "pill-extra", testid: "latency-fps", text: "– fps" });
  const pillMbps = h("span", { class: "pill-extra", testid: "latency-mbps", text: "– Mbps" });
  const pillRoute = h("span", { testid: "latency-route", text: "…" });
  const pill = h(
    "div",
    { class: "latency-pill", testid: "latency-pill", attrs: { "data-level": "unknown", "aria-label": "Connection quality" } },
    h("span", { class: "pill-dot", attrs: { "aria-hidden": "true" } }),
    pillRtt,
    h("span", { class: "pill-sep pill-extra", text: "·" }),
    pillFps,
    h("span", { class: "pill-sep pill-extra", text: "·" }),
    pillMbps,
    h("span", { class: "pill-sep", text: "·" }),
    pillRoute,
  );
  pill.hidden = true;

  const overlay = h("div", { class: "session-overlay", testid: "session-overlay" });
  const unmute = button({
    label: "Turn on sound",
    testid: "session-unmute",
    icon: "speaker",
    variant: "tinted",
    onClick: () => {
      video.muted = false;
      prefs.muted = false;
      savePref("muted", false);
      void video.play().catch(() => undefined);
      unmute.hidden = true;
      updateToolbar();
    },
  });
  unmute.classList.add("unmute-btn");
  unmute.hidden = true;
  const dropzone = h("div", { class: "dropzone", testid: "dropzone" }, icon("upload"), h("span", { text: "Drop files to send them to your Mac" }));
  dropzone.hidden = true;

  // ---------------------------------------------------------- toolbar
  const tb = (name: IconName, label: string, testid: string, fn: () => void) => iconButton(name, label, testid, fn, "tool-btn");
  const btnFullscreen = tb("fullscreen", "Full screen (Ctrl+Alt+Shift+F)", "toolbar-fullscreen", () => void toggleFullscreen());
  const btnDisplay = tb("display", "Choose display", "toolbar-display", () => openDisplayMenu());
  const btnQuality = tb("sliders", "Quality (Ctrl+Alt+Shift+S)", "toolbar-quality", () => openQualityMenu());
  const btnAudio = tb("speaker", "Sound on/off", "toolbar-audio", () => toggleMute());
  const btnClipboard = tb("clipboard", "Clipboard", "toolbar-clipboard", () => openClipboardMenu());
  const btnFiles = tb("folder", "Files (Ctrl+Alt+Shift+U to upload)", "files-button", () => openFiles());
  const filesBadge = h("span", { class: "tool-badge", testid: "files-badge" });
  filesBadge.hidden = true;
  btnFiles.appendChild(filesBadge);
  const btnCmd = tb("command", "Use Ctrl as ⌘", "toolbar-ctrlcmd", () => toggleCtrlCmd());
  const btnKeyboard = tb("keyboard", "On-screen keyboard", "toolbar-keyboard", () => showKeyboard());
  const btnHelp = tb("help", "Help and shortcuts (Ctrl+Alt+Shift+H)", "toolbar-help", () => openHelp());
  const btnDisconnect = tb("power", "Disconnect (Ctrl+Alt+Shift+Q)", "disconnect-button", () => disconnect());
  btnDisconnect.classList.add("tool-danger");
  const toolbarMac = h("span", { class: "tool-mac", testid: "toolbar-mac-name", title: "Connected Mac", text: macName() });
  const toolbar = h(
    "div",
    { class: "toolbar", testid: "session-toolbar", attrs: { role: "toolbar", "aria-label": `Session controls for ${macName()}` } },
    toolbarMac,
    h("span", { class: "tool-sep", attrs: { "aria-hidden": "true" } }),
    btnFullscreen,
    btnDisplay,
    btnQuality,
    btnAudio,
    btnClipboard,
    btnFiles,
    btnCmd,
    btnKeyboard,
    btnHelp,
    h("span", { class: "tool-sep", attrs: { "aria-hidden": "true" } }),
    btnDisconnect,
  );
  const handle = h("button", { class: "toolbar-handle", testid: "toolbar-handle", attrs: { type: "button", "aria-label": "Show controls" } });
  handle.addEventListener("click", () => showToolbar(4000));
  const toolbarWrap = h("div", { class: "toolbar-wrap is-hidden" }, toolbar, handle);
  let tbTimer: ReturnType<typeof setTimeout> | null = null;
  let tbHover = false;
  toolbar.addEventListener("pointerenter", () => {
    tbHover = true;
    showToolbar();
  });
  toolbar.addEventListener("pointerleave", () => {
    tbHover = false;
    showToolbar(1500);
  });
  toolbar.addEventListener("focusin", () => showToolbar(6000));

  function showToolbar(ms = 2500): void {
    if (!session?.connected) return;
    toolbarWrap.classList.remove("is-hidden");
    if (tbTimer) clearTimeout(tbTimer);
    tbTimer = setTimeout(hideToolbar, ms);
  }

  function hideToolbar(): void {
    if (tbHover || popoverEl || toolbar.contains(document.activeElement)) {
      tbTimer = setTimeout(hideToolbar, 1500);
      return;
    }
    toolbarWrap.classList.add("is-hidden");
  }

  function setPressed(b: HTMLButtonElement, on: boolean): void {
    b.setAttribute("aria-pressed", on ? "true" : "false");
  }

  function updateToolbar(): void {
    const fs = !!document.fullscreenElement;
    replace(btnFullscreen, icon(fs ? "fullscreen-exit" : "fullscreen"));
    setPressed(btnFullscreen, fs);
    btnFullscreen.hidden = !document.fullscreenEnabled;
    btnDisplay.disabled = displays.length < 2;
    btnAudio.disabled = !features.audio;
    replace(btnAudio, icon(video.muted ? "speaker-off" : "speaker"));
    setPressed(btnAudio, !video.muted);
    btnAudio.dataset["muted"] = String(video.muted);
    btnClipboard.disabled = !features.clipboard;
    setPressed(btnClipboard, prefs.clipboard && features.clipboard);
    btnFiles.disabled = !features.files;
    setPressed(btnCmd, prefs.ctrlAsCmd);
    const n = files?.activeCount ?? 0;
    filesBadge.hidden = n === 0;
    filesBadge.textContent = n ? String(n) : "";
  }

  // ---------------------------------------------------------- popovers
  function closePopover(): void {
    popoverEl?.remove();
    popoverEl = null;
  }

  function popover(
    anchor: HTMLElement,
    testid: string,
    items: Array<{ label: string; hint?: string; testid: string; value?: string; checked?: boolean; onSelect: () => void }>,
  ): void {
    closePopover();
    const menu = h("div", { class: "popover", testid, attrs: { role: "menu" } });
    for (const it of items) {
      const b = h(
        "button",
        {
          class: "popover-item",
          testid: it.testid,
          attrs: {
            type: "button",
            role: it.checked === undefined ? "menuitem" : "menuitemradio",
            "aria-checked": it.checked === undefined ? null : String(it.checked),
            "data-value": it.value,
          },
        },
        h("span", { class: "popover-check" }, it.checked ? icon("check") : null),
        h("span", { class: "popover-label" }, h("span", { text: it.label }), it.hint ? h("small", { text: it.hint }) : null),
      );
      b.addEventListener("click", () => {
        closePopover();
        it.onSelect();
        showToolbar();
      });
      menu.appendChild(b);
    }
    const r = anchor.getBoundingClientRect();
    menu.style.top = `${Math.round(r.bottom + 8)}px`;
    menu.style.left = `${Math.round(Math.min(Math.max(r.left + r.width / 2, 150), window.innerWidth - 150))}px`;
    root.appendChild(menu);
    popoverEl = menu;
    (menu.querySelector("button") as HTMLButtonElement | null)?.focus();
    const onDown = (e: PointerEvent) => {
      if (!menu.contains(e.target as Node) && e.target !== anchor) cleanup();
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        e.stopPropagation();
        cleanup();
      }
    };
    const cleanup = () => {
      document.removeEventListener("pointerdown", onDown, true);
      document.removeEventListener("keydown", onKey, true);
      if (popoverEl === menu) closePopover();
    };
    document.addEventListener("pointerdown", onDown, true);
    document.addEventListener("keydown", onKey, true);
  }

  function openDisplayMenu(): void {
    popover(
      btnDisplay,
      "display-menu",
      displays.map((d, i) => ({
        label: d.name || `Display ${i + 1}`,
        hint: `${d.width}×${d.height}${d.primary ? " · main" : ""}`,
        testid: "display-option",
        value: String(d.id),
        checked: d.id === activeDisplay,
        onSelect: () => {
          if (session?.sendControl({ t: "select-display", id: d.id })) activeDisplay = d.id;
        },
      })),
    );
  }

  function setQuality(q: Quality): void {
    prefs.quality = q;
    savePref("quality", q);
    session?.sendControl({ t: "quality", mode: q });
  }

  function openQualityMenu(): void {
    popover(
      btnQuality,
      "quality-menu",
      (["auto", "sharp", "smooth"] as Quality[]).map((q) => ({
        label: QUALITY_LABEL[q],
        hint: QUALITY_HINT[q],
        testid: "quality-option",
        value: q,
        checked: prefs.quality === q,
        onSelect: () => setQuality(q),
      })),
    );
  }

  function openClipboardMenu(): void {
    popover(btnClipboard, "clipboard-menu", [
      {
        label: "Sync clipboard automatically",
        hint: "Copy on one side, paste on the other",
        testid: "clipboard-toggle",
        checked: prefs.clipboard,
        onSelect: () => {
          prefs.clipboard = !prefs.clipboard;
          clip.enabled = prefs.clipboard;
          savePref("clipboard", prefs.clipboard);
          updateToolbar();
          toast(prefs.clipboard ? "Clipboard sync is on." : "Clipboard sync is off.");
        },
      },
      { label: "Send my clipboard to the Mac now", testid: "clipboard-send", onSelect: () => void clip.sendNow() },
    ]);
  }

  function toggleMute(): void {
    video.muted = !video.muted;
    prefs.muted = video.muted;
    savePref("muted", video.muted);
    if (!video.muted) void video.play().catch(() => undefined);
    unmute.hidden = true;
    updateToolbar();
  }

  function toggleCtrlCmd(): void {
    prefs.ctrlAsCmd = !prefs.ctrlAsCmd;
    savePref("ctrlAsCmd", prefs.ctrlAsCmd);
    updateToolbar();
    toast(prefs.ctrlAsCmd ? "Ctrl now works as ⌘ Command on your Mac." : "Ctrl now works as Control on your Mac.");
  }

  function showKeyboard(): void {
    kb.value = "";
    kb.focus({ preventScroll: true });
  }

  // ---------------------------------------------------------- fullscreen & keyboard lock
  async function lockKeyboard(on: boolean): Promise<void> {
    const k = (navigator as Navigator & { keyboard?: KeyboardAPI }).keyboard;
    if (!k?.lock) {
      if (on) toast("This browser can't capture system keys. Use Chrome or Edge in full screen for that.");
      return;
    }
    try {
      if (on) {
        await k.lock();
        keyboardLocked = true;
      } else {
        k.unlock?.();
        keyboardLocked = false;
      }
    } catch {
      keyboardLocked = false;
    }
  }

  async function toggleFullscreen(): Promise<void> {
    try {
      if (document.fullscreenElement) {
        await document.exitFullscreen();
        return;
      }
      await root.requestFullscreen({ navigationUI: "hide" });
      // Let shortcuts like ⌘Tab, Esc and Ctrl+W reach the Mac (Chrome/Edge).
      await lockKeyboard(true);
    } catch {
      toast("Full screen isn't available here.");
    }
  }

  async function toggleKeyboardLock(): Promise<void> {
    if (keyboardLocked) {
      await lockKeyboard(false);
      toast("System keys are no longer captured.");
      return;
    }
    if (!document.fullscreenElement) {
      await toggleFullscreen();
      return;
    }
    await lockKeyboard(true);
    if (keyboardLocked) toast("System keys now go to your Mac. Hold Esc to leave full screen.");
  }

  const onFullscreen = () => {
    if (!document.fullscreenElement && keyboardLocked) void lockKeyboard(false);
    updateToolbar();
  };
  document.addEventListener("fullscreenchange", onFullscreen);
  offs.push(() => document.removeEventListener("fullscreenchange", onFullscreen));

  // ---------------------------------------------------------- help
  function openHelp(): void {
    const mods = apple ? "⌃ ⌥ ⇧ " : "Ctrl + Alt + Shift + ";
    const rows = SHORTCUTS.map((s) =>
      h("tr", { testid: "help-shortcut" }, h("td", null, h("kbd", { text: `${mods}${s.key}` })), h("td", { text: s.label })),
    );
    openSheet({
      title: "Help & shortcuts",
      testid: "help-sheet",
      content: [
        h("h3", { text: "Keyboard shortcuts" }),
        h("table", { class: "shortcuts" }, h("tbody", null, ...rows)),
        h("h3", { text: "Keyboard" }),
        h("p", {
          class: "sheet-text",
          text: "Everything you type goes to your Mac. With “Use Ctrl as ⌘” on (the ⌘ button), Ctrl+C / Ctrl+V on a Windows keyboard work like ⌘C / ⌘V. Some browser shortcuts (like Ctrl+W) only reach the Mac in full screen with system keys captured.",
        }),
        h("h3", { text: "Touch" }),
        h(
          "ul",
          { class: "steps" },
          h("li", { text: "Tap — click" }),
          h("li", { text: "Drag with one finger — move the pointer" }),
          h("li", { text: "Two-finger tap — right-click" }),
          h("li", { text: "Two-finger drag — scroll" }),
          h("li", { text: "Touch and hold, then drag — drag and drop" }),
          h("li", { text: "Keyboard button — type with the on-screen keyboard" }),
        ),
        h("h3", { text: "The coloured pill" }),
        h("p", {
          class: "sheet-text",
          text: "Shows the round-trip delay to your Mac (green under 40 ms, amber under 100 ms, red above), frames per second, bandwidth, and whether the connection is Direct or goes through the Relay server. Everything is end-to-end encrypted either way.",
        }),
      ],
    });
  }

  // ---------------------------------------------------------- files panel
  function transferRow(t: Transfer): HTMLElement {
    const pct = t.size > 0 ? Math.min(100, Math.round((t.done / t.size) * 100)) : t.state === "done" ? 100 : 0;
    const stateText: Record<Transfer["state"], string> = {
      hashing: "Preparing…",
      waiting: "Waiting for your Mac…",
      sending: `${pct}%`,
      receiving: `${pct}%`,
      verifying: "Checking…",
      done: t.dir === "up" ? "Sent" : "Downloaded",
      error: t.error ?? "Failed",
      cancelled: "Cancelled",
    };
    const progress = h("progress", { class: "progress", attrs: { max: 100 } });
    progress.value = pct;
    const active = !["done", "error", "cancelled"].includes(t.state);
    return h(
      "div",
      { class: `transfer transfer-${t.state}`, testid: "transfer-item", attrs: { "data-state": t.state, "data-dir": t.dir, "data-name": t.name } },
      h("span", { class: "item-icon" }, icon(t.dir === "up" ? "upload" : "download")),
      h(
        "div",
        { class: "item-text" },
        h("strong", { testid: "transfer-name", text: t.name }),
        progress,
        h("span", { class: "muted", testid: "transfer-state", text: `${stateText[t.state]} · ${formatBytes(t.size)}` }),
      ),
      active ? iconButton("close", `Cancel ${t.name}`, "transfer-cancel", () => files?.cancel(t.id)) : null,
    );
  }

  function openFiles(): void {
    if (!files || filesSheet) return;
    const f = files;
    let path = "";
    let listing: LsResult | null = null;
    let loading = false;
    let lsError: string | null = null;
    const transfersList = h("div", { class: "list", testid: "transfers-list" });
    const browse = h("div", { class: "list", testid: "files-list" });
    const pathEl = h("div", { class: "files-path", testid: "files-path" });
    const upBtn = iconButton("up", "Up one folder", "files-up", () => void go(parentPath(path)));
    const refresh = iconButton("refresh", "Refresh", "files-refresh", () => void go(path));

    const render = () => {
      const ts = [...f.transfers.values()].reverse();
      replace(
        transfersList,
        ts.length ? ts.map(transferRow) : h("p", { class: "muted", text: "Nothing sent or received yet." }),
        ts.some((t) => ["done", "error", "cancelled"].includes(t.state))
          ? button({ label: "Clear finished", testid: "transfers-clear", variant: "plain", onClick: () => f.clearFinished() })
          : null,
      );
      replace(pathEl, icon("folder"), h("span", { text: path === "" ? "Home" : `Home / ${path.split("/").join(" / ")}` }));
      upBtn.disabled = path === "";
      if (loading) {
        replace(browse, h("p", { class: "muted" }, spinner(""), " Loading…"));
      } else if (lsError) {
        replace(browse, h("p", { class: "error-box", text: lsError }));
      } else if (listing) {
        const entries = listing.entries.filter((e) => isSafeEntryName(e.name) && !e.name.startsWith("."));
        replace(
          browse,
          entries.length
            ? entries.map((e) => {
                const row = h(
                  "div",
                  {
                    class: `item file-entry${e.dir ? " is-folder" : ""}`,
                    testid: "file-entry",
                    attrs: e.dir
                      ? { "data-name": e.name, "data-dir": "1", role: "button", tabindex: 0, "aria-label": `Open folder ${e.name}` }
                      : { "data-name": e.name, "data-dir": "0" },
                  },
                  h("span", { class: "item-icon" }, icon(e.dir ? "folder" : "file")),
                  h("div", { class: "item-text" }, h("strong", { text: e.name }), h("span", { class: "muted", text: e.dir ? "Folder" : formatBytes(e.size) })),
                  e.dir
                    ? iconButton("forward", `Open ${e.name}`, "folder-open", () => void go(joinPath(path, e.name)))
                    : iconButton("download", `Download ${e.name}`, "download-button", () => {
                        f.download(joinPath(path, e.name));
                        toast(`Downloading “${e.name}”…`);
                      }),
                );
                if (e.dir) {
                  // The whole folder row opens it (click, Enter or Space).
                  const open = () => void go(joinPath(path, e.name));
                  row.addEventListener("click", (ev) => {
                    if (!(ev.target instanceof Element && ev.target.closest("button"))) open();
                  });
                  row.addEventListener("keydown", (ev) => {
                    if (ev.target !== row || (ev.key !== "Enter" && ev.key !== " ")) return;
                    ev.preventDefault();
                    open();
                  });
                }
                return row;
              })
            : h("p", { class: "muted", text: "This folder is empty." }),
        );
      }
    };

    const go = async (p: string) => {
      path = p;
      loading = true;
      lsError = null;
      render();
      try {
        listing = await f.ls(p);
        if (listing.error) lsError = `Can't open this folder: ${listing.error}`;
        path = listing.path || p;
      } catch (e) {
        lsError = e instanceof Error ? e.message : "Can't list files.";
      } finally {
        loading = false;
        render();
      }
    };

    filesSheet = openSheet({
      title: "Files",
      testid: "files-panel",
      side: true,
      onClose: () => {
        filesSheet = null;
        renderFilesPanel = null;
        surface.focus({ preventScroll: true });
      },
      content: [
        h("h3", { text: "Send to your Mac" }),
        h(
          "div",
          { class: "stack" },
          button({ label: "Choose files…", testid: "upload-button", icon: "upload", variant: "primary", onClick: () => uploadInput.click() }),
          h("p", { class: "hint", text: "Or drag files onto the screen. They're saved in Downloads › Heartfulness Remote on your Mac." }),
        ),
        transfersList,
        h("h3", { text: "Download from your Mac" }),
        h("div", { class: "files-nav" }, upBtn, pathEl, refresh),
        browse,
      ],
    });
    renderFilesPanel = render;
    render();
    void go("");
  }

  // ---------------------------------------------------------- clipboard
  const clip = new ClipboardSync(
    prefs.clipboard,
    (text) => !!session?.sendControl({ t: "clip", text }),
    (msg) => toast(msg),
  );
  const onPaste = (e: ClipboardEvent) => {
    if (!session?.connected || document.querySelector("dialog[open]")) return;
    if (e.target instanceof HTMLInputElement || (e.target instanceof HTMLTextAreaElement && e.target !== kb)) return;
    if (clip.enabled) clip.onPaste(e);
    input?.releaseHold();
  };
  const onFocus = () => {
    if (session?.connected) void clip.onFocus();
  };
  window.addEventListener("paste", onPaste);
  window.addEventListener("focus", onFocus);
  offs.push(() => window.removeEventListener("paste", onPaste));
  offs.push(() => window.removeEventListener("focus", onFocus));

  // ---------------------------------------------------------- drag & drop
  let dragDepth = 0;
  const hasFiles = (e: DragEvent) => !!e.dataTransfer && [...e.dataTransfer.types].includes("Files");
  root.addEventListener("dragenter", (e) => {
    if (!hasFiles(e) || !session?.connected || !features.files) return;
    e.preventDefault();
    dragDepth++;
    dropzone.hidden = false;
  });
  root.addEventListener("dragover", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    if (e.dataTransfer) e.dataTransfer.dropEffect = session?.connected && features.files ? "copy" : "none";
  });
  root.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) dropzone.hidden = true;
  });
  root.addEventListener("drop", (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault();
    dragDepth = 0;
    dropzone.hidden = true;
    const list = e.dataTransfer?.files;
    if (list && list.length && files && features.files) {
      files.enqueue([...list]);
      toast(`Sending ${list.length} file${list.length === 1 ? "" : "s"} to your Mac…`);
    }
  });

  // ---------------------------------------------------------- overlay states
  function setStage(st: Stage | "ended"): void {
    root.dataset["stage"] = st;
  }

  function showConnecting(st: Stage): void {
    const text = stageText[st];
    setStage(st);
    overlay.hidden = false;
    replace(
      overlay,
      h(
        "div",
        { class: "overlay-card" },
        spinner(text),
        h("p", { class: "overlay-title", testid: "session-status", text, attrs: { "data-stage": st } }),
        h("p", { class: "overlay-text", testid: "session-mac-name", text: macName() }),
        button({ label: "Cancel", testid: "session-cancel", variant: "tinted", onClick: () => disconnect() }),
      ),
    );
  }

  function showEnded(kind: EndKind, reason: string, auto = false): void {
    live = false;
    setStage("ended");
    overlay.hidden = false;
    pill.hidden = true;
    toolbarWrap.classList.add("is-hidden");
    const title = kind === "security" ? "Connection stopped for your safety" : kind === "rejected" ? "Couldn't connect" : kind === "user" ? "Disconnected" : "Session ended";
    replace(
      overlay,
      h(
        "div",
        { class: `overlay-card ${kind === "security" ? "tone-danger" : ""}`.trim(), testid: "session-ended", attrs: { "data-kind": kind } },
        h("div", { class: "overlay-icon" }, icon(kind === "security" ? "shield" : kind === "user" ? "power" : "warning")),
        h("p", { class: "overlay-title", testid: "session-status", text: title, attrs: { "data-stage": "ended" } }),
        h("p", { class: "overlay-text overlay-mac", testid: "session-mac-name", text: macName() }),
        h("p", { class: "overlay-text", testid: "session-end-reason", text: reason }),
        auto ? h("p", { class: "overlay-text", testid: "session-auto-reconnect" }, spinner(""), " Reconnecting automatically…") : null,
        h(
          "div",
          { class: "row-center" },
          button({
            label: "Back to Home",
            testid: "session-home",
            variant: "tinted",
            onClick: () => {
              cancelAutoReconnect();
              app.goHome();
            },
          }),
          button({ label: "Reconnect", testid: "reconnect-button", variant: "primary", icon: "refresh", onClick: () => reconnect() }),
        ),
      ),
    );
  }

  // ---------------------------------------------------------- session lifecycle
  function onControl(m: Record<string, unknown>): void {
    if (files?.handleControl(m)) {
      updateToolbar();
      renderFilesPanel?.();
      return;
    }
    switch (m["t"]) {
      case "hello": {
        const ds = Array.isArray(m["displays"]) ? m["displays"] : [];
        displays = ds
          .filter((d): d is Record<string, unknown> => !!d && typeof d === "object")
          .map((d) => ({
            id: typeof d["id"] === "number" || typeof d["id"] === "string" ? d["id"] : 0,
            name: typeof d["name"] === "string" ? d["name"] : "",
            width: typeof d["width"] === "number" ? d["width"] : 0,
            height: typeof d["height"] === "number" ? d["height"] : 0,
            primary: d["primary"] === true,
          }));
        const ad = m["activeDisplay"];
        activeDisplay = typeof ad === "number" || typeof ad === "string" ? ad : (displays[0]?.id ?? null);
        const f = m["features"] && typeof m["features"] === "object" ? (m["features"] as Record<string, unknown>) : {};
        features = { audio: f["audio"] !== false, clipboard: f["clipboard"] !== false, files: f["files"] !== false };
        clip.enabled = prefs.clipboard && features.clipboard;
        updateToolbar();
        break;
      }
      case "ping":
        session?.sendControl({ t: "pong", id: m["id"], ts: m["ts"] });
        break;
      case "pong": {
        const sent = typeof m["id"] === "number" ? pings.get(m["id"]) : undefined;
        if (sent !== undefined) {
          pings.delete(m["id"] as number);
          pingRtt = performance.now() - sent;
          pingAt = performance.now();
        }
        break;
      }
      case "clip":
        if (features.clipboard) clip.onRemote(m["text"]);
        break;
      case "notice":
        if (typeof m["text"] === "string") toast(m["text"].slice(0, 300), m["level"] === "warn" ? "error" : "info");
        break;
      case "bye":
        session?.end("host", byeText(m["reason"]), false);
        break;
      default:
        break;
    }
  }

  async function updateStats(): Promise<void> {
    const s = session;
    if (!s || !s.connected) return;
    const rep = await s.getStats();
    if (!rep) return;
    const list: RawStat[] = [];
    rep.forEach((v: RawStat) => list.push(v));
    const snap = snapshot(list, performance.now());
    const r = rates(prevSnap, snap);
    prevSnap = snap;
    const rtt = pingRtt !== null && performance.now() - pingAt < 6000 ? pingRtt : snap.iceRttMs;
    pillRtt.textContent = rtt === null ? "– ms" : `${Math.round(rtt)} ms`;
    pillFps.textContent = r.fps === null ? "– fps" : `${Math.round(r.fps)} fps`;
    pillMbps.textContent = r.mbps === null ? "– Mbps" : `${r.mbps < 10 ? r.mbps.toFixed(1) : Math.round(r.mbps)} Mbps`;
    pillRoute.textContent = snap.relay === null ? "…" : snap.relay ? "Relay" : "Direct";
    pill.dataset["level"] = latencyLevel(rtt);
    pill.dataset["route"] = snap.relay ? "relay" : "direct";
    const parts = [
      `Round trip: ${rtt === null ? "unknown" : `${Math.round(rtt)} ms`}`,
      snap.iceRttMs !== null ? `network ${Math.round(snap.iceRttMs)} ms` : "",
      snap.codec ? `codec ${snap.codec}` : "",
      snap.width && snap.height ? `${snap.width}×${snap.height}` : "",
      snap.relay ? "via relay server (still end-to-end encrypted)" : "direct connection",
    ].filter(Boolean);
    pill.title = parts.join(" · ");
  }

  function sendPing(): void {
    if (!session?.connected) return;
    const id = ++pingId;
    pings.set(id, performance.now());
    if (pings.size > 10) {
      const oldest = pings.keys().next().value;
      if (oldest !== undefined) pings.delete(oldest);
    }
    session.sendControl({ t: "ping", id, ts: Date.now() });
  }

  async function playVideo(): Promise<void> {
    video.muted = prefs.muted;
    try {
      await video.play();
    } catch {
      // Autoplay with sound was blocked: play muted and offer an unmute button.
      video.muted = true;
      try {
        await video.play();
      } catch {
        /* will start on the next user gesture */
      }
      if (!prefs.muted && features.audio) unmute.hidden = false;
    }
    updateToolbar();
  }

  async function acquireWakeLock(): Promise<void> {
    try {
      const wl = (navigator as Navigator & { wakeLock?: { request(t: "screen"): Promise<{ release(): Promise<void> }> } }).wakeLock;
      // Skip quietly when the server's Permissions-Policy disallows it.
      const pp = (document as Document & { permissionsPolicy?: PolicyLike; featurePolicy?: PolicyLike }).permissionsPolicy ??
        (document as Document & { featurePolicy?: PolicyLike }).featurePolicy;
      if (pp && typeof pp.allowsFeature === "function" && !pp.allowsFeature("screen-wake-lock")) return;
      if (wl && document.visibilityState === "visible") wakeLock = await wl.request("screen");
    } catch {
      wakeLock = null;
    }
  }
  const onVisibility = () => {
    if (document.visibilityState === "visible" && session?.connected && !wakeLock) void acquireWakeLock();
  };
  document.addEventListener("visibilitychange", onVisibility);
  offs.push(() => document.removeEventListener("visibilitychange", onVisibility));

  function stopTimers(): void {
    if (statsTimer) clearInterval(statsTimer);
    if (pingTimer) clearInterval(pingTimer);
    if (tbTimer) clearTimeout(tbTimer);
    statsTimer = pingTimer = tbTimer = null;
  }

  function teardown(): void {
    stopTimers();
    input?.detach();
    input = null;
    files?.dispose();
    filesSheet?.close();
    filesSheet = null;
    closePopover();
    if (keyboardLocked) void lockKeyboard(false);
    void wakeLock?.release().catch(() => undefined);
    wakeLock = null;
    video.srcObject = null;
  }

  const stageText: Record<Stage, string> = {
    requesting: "Asking the Mac…",
    negotiating: "Securing the connection…",
    connecting: "Connecting…",
    connected: "",
  };

  function start(): void {
    const signal = app.signal;
    const signer = app.signer;
    // Always the PINNED key of the chosen Mac: the answer is verified with it.
    const pinned = app.pinBytes(hostPub);
    prevSnap = null;
    pingRtt = null;
    pings.clear();
    toolbarMac.textContent = macName();
    if (!signal || !signer || !pinned || !app.canUse(hostPub)) {
      showEnded("error", "This device isn't ready to connect to this Mac. Go back to Home and try again.");
      return;
    }
    live = false;
    showConnecting("requesting");
    const s = new RemoteSession(
      { signal, api: app.api, signer, pinnedHost: pinned },
      {
        stage: (st) => {
          if (s !== session) return;
          if (st === "connected") {
            if (live) return;
            live = true;
            autoTries = 0;
            setStage("connected");
            overlay.hidden = true;
            pill.hidden = false;
            showToolbar(3500);
            surface.focus({ preventScroll: true });
            statsTimer = setInterval(() => void updateStats(), 1000);
            pingTimer = setInterval(sendPing, 2000);
            void acquireWakeLock();
          } else if (!live) {
            // Never cover a live session with a stale "Connecting…" card.
            showConnecting(st);
          }
        },
        track: (stream) => {
          if (s !== session) return;
          if (video.srcObject !== stream) video.srcObject = stream;
          void playVideo();
        },
        channelsOpen: () => {
          s.sendControl({ t: "quality", mode: prefs.quality });
          sendPing();
        },
        control: (m) => {
          if (s === session) onControl(m);
        },
        fileData: (d) => {
          if (s === session) files?.handleData(d);
        },
        end: (kind, reason) => {
          if (s !== session) return;
          const wasLive = live;
          teardown();
          if (destroyed) return;
          if (kind === "user") {
            app.goHome();
            return;
          }
          // A live session that dropped (Wi-Fi blip, sleep, network change):
          // try again on our own a few times before asking the owner.
          if (kind === "network" && (wasLive || autoTries > 0) && autoTries < AUTO_RECONNECT_MAX) {
            scheduleAutoReconnect(reason);
            return;
          }
          showEnded(kind, reason);
        },
      },
    );
    session = s;
    files = new FilesController(
      s,
      () => {
        updateToolbar();
        renderFilesPanel?.();
      },
      (msg, level) => toast(msg, level),
    );
    input = new InputController(
      surface,
      video,
      kb,
      {
        pointer: (m) => void s.sendPointer(m),
        input: (m) => void s.sendInput(m),
      },
      {
        ctrlAsCmd: () => prefs.ctrlAsCmd,
        clipboardSync: () => clip.enabled,
        onShortcut: (a) => onShortcut(a),
        onGesture: () => void clip.flushPending(),
        onPasteKey: () => undefined,
        onTopEdge: () => showToolbar(),
      },
    );
    input.attach();
    updateToolbar();
    void s.start();
  }

  function onShortcut(a: ShortcutAction): void {
    switch (a) {
      case "fullscreen":
        void toggleFullscreen();
        break;
      case "disconnect":
        disconnect();
        break;
      case "keyboard-lock":
        void toggleKeyboardLock();
        break;
      case "upload":
        if (features.files) uploadInput.click();
        break;
      case "send-clipboard":
        void clip.sendNow();
        break;
      case "quality": {
        const order: Quality[] = ["auto", "sharp", "smooth"];
        const next = order[(order.indexOf(prefs.quality) + 1) % order.length]!;
        setQuality(next);
        toast(`Quality: ${QUALITY_LABEL[next]}`);
        break;
      }
      case "help":
        openHelp();
        break;
    }
  }

  function cancelAutoReconnect(): void {
    if (autoTimer) clearTimeout(autoTimer);
    autoTimer = null;
  }

  function scheduleAutoReconnect(reason: string): void {
    autoTries++;
    showEnded("network", reason, true);
    const attempt = () => {
      autoTimer = null;
      if (destroyed || root.dataset["stage"] !== "ended") return;
      if (app.signalState === "ready") {
        start();
        return;
      }
      // Wait (bounded) for the server connection to come back first.
      const off = app.on("signal", () => {
        if (app.signalState !== "ready") return;
        off();
        if (autoTimer) clearTimeout(autoTimer);
        autoTimer = null;
        if (!destroyed && root.dataset["stage"] === "ended") start();
      });
      offs.push(off);
      autoTimer = setTimeout(() => {
        off();
        autoTimer = null;
        if (!destroyed && root.dataset["stage"] === "ended") showEnded("network", reason);
      }, 30_000);
    };
    autoTimer = setTimeout(attempt, 1500 * 2 ** (autoTries - 1));
  }

  function disconnect(): void {
    cancelAutoReconnect();
    if (session && !session.ended) session.end("user", "You disconnected.");
    else app.goHome();
  }

  function reconnect(): void {
    cancelAutoReconnect();
    autoTries = 0;
    if (session && !session.ended) session.end("user", "Reconnecting.", true);
    start();
  }

  append(root, stage, toolbarWrap, pill, unmute, overlay, dropzone, kb, uploadInput);

  start();

  return {
    name: "session",
    el: root,
    destroy() {
      destroyed = true;
      cancelAutoReconnect();
      if (session && !session.ended) session.end("user", "Left the session.");
      teardown();
      if (document.fullscreenElement) void document.exitFullscreen().catch(() => undefined);
      for (const o of offs.splice(0)) o();
    },
  };
}

