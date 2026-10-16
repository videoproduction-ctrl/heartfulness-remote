// Captures mouse, wheel, keyboard and touch input on the session surface and
// turns it into §8.2 messages. Pointer moves are coalesced to one message per
// animation frame on the unreliable `pointer` channel; everything else goes on
// the reliable `input` channel.

import { mapPoint, wheelPixels } from "./coords";
import { isForwardableCode, matchShortcut, remapCode, type ShortcutAction } from "./keymap";
import { type GestureAction, TouchGestures } from "./touch";

export interface InputSink {
  pointer(m: Record<string, unknown>): void;
  input(m: Record<string, unknown>): void;
}

export interface InputOptions {
  ctrlAsCmd(): boolean;
  clipboardSync(): boolean;
  onShortcut(a: ShortcutAction): void;
  /** Called on every user gesture (lets the clipboard writer run inside a gesture). */
  onGesture(): void;
  onPasteKey(): void;
  onTopEdge(): void;
}

const MAX_TXT = 4096;

function isEditable(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  if (t.dataset["kbCapture"] === "1") return false;
  return t.isContentEditable || t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement;
}

/** Splits text into ≤ MAX_TXT code-point chunks. */
export function splitText(s: string, max = MAX_TXT): string[] {
  const cps = [...s];
  const out: string[] = [];
  for (let i = 0; i < cps.length; i += max) out.push(cps.slice(i, i + max).join(""));
  return out;
}

export class InputController {
  private pendingMove: { x: number; y: number } | null = null;
  private lastSent: { x: number; y: number } | null = null;
  private wheel = { dx: 0, dy: 0, x: 0, y: 0, any: false };
  private raf = 0;
  private buttons = new Set<number>();
  private keys = new Map<string, string>(); // physical code → code sent
  private consumed = new Set<string>();
  private hold: Array<Record<string, unknown>> | null = null;
  private holdTimer: ReturnType<typeof setTimeout> | null = null;
  private readonly gestures: TouchGestures;
  private readonly cleanup: Array<() => void> = [];
  private composing = false;
  enabled = true;

  constructor(
    private readonly surface: HTMLElement,
    private readonly video: HTMLVideoElement,
    private readonly kbInput: HTMLTextAreaElement,
    private readonly sink: InputSink,
    private readonly opts: InputOptions,
  ) {
    this.gestures = new TouchGestures((a) => this.onGesture(a));
  }

  private map(clientX: number, clientY: number) {
    return mapPoint(clientX, clientY, this.video.getBoundingClientRect(), this.video.videoWidth, this.video.videoHeight);
  }

  private listen<K extends keyof HTMLElementEventMap>(el: HTMLElement, type: K, fn: (e: HTMLElementEventMap[K]) => void, opts?: AddEventListenerOptions): void;
  private listen<K extends keyof WindowEventMap>(el: Window, type: K, fn: (e: WindowEventMap[K]) => void, opts?: AddEventListenerOptions): void;
  private listen<K extends keyof DocumentEventMap>(el: Document, type: K, fn: (e: DocumentEventMap[K]) => void, opts?: AddEventListenerOptions): void;
  private listen(el: EventTarget, type: string, fn: (e: Event) => void, opts?: AddEventListenerOptions): void {
    el.addEventListener(type, fn, opts);
    this.cleanup.push(() => el.removeEventListener(type, fn, opts));
  }

  attach(): void {
    const s = this.surface;
    this.listen(s, "pointerdown", (e) => this.onPointerDown(e));
    this.listen(s, "pointermove", (e) => this.onPointerMove(e));
    this.listen(s, "pointerup", (e) => this.onPointerUp(e));
    this.listen(s, "pointercancel", (e) => this.onPointerCancel(e));
    this.listen(s, "wheel", (e) => this.onWheel(e), { passive: false });
    this.listen(s, "contextmenu", (e) => e.preventDefault());
    this.listen(s, "auxclick", (e) => e.preventDefault());
    this.listen(s, "mouseup", (e) => {
      if (e.button === 3 || e.button === 4) e.preventDefault(); // no browser back/forward
    });
    this.listen(s, "dragstart", (e) => e.preventDefault());
    this.listen(window, "keydown", (e) => this.onKey(e, true), { capture: true });
    this.listen(window, "keyup", (e) => this.onKey(e, false), { capture: true });
    this.listen(window, "blur", () => this.reset());
    this.listen(document, "visibilitychange", () => {
      if (document.visibilityState !== "visible") this.reset();
    });
    this.listen(this.kbInput, "beforeinput", (e) => this.onBeforeInput(e));
    this.listen(this.kbInput, "compositionstart", () => {
      this.composing = true;
    });
    this.listen(this.kbInput, "compositionend", (e) => {
      this.composing = false;
      if (e.data) this.typeText(e.data);
      this.kbInput.value = "";
    });
    this.listen(this.kbInput, "input", () => {
      // Fallback for input types that beforeinput didn't handle.
      const v = this.kbInput.value;
      if (v && !this.composing) {
        this.typeText(v);
        this.kbInput.value = "";
      }
    });
  }

  detach(): void {
    this.reset();
    for (const c of this.cleanup.splice(0)) c();
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
  }

  // ------------------------------------------------------------ sending

  private send(m: Record<string, unknown>): void {
    if (!this.enabled) return;
    if (this.hold) this.hold.push(m);
    else this.sink.input(m);
  }

  /** Holds input messages (in order) until releaseHold() or the timeout. Used for paste. */
  beginHold(ms: number): void {
    if (this.hold) return;
    this.hold = [];
    this.holdTimer = setTimeout(() => this.releaseHold(), ms);
  }

  releaseHold(): void {
    if (this.holdTimer) clearTimeout(this.holdTimer);
    this.holdTimer = null;
    const q = this.hold;
    this.hold = null;
    if (q) for (const m of q) this.sink.input(m);
  }

  private schedule(): void {
    if (!this.raf) this.raf = requestAnimationFrame(() => this.flush());
  }

  private flush(): void {
    this.raf = 0;
    const m = this.pendingMove;
    if (m) {
      this.pendingMove = null;
      if (!this.lastSent || this.lastSent.x !== m.x || this.lastSent.y !== m.y) {
        this.lastSent = m;
        if (this.enabled) this.sink.pointer({ t: "m", x: m.x, y: m.y });
      }
    }
    if (this.wheel.any) {
      const w = this.wheel;
      this.send({ t: "w", dx: Math.round(w.dx * 100) / 100, dy: Math.round(w.dy * 100) / 100, x: w.x, y: w.y });
      this.wheel = { dx: 0, dy: 0, x: 0, y: 0, any: false };
    }
  }

  /** Sends any coalesced move immediately (before a click, so the Mac clicks in the right place). */
  private flushMoveNow(x: number, y: number): void {
    this.pendingMove = null;
    if (!this.lastSent || this.lastSent.x !== x || this.lastSent.y !== y) {
      this.lastSent = { x, y };
      if (this.enabled) this.sink.pointer({ t: "m", x, y });
    }
  }

  // ------------------------------------------------------------ mouse & pen

  private onPointerDown(e: PointerEvent): void {
    this.opts.onGesture();
    if (e.pointerType === "touch") {
      e.preventDefault();
      this.gestures.down(e.pointerId, e.clientX, e.clientY, e.timeStamp);
      return;
    }
    this.surface.focus({ preventScroll: true });
    const p = this.map(e.clientX, e.clientY);
    if (!p.inside) return;
    e.preventDefault();
    try {
      this.surface.setPointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
    this.flushMoveNow(p.x, p.y);
    if (e.button >= 0 && e.button <= 4) {
      this.buttons.add(e.button);
      this.send({ t: "b", b: e.button, d: true, x: p.x, y: p.y });
    }
  }

  private onPointerUp(e: PointerEvent): void {
    if (e.pointerType === "touch") {
      e.preventDefault();
      this.gestures.up(e.pointerId, e.timeStamp);
      return;
    }
    const p = this.map(e.clientX, e.clientY);
    if (this.buttons.delete(e.button)) {
      e.preventDefault();
      this.flushMoveNow(p.x, p.y);
      this.send({ t: "b", b: e.button, d: false, x: p.x, y: p.y });
    }
    try {
      this.surface.releasePointerCapture(e.pointerId);
    } catch {
      /* ignore */
    }
  }

  private onPointerMove(e: PointerEvent): void {
    if (e.pointerType === "touch") {
      e.preventDefault();
      this.gestures.move(e.pointerId, e.clientX, e.clientY);
      return;
    }
    if (e.clientY < 64) this.opts.onTopEdge();
    const p = this.map(e.clientX, e.clientY);
    if (!p.inside && this.buttons.size === 0 && !this.lastSent) return;
    this.pendingMove = { x: p.x, y: p.y };
    this.schedule();
  }

  private onPointerCancel(e: PointerEvent): void {
    if (e.pointerType === "touch") {
      this.gestures.reset();
      return;
    }
    this.releaseButtons();
  }

  private onWheel(e: WheelEvent): void {
    e.preventDefault();
    const p = this.map(e.clientX, e.clientY);
    const d = wheelPixels(e.deltaX, e.deltaY, e.deltaMode, this.surface.clientHeight);
    this.wheel.dx += d.dx;
    this.wheel.dy += d.dy;
    this.wheel.x = p.x;
    this.wheel.y = p.y;
    this.wheel.any = true;
    this.schedule();
  }

  // ------------------------------------------------------------ touch

  private onGesture(a: GestureAction): void {
    if (a.kind === "longpress") {
      try {
        navigator.vibrate?.(15);
      } catch {
        /* ignore */
      }
      return;
    }
    const p = this.map(a.x, a.y);
    if (a.kind === "move") {
      this.pendingMove = { x: p.x, y: p.y };
      this.schedule();
    } else if (a.kind === "button") {
      this.flushMoveNow(p.x, p.y);
      if (a.d) this.buttons.add(a.b);
      else this.buttons.delete(a.b);
      this.send({ t: "b", b: a.b, d: a.d, x: p.x, y: p.y });
    } else if (a.kind === "wheel") {
      this.wheel.dx += a.dx;
      this.wheel.dy += a.dy;
      this.wheel.x = p.x;
      this.wheel.y = p.y;
      this.wheel.any = true;
      this.schedule();
    }
  }

  // ------------------------------------------------------------ keyboard

  private onKey(e: KeyboardEvent, down: boolean): void {
    if (!this.enabled) return;
    if (isEditable(e.target)) return; // typing into our own UI (dialogs, file panel)
    if (document.querySelector("dialog[open]")) return;
    if (down) this.opts.onGesture();
    if (down) {
      const sc = matchShortcut(e);
      if (sc) {
        e.preventDefault();
        e.stopPropagation();
        this.consumed.add(e.code);
        this.opts.onShortcut(sc);
        return;
      }
    } else if (this.consumed.delete(e.code)) {
      e.preventDefault();
      return;
    }
    if (e.isComposing || !isForwardableCode(e.code)) return; // soft keyboards: handled by beforeinput
    const isPaste = down && e.code === "KeyV" && (e.ctrlKey || e.metaKey) && !e.altKey && this.opts.clipboardSync();
    if (isPaste) {
      // Let the browser fire a `paste` event first so the clipboard reaches the
      // Mac before ⌘V does; input is held in order until then (max 250 ms).
      this.beginHold(250);
      this.opts.onPasteKey();
    } else {
      e.preventDefault();
    }
    e.stopPropagation();
    if (down) {
      const sent = this.keys.get(e.code) ?? remapCode(e.code, this.opts.ctrlAsCmd());
      this.keys.set(e.code, sent);
      this.send({ t: "k", c: sent, d: true });
    } else {
      const sent = this.keys.get(e.code) ?? remapCode(e.code, this.opts.ctrlAsCmd());
      this.keys.delete(e.code);
      this.send({ t: "k", c: sent, d: false });
    }
  }

  private onBeforeInput(e: InputEvent): void {
    if (!this.enabled) return;
    switch (e.inputType) {
      case "insertText":
      case "insertReplacementText":
        if (e.data) this.typeText(e.data);
        e.preventDefault();
        break;
      case "insertLineBreak":
      case "insertParagraph":
        this.tapKey("Enter");
        e.preventDefault();
        break;
      case "deleteContentBackward":
      case "deleteWordBackward":
        this.tapKey("Backspace");
        e.preventDefault();
        break;
      case "deleteContentForward":
        this.tapKey("Delete");
        e.preventDefault();
        break;
      default:
        break; // composition etc.: handled on compositionend
    }
  }

  typeText(s: string): void {
    for (const part of splitText(s)) this.send({ t: "txt", s: part });
  }

  tapKey(code: string): void {
    this.send({ t: "k", c: code, d: true });
    this.send({ t: "k", c: code, d: false });
  }

  private releaseButtons(): void {
    const last = this.lastSent ?? { x: 0, y: 0 };
    for (const b of this.buttons) this.send({ t: "b", b, d: false, x: last.x, y: last.y });
    this.buttons.clear();
  }

  /** Releases everything on the Mac side (window blur, tab hidden, session end). */
  reset(): void {
    this.releaseHold();
    this.gestures.reset();
    this.buttons.clear();
    this.keys.clear();
    this.consumed.clear();
    this.wheel = { dx: 0, dy: 0, x: 0, y: 0, any: false };
    this.pendingMove = null;
    if (this.enabled) this.sink.input({ t: "reset" });
  }
}
