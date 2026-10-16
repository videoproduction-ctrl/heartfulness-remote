// Touch gesture recognizer for phones and tablets.
//   one-finger tap        → left click
//   one-finger drag       → move the pointer
//   long-press then drag  → drag (left button held)
//   two-finger tap        → right click
//   two-finger pan        → scroll
// Pure logic with injectable timers so it can be unit-tested.

export type GestureAction =
  | { kind: "move"; x: number; y: number }
  | { kind: "button"; b: number; d: boolean; x: number; y: number }
  | { kind: "wheel"; dx: number; dy: number; x: number; y: number }
  | { kind: "longpress" };

export interface GestureOptions {
  tapMaxMs: number;
  moveTolerance: number;
  longPressMs: number;
  setTimer: (fn: () => void, ms: number) => unknown;
  clearTimer: (t: unknown) => void;
}

interface Pt {
  x0: number;
  y0: number;
  x: number;
  y: number;
}

type Mode = "idle" | "one" | "hover" | "drag" | "two" | "scroll" | "done";

export class TouchGestures {
  private pts = new Map<number, Pt>();
  private mode: Mode = "idle";
  private t0 = 0;
  private timer: unknown = null;
  private lastCx = 0;
  private lastCy = 0;
  private readonly o: GestureOptions;

  constructor(
    private readonly emit: (a: GestureAction) => void,
    opts: Partial<GestureOptions> = {},
  ) {
    this.o = {
      tapMaxMs: 350,
      moveTolerance: 10,
      longPressMs: 500,
      setTimer: (fn, ms) => setTimeout(fn, ms),
      clearTimer: (t) => clearTimeout(t as ReturnType<typeof setTimeout>),
      ...opts,
    };
  }

  get state(): string {
    return this.mode;
  }

  private centroid(): { x: number; y: number } {
    let x = 0;
    let y = 0;
    for (const p of this.pts.values()) {
      x += p.x;
      y += p.y;
    }
    const n = Math.max(this.pts.size, 1);
    return { x: x / n, y: y / n };
  }

  private stopTimer(): void {
    if (this.timer !== null) {
      this.o.clearTimer(this.timer);
      this.timer = null;
    }
  }

  private moved(p: Pt): boolean {
    return Math.hypot(p.x - p.x0, p.y - p.y0) > this.o.moveTolerance;
  }

  down(id: number, x: number, y: number, t: number): void {
    this.pts.set(id, { x0: x, y0: y, x, y });
    if (this.mode === "idle") {
      this.mode = "one";
      this.t0 = t;
      this.emit({ kind: "move", x, y });
      this.timer = this.o.setTimer(() => {
        this.timer = null;
        if (this.mode === "one") {
          this.mode = "drag";
          const p = [...this.pts.values()][0];
          if (p) {
            this.emit({ kind: "longpress" });
            this.emit({ kind: "button", b: 0, d: true, x: p.x, y: p.y });
          }
        }
      }, this.o.longPressMs);
      return;
    }
    if (this.mode === "one" && this.pts.size === 2) {
      this.stopTimer();
      this.mode = "two";
      this.t0 = t;
      for (const p of this.pts.values()) {
        p.x0 = p.x;
        p.y0 = p.y;
      }
      const c = this.centroid();
      this.lastCx = c.x;
      this.lastCy = c.y;
      return;
    }
    // A third finger (or a finger added mid-gesture) ends gesture recognition.
    if (this.mode === "drag") this.releaseDrag();
    this.stopTimer();
    this.mode = "done";
  }

  move(id: number, x: number, y: number): void {
    const p = this.pts.get(id);
    if (!p) return;
    p.x = x;
    p.y = y;
    switch (this.mode) {
      case "one":
        if (this.moved(p)) {
          this.stopTimer();
          this.mode = "hover";
          this.emit({ kind: "move", x, y });
        }
        break;
      case "hover":
      case "drag":
        this.emit({ kind: "move", x, y });
        break;
      case "two": {
        let any = false;
        for (const q of this.pts.values()) if (this.moved(q)) any = true;
        if (any) {
          this.mode = "scroll";
          this.scroll();
        }
        break;
      }
      case "scroll":
        this.scroll();
        break;
      default:
        break;
    }
  }

  private scroll(): void {
    const c = this.centroid();
    const dx = c.x - this.lastCx;
    const dy = c.y - this.lastCy;
    this.lastCx = c.x;
    this.lastCy = c.y;
    // Content follows the fingers (natural scrolling): fingers up → scroll down.
    if (dx !== 0 || dy !== 0) this.emit({ kind: "wheel", dx: -dx, dy: -dy, x: c.x, y: c.y });
  }

  private releaseDrag(): void {
    const p = [...this.pts.values()][0];
    this.emit({ kind: "button", b: 0, d: false, x: p?.x ?? 0, y: p?.y ?? 0 });
  }

  up(id: number, t: number): void {
    const p = this.pts.get(id);
    if (!p) return;
    switch (this.mode) {
      case "one":
        this.stopTimer();
        this.emit({ kind: "button", b: 0, d: true, x: p.x, y: p.y });
        this.emit({ kind: "button", b: 0, d: false, x: p.x, y: p.y });
        this.mode = "done";
        break;
      case "drag":
        this.emit({ kind: "button", b: 0, d: false, x: p.x, y: p.y });
        this.mode = "done";
        break;
      case "two": {
        const c = this.centroid();
        if (t - this.t0 <= this.o.tapMaxMs) {
          this.emit({ kind: "move", x: c.x, y: c.y });
          this.emit({ kind: "button", b: 2, d: true, x: c.x, y: c.y });
          this.emit({ kind: "button", b: 2, d: false, x: c.x, y: c.y });
        }
        this.mode = "done";
        break;
      }
      case "hover":
      case "scroll":
        this.mode = "done";
        break;
      default:
        break;
    }
    this.pts.delete(id);
    if (this.pts.size === 0) {
      this.stopTimer();
      this.mode = "idle";
    }
  }

  /** Cancels everything (pointercancel, blur); releases a held drag button. */
  reset(): void {
    if (this.mode === "drag") this.releaseDrag();
    this.stopTimer();
    this.pts.clear();
    this.mode = "idle";
  }
}
