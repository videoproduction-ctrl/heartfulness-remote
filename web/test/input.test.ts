// Key remapping, shortcuts, letterbox coordinate mapping, wheel units and touch gestures.
import { test } from "node:test";
import assert from "node:assert/strict";
import { contentRect, mapPoint, wheelPixels } from "../src/coords";
import { isForwardableCode, matchShortcut, remapCode, SHORTCUTS } from "../src/keymap";
import { splitText } from "../src/input";
import { type GestureAction, TouchGestures } from "../src/touch";

test("Ctrl ⇄ ⌘ remapping", () => {
  assert.equal(remapCode("ControlLeft", true), "MetaLeft");
  assert.equal(remapCode("ControlRight", true), "MetaRight");
  assert.equal(remapCode("MetaLeft", true), "ControlLeft");
  assert.equal(remapCode("MetaRight", true), "ControlRight");
  for (const c of ["KeyC", "ShiftLeft", "AltLeft", "Enter", "F5"]) assert.equal(remapCode(c, true), c);
  for (const c of ["ControlLeft", "ControlRight", "MetaLeft", "KeyV"]) assert.equal(remapCode(c, false), c);
});

test("client shortcuts are Ctrl+Alt+Shift+key only", () => {
  const ev = (code: string, mods: Partial<{ ctrlKey: boolean; altKey: boolean; shiftKey: boolean; metaKey: boolean }>) => ({
    code,
    ctrlKey: false,
    altKey: false,
    shiftKey: false,
    metaKey: false,
    ...mods,
  });
  const all = { ctrlKey: true, altKey: true, shiftKey: true };
  assert.equal(matchShortcut(ev("KeyF", all)), "fullscreen");
  assert.equal(matchShortcut(ev("KeyQ", all)), "disconnect");
  assert.equal(matchShortcut(ev("KeyK", all)), "keyboard-lock");
  assert.equal(matchShortcut(ev("KeyU", all)), "upload");
  assert.equal(matchShortcut(ev("KeyV", all)), "send-clipboard");
  assert.equal(matchShortcut(ev("KeyS", all)), "quality");
  assert.equal(matchShortcut(ev("KeyH", all)), "help");
  assert.equal(matchShortcut(ev("KeyF", { ctrlKey: true, altKey: true })), null);
  assert.equal(matchShortcut(ev("KeyF", { ...all, metaKey: true })), null);
  assert.equal(matchShortcut(ev("KeyZ", all)), null);
  assert.equal(matchShortcut(ev("KeyV", { ctrlKey: true })), null);
  assert.equal(new Set(SHORTCUTS.map((s) => s.code)).size, SHORTCUTS.length);
  assert.equal(isForwardableCode("KeyA"), true);
  assert.equal(isForwardableCode("NumpadEnter"), true);
  assert.equal(isForwardableCode(""), false);
  assert.equal(isForwardableCode("Unidentified"), false);
});

test("letterboxed video content rect", () => {
  // 16:9 video in a 4:3 box → bars top and bottom.
  const r = contentRect({ left: 0, top: 0, width: 800, height: 600 }, 1920, 1080);
  assert.equal(r.width, 800);
  assert.equal(r.height, 450);
  assert.equal(r.left, 0);
  assert.equal(r.top, 75);
  // 4:3 video in a wide box → bars left and right, with an offset box.
  const p = contentRect({ left: 10, top: 20, width: 1600, height: 900 }, 1024, 768);
  assert.equal(p.height, 900);
  assert.equal(p.width, 1200);
  assert.equal(p.left, 210);
  assert.equal(p.top, 20);
  // Unknown video size: the whole box.
  assert.deepEqual(contentRect({ left: 1, top: 2, width: 3, height: 4 }, 0, 0), { left: 1, top: 2, width: 3, height: 4 });
});

test("pointer coordinates map to 0..1 within the picture", () => {
  const box = { left: 0, top: 0, width: 800, height: 600 };
  assert.deepEqual(mapPoint(400, 300, box, 1920, 1080), { x: 0.5, y: 0.5, inside: true });
  assert.deepEqual(mapPoint(0, 75, box, 1920, 1080), { x: 0, y: 0, inside: true });
  assert.deepEqual(mapPoint(800, 525, box, 1920, 1080), { x: 1, y: 1, inside: true });
  // On the black bar above the picture → clamped and flagged.
  assert.deepEqual(mapPoint(200, 10, box, 1920, 1080), { x: 0.25, y: 0, inside: false });
  assert.deepEqual(mapPoint(-50, 700, box, 1920, 1080), { x: 0, y: 1, inside: false });
  // Side bars.
  const wide = { left: 0, top: 0, width: 1600, height: 900 };
  assert.equal(mapPoint(100, 450, wide, 1024, 768).inside, false);
  const m = mapPoint(200 + 600, 450, wide, 1024, 768);
  assert.equal(m.x, 0.5);
  assert.equal(m.y, 0.5);
  // Precision is bounded (small JSON).
  const q = mapPoint(123.456789, 77.777, box, 1920, 1080);
  assert.ok(String(q.x).length <= 7);
});

test("wheel deltas are converted to CSS pixels", () => {
  assert.deepEqual(wheelPixels(0, 100, 0, 800), { dx: 0, dy: 100 });
  assert.deepEqual(wheelPixels(1, -3, 1, 800), { dx: 16, dy: -48 });
  assert.deepEqual(wheelPixels(0, 1, 2, 800), { dx: 0, dy: 800 });
});

test("text is split into ≤ 4096-character messages without breaking characters", () => {
  assert.deepEqual(splitText("abc"), ["abc"]);
  const long = "😀".repeat(5000);
  const parts = splitText(long);
  assert.equal(parts.length, 2);
  assert.equal([...parts[0]!].length, 4096);
  assert.equal(parts.join(""), long);
});

function gestures() {
  const out: GestureAction[] = [];
  let pending: (() => void) | null = null;
  const g = new TouchGestures((a) => out.push(a), {
    setTimer: (fn) => {
      pending = fn;
      return 1;
    },
    clearTimer: () => {
      pending = null;
    },
  });
  return { g, out, fire: () => pending?.() };
}

test("touch: tap = left click", () => {
  const { g, out } = gestures();
  g.down(1, 100, 100, 0);
  g.up(1, 120);
  assert.deepEqual(out, [
    { kind: "move", x: 100, y: 100 },
    { kind: "button", b: 0, d: true, x: 100, y: 100 },
    { kind: "button", b: 0, d: false, x: 100, y: 100 },
  ]);
  assert.equal(g.state, "idle");
});

test("touch: one-finger drag moves the pointer without clicking", () => {
  const { g, out } = gestures();
  g.down(1, 100, 100, 0);
  g.move(1, 105, 100); // within tolerance
  g.move(1, 150, 120);
  g.move(1, 160, 130);
  g.up(1, 400);
  assert.ok(out.every((a) => a.kind === "move"));
  assert.deepEqual(out.at(-1), { kind: "move", x: 160, y: 130 });
});

test("touch: long-press then drag = drag with the left button held", () => {
  const { g, out, fire } = gestures();
  g.down(1, 50, 50, 0);
  fire(); // long-press timer
  g.move(1, 80, 90);
  g.up(1, 900);
  assert.deepEqual(out, [
    { kind: "move", x: 50, y: 50 },
    { kind: "longpress" },
    { kind: "button", b: 0, d: true, x: 50, y: 50 },
    { kind: "move", x: 80, y: 90 },
    { kind: "button", b: 0, d: false, x: 80, y: 90 },
  ]);
});

test("touch: two-finger tap = right click at the centroid", () => {
  const { g, out } = gestures();
  g.down(1, 100, 100, 0);
  g.down(2, 200, 100, 30);
  g.up(1, 150);
  g.up(2, 160);
  assert.deepEqual(out.slice(1), [
    { kind: "move", x: 150, y: 100 },
    { kind: "button", b: 2, d: true, x: 150, y: 100 },
    { kind: "button", b: 2, d: false, x: 150, y: 100 },
  ]);
  assert.equal(g.state, "idle");
});

test("touch: two-finger pan = scroll (content follows the fingers)", () => {
  const { g, out } = gestures();
  g.down(1, 100, 300, 0);
  g.down(2, 200, 300, 10);
  g.move(1, 100, 250); // centroid moves up 25 (beyond tolerance for finger 1)
  g.move(2, 200, 250); // centroid moves up another 25
  g.up(1, 600);
  g.up(2, 610);
  const wheels = out.filter((a) => a.kind === "wheel");
  assert.equal(wheels.length, 2);
  const total = wheels.reduce((s, w) => s + (w.kind === "wheel" ? w.dy : 0), 0);
  assert.equal(total, 50); // fingers up → positive dy → scroll down (DOM convention)
  assert.ok(!out.some((a) => a.kind === "button"));
});

test("touch: three fingers cancel the gesture", () => {
  const { g, out } = gestures();
  g.down(1, 0, 0, 0);
  g.down(2, 10, 0, 5);
  g.down(3, 20, 0, 10);
  g.up(1, 50);
  g.up(2, 60);
  g.up(3, 70);
  assert.ok(!out.some((a) => a.kind === "button"));
});

test("touch: reset during a drag releases the button", () => {
  const { g, out, fire } = gestures();
  g.down(1, 10, 10, 0);
  fire();
  g.reset();
  assert.deepEqual(out.at(-1), { kind: "button", b: 0, d: false, x: 10, y: 10 });
});
