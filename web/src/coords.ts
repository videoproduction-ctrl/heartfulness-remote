// Coordinate mapping for a <video> shown with `object-fit: contain`
// (letterboxed). Remote coordinates are 0..1 within the active display.

export interface Rect {
  left: number;
  top: number;
  width: number;
  height: number;
}

/** The rectangle actually covered by the picture inside the element box. */
export function contentRect(box: Rect, videoWidth: number, videoHeight: number): Rect {
  if (!(videoWidth > 0 && videoHeight > 0 && box.width > 0 && box.height > 0)) return { ...box };
  const scale = Math.min(box.width / videoWidth, box.height / videoHeight);
  const width = videoWidth * scale;
  const height = videoHeight * scale;
  return {
    left: box.left + (box.width - width) / 2,
    top: box.top + (box.height - height) / 2,
    width,
    height,
  };
}

export interface MappedPoint {
  x: number;
  y: number;
  /** False when the point lies on the letterbox bars (x/y are then clamped). */
  inside: boolean;
}

const clamp01 = (v: number) => (v < 0 ? 0 : v > 1 ? 1 : v);
const round5 = (v: number) => Math.round(v * 100000) / 100000;

export function mapPoint(clientX: number, clientY: number, box: Rect, videoWidth: number, videoHeight: number): MappedPoint {
  const r = contentRect(box, videoWidth, videoHeight);
  if (r.width <= 0 || r.height <= 0) return { x: 0, y: 0, inside: false };
  const fx = (clientX - r.left) / r.width;
  const fy = (clientY - r.top) / r.height;
  const inside = fx >= 0 && fx <= 1 && fy >= 0 && fy <= 1;
  return { x: round5(clamp01(fx)), y: round5(clamp01(fy)), inside };
}

/** Wheel deltas in CSS pixels (DOM sign convention), whatever the event's deltaMode. */
export function wheelPixels(deltaX: number, deltaY: number, deltaMode: number, pageHeight: number): { dx: number; dy: number } {
  const LINE = 16;
  const f = deltaMode === 1 ? LINE : deltaMode === 2 ? Math.max(pageHeight, 100) : 1;
  return { dx: deltaX * f, dy: deltaY * f };
}
