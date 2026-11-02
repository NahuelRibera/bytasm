// Atmospheric field of 0 and 1 glyphs drawn on a canvas (decoration only, aria-hidden).
// Deterministic: a seeded PRNG decides every glyph, so the same box always paints the same field.
// The field brightens around a light source (the moon) and dissolves toward the copy side, so it
// never sits under readable text and never resembles real evidence (no offsets, no hex).
import { useEffect, useRef } from "react";

export function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export interface FieldLight {
  /** Light centre as a fraction of the box. */
  x: number;
  y: number;
  /** Radius of the bright zone as a fraction of the box width. */
  radius: number;
}

export interface FieldOptions {
  seed?: number;
  light?: FieldLight;
  /** Fraction of the width (from the left) kept clear for copy. */
  clearLeft?: number;
  /** Fraction of the height (from the bottom) over which the field fades out. */
  fadeBottom?: number;
  density?: number;
}

export function paintBinaryField(canvas: HTMLCanvasElement, options: FieldOptions = {}) {
  const { seed = 0xb17a5, light = { x: 0.66, y: 0.28, radius: 0.22 }, clearLeft = 0.4, fadeBottom = 0.45, density = 0.62 } = options;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const width = canvas.clientWidth;
  const height = canvas.clientHeight;
  if (!width || !height) return;
  canvas.width = Math.round(width * ratio);
  canvas.height = Math.round(height * ratio);
  const context = canvas.getContext("2d");
  if (!context) return;
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  context.font = '500 8.5px "JetBrains Mono Variable", ui-monospace, monospace';
  context.textBaseline = "top";

  const random = mulberry32(seed);
  const cellX = 7;
  const cellY = 10;
  const lx = light.x * width;
  const ly = light.y * height;
  const lr = light.radius * width;
  for (let row = 0; row * cellY < height; row += 1) {
    // Rows drift in and out like a weak signal: some rows are almost empty.
    const rowSignal = 0.55 + 0.45 * Math.sin(row * 0.9 + random() * 0.6);
    for (let col = 0; col * cellX < width; col += 1) {
      const roll = random();
      const glyph = random() < 0.5 ? "0" : "1";
      const x = col * cellX;
      const y = row * cellY;
      const fx = x / width;
      const fy = y / height;
      const copy = Math.min(1, Math.max(0, (fx - clearLeft) / 0.18));
      const bottom = Math.min(1, Math.max(0, (1 - fy) / fadeBottom));
      const distance = Math.hypot(x - lx, (y - ly) * 1.25);
      const glow = Math.max(0, 1 - distance / (lr * 2.6));
      const presence = density * rowSignal * (0.35 + glow * 0.9);
      if (roll > presence) continue;
      const alpha = copy * bottom * (0.035 + glow * glow * 0.3);
      if (alpha < 0.012) continue;
      const lit = glow > 0.55 && random() < 0.35;
      context.fillStyle = lit ? `rgba(196, 150, 255, ${alpha * 1.25})` : `rgba(214, 206, 232, ${alpha})`;
      context.fillText(glyph, x, y);
    }
  }
}

/** A canvas that repaints its binary field whenever its box changes size. */
export function BinaryField({ className, ...options }: FieldOptions & { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const key = JSON.stringify(options);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const parsed = JSON.parse(key) as FieldOptions;
    let frame = 0;
    const paint = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => paintBinaryField(canvas, parsed));
    };
    paint();
    // Repaint once the mono face has loaded so glyph widths match the grid.
    void document.fonts?.ready.then(paint);
    if (typeof ResizeObserver === "undefined") return () => cancelAnimationFrame(frame);
    const observer = new ResizeObserver(paint);
    observer.observe(canvas);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [key]);
  return <canvas ref={ref} className={["binary-field", className].filter(Boolean).join(" ")} aria-hidden="true" />;
}
