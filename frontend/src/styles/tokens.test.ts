// Re-checks the Signal palette's contrast roles (docs/design/DESIGN_SYSTEM.md §2) straight from
// tokens.css, so a token edit that breaks a role fails CI.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const css = readFileSync(join(import.meta.dirname, "tokens.css"), "utf8");
const root = css.slice(css.indexOf(":root {"), css.indexOf("}", css.indexOf(":root {")));
const tokens = Object.fromEntries(
  [...root.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/gi)].map((match) => [match[1]!, match[2]!.toLowerCase()]),
);

function luminance(hex: string): number {
  const [r, g, b] = [1, 3, 5].map((i) => {
    const c = Number.parseInt(hex.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi! + 0.05) / (lo! + 0.05);
}

const t = (name: string) => {
  const value = tokens[name] ?? (name.startsWith("#") ? name : undefined);
  if (!value) throw new Error(`missing token --${name}`);
  return value;
};

// [role, foreground, backgrounds it may sit on, minimum ratio]
const ROLES: Array<[string, string, string[], number]> = [
  ["body text", "text", ["void", "bg", "surface", "raised", "plum-900", "plum-800", "warn-bg", "danger-bg"], 4.5],
  ["secondary text", "text-muted", ["void", "bg", "surface", "raised", "plum-900", "plum-800"], 4.5],
  ["primary button label", "#ffffff", ["signal-500", "signal-500h", "signal-600"], 4.5],
  ["primary button boundary", "signal-500", ["bg", "surface", "raised"], 3],
  ["links and purple text", "signal-300", ["void", "bg", "surface", "raised", "plum-900", "plum-800"], 4.5],
  ["focus ring", "signal-300", ["void", "bg", "surface", "raised", "plum-800"], 3],
  ["text on plum", "signal-200", ["plum-900", "plum-800"], 4.5],
  ["selected edge and active bar", "signal-400", ["bg", "surface", "raised", "plum-900"], 3],
  ["magenta marker", "magenta-400", ["surface", "raised", "magenta-900"], 3],
  ["control boundary", "control", ["bg", "surface", "raised"], 3],
  ["status ok", "ok", ["ok-bg"], 4.5],
  ["status warn", "warn", ["warn-bg"], 4.5],
  ["status danger", "danger", ["danger-bg"], 4.5],
  ["status info", "info", ["info-bg"], 4.5],
];

describe("Signal palette contrast", () => {
  for (const [role, fg, backgrounds, minimum] of ROLES) {
    it(`${role} reaches ${minimum}:1 on every surface it may sit on`, () => {
      for (const bg of backgrounds) {
        expect(contrast(t(fg), t(bg)), `${fg} on ${bg}`).toBeGreaterThanOrEqual(minimum);
      }
    });
  }

  it("keeps the decoration-only grey below text contrast, so it is never used for text", () => {
    expect(contrast(t("text-faint"), t("bg"))).toBeLessThan(4.5);
  });
});
