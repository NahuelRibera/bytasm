import { ESLint } from "eslint";
import { describe, expect, it } from "vitest";

describe("ESLint safety rules", () => {
  it("bans raw-HTML escape hatches", async () => {
    const eslint = new ESLint({ cwd: process.cwd() });
    const [result] = await eslint.lintText(
      [
        "export const A = (p: { s: string }) => <div dangerouslySetInnerHTML={{ __html: p.s }} />;",
        "export function b(el: HTMLElement, s: string) { el.innerHTML = s; el.insertAdjacentHTML('beforeend', s); }",
      ].join("\n"),
      { filePath: "src/banned-example.tsx" },
    );
    const messages = result!.messages.map((message) => message.message);
    expect(messages.some((m) => m.includes("dangerouslySetInnerHTML is banned"))).toBe(true);
    expect(messages.some((m) => m.includes("innerHTML/outerHTML are banned"))).toBe(true);
    expect(messages.some((m) => m.includes("insertAdjacentHTML is banned"))).toBe(true);
  });
});
