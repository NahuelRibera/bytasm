import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { HOSTILE, VERSION_ID, health, installFetch, json, sections, version } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

function openVersion(v = version(), s = sections(), mode: "fixtures" | "self_built" = "fixtures") {
  window.history.pushState({}, "", `/versions/${VERSION_ID}`);
  installFetch({
    "GET /api/v1/health": () => json(health(mode)),
    [`GET /api/v1/sample-versions/${VERSION_ID}`]: () => json(v),
    [`GET /api/v1/sample-versions/${VERSION_ID}/sections`]: () => json(s),
    [`GET /api/v1/sample-versions/${VERSION_ID}/imports`]: () =>
      json({ libraries: ["KERNEL32.dll"], functions: [HOSTILE, "puts"] }),
    [`GET /api/v1/sample-versions/${VERSION_ID}/exports`]: () => json({ functions: [] }),
  });
  return renderWithClient(<App />);
}

describe("Sample version overview", () => {
  it("shows identity, declared metadata and provenance", async () => {
    openVersion();
    expect(await screen.findByTestId("sha256")).toHaveProperty(
      "textContent",
      "71f62a001edac210d19897a84c8b1217fa34ca5d3f94e1cc96e537ca1e4423c1",
    );
    expect(screen.getByRole("button", { name: "Copy SHA-256" })).toBeTruthy();
    expect(screen.getByText("as uploaded, untrusted")).toBeTruthy();
    expect(screen.getAllByText("declared in file").length).toBeGreaterThan(3);
    expect(screen.getByText("0x1400013f0")).toBeTruthy();
    expect(screen.getAllByText("Fixture manifest").length).toBeGreaterThan(0);
    expect(screen.getByText("bin/hello_v1-x86_64.exe")).toBeTruthy();
    expect(screen.getByText("lief 1.0.0")).toBeTruthy();
    expect(screen.getByText(/not proof of permission/)).toBeTruthy();
  });

  it("labels entropy as a measurement and shows sections without file data", async () => {
    openVersion();
    expect(await screen.findByText(/is a measurement in bits per byte/)).toBeTruthy();
    expect(screen.getByText(/It is not a verdict/)).toBeTruthy();
    expect(screen.getByText("5.123")).toBeTruthy();
    expect(screen.getByText("no file data")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/malicious|risk score|detected malware/i);
  });

  it("renders hostile file-derived names as text, never as markup", async () => {
    const user = userEvent.setup();
    const { container } = openVersion(
      version({ declared_filename: HOSTILE, sample_name: HOSTILE }),
      sections([HOSTILE, ".bss"]),
      "self_built",
    );
    const table = await screen.findByRole("table");
    expect(within(table).getByText(HOSTILE)).toBeTruthy();
    expect(screen.getAllByText(HOSTILE).length).toBeGreaterThanOrEqual(2);
    await user.click(screen.getByRole("tab", { name: /Imports/ }));
    expect(await screen.findByText("puts")).toBeTruthy();
    expect(screen.getAllByText(HOSTILE).length).toBeGreaterThanOrEqual(2);

    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
  });

  it("supports arrow keys between tabs", async () => {
    const user = userEvent.setup();
    openVersion();
    const sectionsTab = await screen.findByRole("tab", { name: /Sections/ });
    sectionsTab.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: /Imports/ }).getAttribute("aria-selected")).toBe("true");
    expect(document.activeElement).toBe(screen.getByRole("tab", { name: /Imports/ }));
  });

  it("shows the self_built banner on every page while that mode is on", async () => {
    openVersion(version({ admitted_under: "self_built_optin", manifest_entry: null }), sections(), "self_built");
    expect(await screen.findByText(/self_built mode is on/)).toBeTruthy();
    expect(screen.getByText(/Input policy: fixtures \+ self-built/)).toBeTruthy();
    expect(screen.getAllByText("Self-built (operator attestation)").length).toBeGreaterThan(0);
  });

  it("shows no banner in the default fixtures mode", async () => {
    openVersion();
    expect(await screen.findByText(/Input policy: fixtures only/)).toBeTruthy();
    expect(screen.queryByText(/self_built mode is on/)).toBeNull();
  });
});
