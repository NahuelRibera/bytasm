import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { App } from "../App";
import { HOSTILE, PROJECT_ID, VERSION_ID, health, installFetch, json, ruleSet, run, version } from "../test/fakeApi";
import { renderWithClient } from "../test/render";

describe("Rules page", () => {
  it("shows the bundled rule source and a successful validation", async () => {
    const user = userEvent.setup();
    window.history.pushState({}, "", "/rules");
    installFetch({
      "GET /api/v1/health": () => json(health()),
      "GET /api/v1/rule-sets/current": () => json(ruleSet({ id: null })),
      "POST /api/v1/rule-sets/current/validation": () =>
        json({
          rule_set_sha256: "9".repeat(64),
          label: "bytasm-rules@0.2.0",
          yara_x_version: "1.22.1",
          compiled: true,
          rule_identifiers: ["url_reference"],
          problems: [],
          errors: [],
          warnings: [],
          duration_ms: 12,
        }),
    });
    renderWithClient(<App />);
    expect(await screen.findByRole("heading", { level: 1, name: /YARA-X rules/ })).toBeTruthy();
    expect(screen.getByLabelText("Source of rule url_reference").textContent).toMatch(/\$https/);
    expect(screen.getByText(/cannot be edited from the UI/)).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Validate rules" }));
    expect(await screen.findByText(/1 rules compiled with YARA-X 1.22.1/)).toBeTruthy();
  });

  it("shows bounded compiler errors with their location, as text", async () => {
    const user = userEvent.setup();
    window.history.pushState({}, "", "/rules");
    installFetch({
      "GET /api/v1/health": () => json(health()),
      "GET /api/v1/rule-sets/current": () =>
        json(ruleSet({ files: [{ name: "x.yar", identifier: "x", text: HOSTILE }] })),
      "POST /api/v1/rule-sets/current/validation": () =>
        json({
          rule_set_sha256: "9".repeat(64),
          label: "bytasm-rules@0.2.0",
          yara_x_version: "1.22.1",
          compiled: false,
          rule_identifiers: [],
          problems: [],
          errors: [{ code: "E009", title: `unknown identifier ${HOSTILE}`, file: "x.yar", line: 3, column: 7 }],
          warnings: [],
          duration_ms: 9,
        }),
    });
    const { container } = renderWithClient(<App />);
    await user.click(await screen.findByRole("button", { name: "Validate rules" }));
    expect(await screen.findByText("The rules did not compile")).toBeTruthy();
    expect(screen.getByText("E009")).toBeTruthy();
    expect(screen.getByText("at x.yar:3:7")).toBeTruthy();
    expect(screen.getByText(`unknown identifier ${HOSTILE}`)).toBeTruthy();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
  });

  it("shows an earlier rule set as no longer current", async () => {
    window.history.pushState({}, "", `/rules/${"f".repeat(32)}`);
    installFetch({
      "GET /api/v1/health": () => json(health()),
      [`GET /api/v1/rule-sets/${"f".repeat(32)}`]: () => json(ruleSet({ current: false, version: "0.0.9" })),
    });
    renderWithClient(<App />);
    expect(await screen.findByText(/Earlier version/)).toBeTruthy();
    expect(screen.getByText(/differ from the current ones/)).toBeTruthy();
  });
});

describe("Starting a run from a sample version", () => {
  it("asks for confirmation naming the sample and rules, then starts one run", async () => {
    const user = userEvent.setup();
    window.history.pushState({}, "", `/versions/${VERSION_ID}`);
    const calls = installFetch({
      "GET /api/v1/health": () => json(health()),
      [`GET /api/v1/sample-versions/${VERSION_ID}`]: () => json(version()),
      [`GET /api/v1/sample-versions/${VERSION_ID}/sections`]: () =>
        json({ entropy_method: "m", entropy_unit: "bits_per_byte", sections: [] }),
      [`GET /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json({ runs: [] }),
      "GET /api/v1/rule-sets/current": () => json(ruleSet()),
      [`POST /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json(run({ status: "queued" }), 202),
      [`GET /api/v1/runs/${"e".repeat(32)}`]: () => json(run({ status: "queued", finished_at: null })),
    });
    renderWithClient(<App />);
    expect(await screen.findByText("No analysis runs yet for this version.")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Run pattern matching…" }));
    const confirm = await screen.findByRole("group", { name: "Start a run?" });
    expect(confirm.textContent).toMatch(/bytasm-rules@0\.2\.0/);
    expect(confirm.textContent).toMatch(/hello v1/);
    await user.click(screen.getByRole("button", { name: "Start run" }));
    await screen.findByRole("heading", { level: 1, name: /Analysis run/ });
    expect(window.location.pathname).toBe(`/runs/${"e".repeat(32)}`);
    const posts = calls.filter((call) => call.init?.method === "POST");
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]!.init?.body))).toEqual({ profile_id: "default-static" });
  });

  it("shows the conflict with a link when a run is already active", async () => {
    const user = userEvent.setup();
    window.history.pushState({}, "", `/versions/${VERSION_ID}`);
    installFetch({
      "GET /api/v1/health": () => json(health()),
      [`GET /api/v1/sample-versions/${VERSION_ID}`]: () => json(version()),
      [`GET /api/v1/sample-versions/${VERSION_ID}/sections`]: () =>
        json({ entropy_method: "m", entropy_unit: "bits_per_byte", sections: [] }),
      [`GET /api/v1/sample-versions/${VERSION_ID}/runs`]: () => json({ runs: [] }),
      "GET /api/v1/rule-sets/current": () => json(ruleSet()),
      [`POST /api/v1/sample-versions/${VERSION_ID}/runs`]: () =>
        json(
          { code: "run_active", title: "A run is already in progress", status: 409, detail: "Wait.", run_id: "e".repeat(32) },
          409,
        ),
    });
    renderWithClient(<App />);
    await user.click(await screen.findByRole("button", { name: "Run pattern matching…" }));
    await user.click(await screen.findByRole("button", { name: "Start run" }));
    expect(await screen.findByText("The run was not started")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Open the run in progress" })).toBeTruthy();
    expect(PROJECT_ID).toBeTruthy();
  });
});
