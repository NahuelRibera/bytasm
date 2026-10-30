import { screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { ToolsPage } from "./pages/ToolsPage";
import { renderWithClient } from "./test/render";
import { installFetch, json } from "./test/fakeApi";

it("shows Ghidra diagnostics without promising an available provider or an analysis action", async () => {
  installFetch({ "GET /api/v1/tools": () => json({ tools: [], profiles: [], optional_providers: [{
    provider: "ghidra", available: false, analysis_enabled: false, status: "execution_unavailable",
    message: "No verified offline runner; no tool was launched.", verification: "metadata_only",
    health_check: "not_run", declared_ghidra_version: "12.2", declared_java_major: 25,
  }] }) });
  renderWithClient(<ToolsPage />);
  expect(await screen.findByRole("heading", { name: "Optional Ghidra provider" })).toBeTruthy();
  expect(screen.getByText(/No verified offline runner/)).toBeTruthy();
  expect(screen.getByText(/Metadata only/)).toBeTruthy();
  expect(screen.getByText(/Health check: not run/)).toBeTruthy();
  expect(screen.queryByRole("button", { name: /Ghidra|analy/i })).toBeNull();
});

it("keeps Tools loading and API failure states visible", async () => {
  installFetch({ "GET /api/v1/tools": () => json({ code: "unavailable", title: "Unavailable", detail: "Try again", status: 503 }, 503) });
  renderWithClient(<ToolsPage />);
  expect(screen.getByRole("status")).toBeTruthy();
  expect(await screen.findByText("Try again")).toBeTruthy();
});
