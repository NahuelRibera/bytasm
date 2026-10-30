import { screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { installFetch, json } from "../test/fakeApi";
import { renderWithClient } from "../test/render";
import { ToolsPage } from "./ToolsPage";
import { ReportPage } from "./ReportPage";

it("shows real availability and profile limits without opening a sample", async () => {
  installFetch({ "GET /api/v1/tools": () => json({ tools: [{ tool: "capa", version: null, available: false, adapter: "capa_scan", adapter_version: "0.1.0", formats: ["PE x64"], rules_sha256: "1".repeat(64), limitations: "Only two rules." }], profiles: [{ id: "full-static", name: "Full static review", steps: ["strings", "yara-x", "capa"], limitations: "Unsupported formats retain partial results." }] }) });
  renderWithClient(<ToolsPage />);
  expect(await screen.findByText("Unavailable for the configured version")).toBeTruthy();
  expect(screen.getByText("Only two rules.")).toBeTruthy();
  expect(screen.getByText("Unsupported formats retain partial results.")).toBeTruthy();
});

it("renders canonical report summaries as inert text and gates legacy HTML", async () => {
  const hostile = '<img src=x onerror="alert(1)">';
  installFetch({ "GET /api/v1/reports/report/download": () => json({ schema_version: 3, summary: [hostile], limitations: ["Partial results"] }) });
  const { container } = renderWithClient(<ReportPage reportId="report" />);
  expect(await screen.findByText(hostile)).toBeTruthy();
  expect(container.querySelector("img")).toBeNull();
  expect(screen.queryByRole("link", { name: "Download standalone HTML" })).toBeNull();
  expect(screen.getByRole("link", { name: "Download JSON" })).toBeTruthy();
});

it("displays the exact hexadecimal address beyond JavaScript integer precision", async () => {
  installFetch({ "GET /api/v1/reports/wide/download": () => json({ schema_version: 4, summary: [], evidence: { virtual_address: 18446735277616534000, virtual_address_hex: "0xfffff80000001234" } }) });
  renderWithClient(<ReportPage reportId="wide" />);
  expect(await screen.findAllByText("0xfffff80000001234")).toHaveLength(2);
  expect(screen.queryByText("18446735277616534000")).toBeNull();
});
