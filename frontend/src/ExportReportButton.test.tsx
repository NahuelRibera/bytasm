import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ExportReportButton } from "./ExportReportButton";
import { VERSION_ID, installFetch, json } from "./test/fakeApi";
import { renderWithClient } from "./test/render";

describe("Export JSON report", () => {
  it("creates the report with the custom header and reports its hash", async () => {
    const user = userEvent.setup();
    const calls = installFetch({
      [`POST /api/v1/sample-versions/${VERSION_ID}/reports`]: () =>
        json(
          {
            id: "e".repeat(32),
            sample_version_id: VERSION_ID,
            format: "json",
            sha256: "1234567890abcdef".repeat(4),
            generated_at: "2026-10-27T10:00:00Z",
            download_url: `/api/v1/reports/${"e".repeat(32)}/download`,
          },
          201,
        ),
    });
    renderWithClient(<ExportReportButton versionId={VERSION_ID} />);
    await user.click(screen.getByRole("button", { name: "Export JSON report" }));
    expect(await screen.findByText(/Report exported/)).toBeTruthy();
    const post = calls.find((call) => call.init?.method === "POST")!;
    expect((post.init!.headers as Record<string, string>)["X-Bytasm-Request"]).toBe("1");
  });

  it("shows the integrity error when the stored file changed", async () => {
    const user = userEvent.setup();
    installFetch({
      [`POST /api/v1/sample-versions/${VERSION_ID}/reports`]: () =>
        json(
          {
            type: "urn:bytasm:error:integrity_error",
            code: "integrity_error",
            title: "Stored file changed",
            status: 409,
            detail: "A stored file no longer matches its recorded SHA-256. Nothing was exported.",
          },
          409,
        ),
    });
    renderWithClient(<ExportReportButton versionId={VERSION_ID} />);
    await user.click(screen.getByRole("button", { name: "Export JSON report" }));
    expect((await screen.findByRole("alert")).textContent).toContain("Nothing was exported");
  });
});
