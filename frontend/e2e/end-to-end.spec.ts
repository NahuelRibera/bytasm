// End to end (v0.1 slice): import a committed fixture in the UI → see its
// metadata in the UI and through the API → export the JSON report, download
// it, and check it against the committed schema and the API data.
import { expect, test } from "@playwright/test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { FIXTURES_URL } from "../playwright.config";
import { FIXTURE, REPO, createProject, expectNoAxeViolations, importFile } from "./helpers";

const fixture = "entropy_blob-aarch64.elf";

test("import → metadata (UI and API) → JSON report export", async ({ page, request }) => {
  const bytes = readFileSync(FIXTURE(fixture));
  const sha256 = createHash("sha256").update(bytes).digest("hex");

  await createProject(page, FIXTURES_URL, "End to end");
  await importFile(page, FIXTURE(fixture), { sample: "entropy-demo", label: "v1" });

  // UI: identity and metadata.
  await expect(page.getByTestId("sha256")).toHaveText(sha256);
  await expect(page.getByText("ELF · aarch64")).toBeVisible();
  await expect(page.getByRole("cell", { name: ".blob", exact: true })).toBeVisible();
  await expect(page.getByText("no file data").first()).toBeVisible();
  const versionId = page.url().split("/versions/")[1]!;

  // API: the same version, retrieved independently.
  const version = await (await request.get(`${FIXTURES_URL}/api/v1/sample-versions/${versionId}`)).json();
  expect(version.sha256).toBe(sha256);
  expect(version.admitted_under).toBe("fixture_manifest");
  const sections = await (
    await request.get(`${FIXTURES_URL}/api/v1/sample-versions/${versionId}/sections`)
  ).json();
  const blob = sections.sections.find((s: { name: string }) => s.name === ".blob");
  expect(blob.entropy).toBeGreaterThan(7.9);

  // Export through the UI: a real browser download.
  const downloadEvent = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export JSON report" }).click();
  const download = await downloadEvent;
  expect(download.suggestedFilename()).toMatch(/^bytasm-report-[0-9a-f]{16}-[0-9a-f]{8}\.json$/);
  const text = readFileSync((await download.path())!, "utf8");
  await expect(page.getByText(/Report exported/)).toBeVisible();
  await expectNoAxeViolations(page);

  const report = JSON.parse(text);
  expect(report.report_kind).toBe("bytasm.sample_version_report");
  expect(report.schema_version).toBe(3);
  expect(report.pattern_analysis).toBeNull();
  expect(report.sample.sha256).toBe(sha256);
  expect(report.sample.sample_name).toBe("entropy-demo");
  expect(report.input_policy.admitted_under).toBe("fixture_manifest");
  expect(report.authorization.type).toBe("self_attestation");
  expect(report.analysis.tool_invocations[0].tool).toBe("lief");
  const reportBlob = report.metadata.sections.find((s: { name: string }) => s.name === ".blob");
  expect(reportBlob.entropy.value).toBe(blob.entropy);
  expect(reportBlob.entropy.unit).toBe("bits_per_byte");

  // The schema is the committed one, and required top-level fields are present.
  const schema = JSON.parse(readFileSync(join(REPO, "schemas", "report.schema.json"), "utf8"));
  expect(Object.keys(report).sort()).toEqual([...schema.required].sort());

  // Reproducible: a second export differs only in generated_at.
  const second = await (
    await request.post(`${FIXTURES_URL}/api/v1/sample-versions/${versionId}/reports`, {
      headers: { "X-Bytasm-Request": "1" },
    })
  ).json();
  const secondReport = await (await request.get(`${FIXTURES_URL}${second.download_url}`)).json();
  const { generated_at: _a, ...first } = report;
  const { generated_at: _b, ...again } = secondReport;
  void _a;
  void _b;
  expect(again).toEqual(first);
});
