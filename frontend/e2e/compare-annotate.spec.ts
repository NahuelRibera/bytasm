import { expect, test, type Page } from "@playwright/test";
import { readFile } from "node:fs/promises";
import { FIXTURES_URL } from "../playwright.config";
import { createProject, expectNoAxeViolations, FIXTURE, importFile, STATEMENT } from "./helpers";

async function analyse(page: Page) {
  await page.getByRole("button", { name: "Run pattern matching…" }).click();
  await page.getByRole("button", { name: "Start run", exact: true }).click();
  await expect(page.getByTestId("status").first()).toHaveText("Succeeded", { timeout: 30_000 });
}

test("compare, cite a finding, revise, review activity and export at 360 px", async ({ page, request }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await createProject(page, FIXTURES_URL, "Compare and annotate");
  const projectUrl = page.url();
  await importFile(page, FIXTURE("hello_v1-x86_64.elf"), { sample: "hello", label: "v1" });
  await analyse(page);
  const firstRun = await (await request.get(`${FIXTURES_URL}/api/v1/runs/${page.url().split("/runs/")[1]}`)).json();
  await page.goto(`${projectUrl}/import`);
  await page.getByLabel("File", { exact: true }).setInputFiles(FIXTURE("hello_v2-x86_64.elf"));
  await page.getByRole("radio", { name: "A new version of an existing sample" }).check();
  await page.getByRole("combobox", { name: "Sample", exact: true }).selectOption({ label: "hello" });
  await page.getByLabel("Version label (optional)").fill("v2");
  await page.getByLabel("Statement", { exact: true }).fill(STATEMENT);
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("v2");
  await analyse(page);
  await page.getByRole("button", { name: "Inspect url_reference", exact: true }).click();
  const evidence = page.getByRole("region", { name: "Evidence: url_reference" });
  await evidence.getByRole("button", { name: "Add note / View annotations" }).click();
  const annotations = evidence.getByRole("region", { name: "Analyst annotations", exact: true });
  await annotations.getByRole("button", { name: "Add note", exact: true }).click();
  await annotations.getByLabel("Kind", { exact: true }).selectOption("conclusion");
  await annotations.getByLabel("Annotation text", { exact: true }).fill("I reviewed this pattern in the file.");
  await annotations.getByLabel("Confidence", { exact: true }).selectOption("likely");
  await annotations.getByRole("checkbox").first().check();
  await annotations.getByRole("button", { name: "Save annotation", exact: true }).focus();
  await page.keyboard.press("Enter");
  await expect(annotations.getByText("Annotation saved.", { exact: true })).toBeVisible();
  await annotations.getByRole("button", { name: "Revise", exact: true }).click();
  await annotations.getByLabel("Annotation text", { exact: true }).fill("I checked the cited evidence again.");
  await annotations.getByRole("button", { name: "Save revision", exact: true }).click();
  await expect(annotations.getByText("I checked the cited evidence again.", { exact: true })).toBeVisible();
  await annotations.getByRole("button", { name: "Revision history", exact: true }).click();
  await expect(annotations.getByText("I reviewed this pattern in the file.", { exact: true })).toBeVisible();
  await expectNoAxeViolations(page);

  await page.goto(projectUrl);
  const activity = page.getByRole("region", { name: "Activity", exact: true });
  await expect(activity.getByText("Analyst annotation added", { exact: true })).toBeVisible();
  await expect(activity.getByText("Analyst annotation revised", { exact: true })).toBeVisible();
  // Activity must open the annotation's finding target, not the version-level notes.
  await activity.getByRole("link", { name: "View analyst annotations" }).first().click();
  await expect(page.getByText("I checked the cited evidence again.", { exact: true })).toBeVisible();
  const secondRunId = page.url().split("/runs/")[1]!.split("?")[0]!;
  const matches = await (await request.get(`${FIXTURES_URL}/api/v1/runs/${secondRunId}/findings`)).json();
  const evidenceId = String(matches.findings[0].evidence[0].id);
  const createdNote = await request.post(`${FIXTURES_URL}/api/v1/annotations`, {
    headers: { "X-Bytasm-Request": "1" },
    data: { target_type: "evidence", target_id: evidenceId, kind: "note", body: "Evidence timeline destination" },
  });
  expect(createdNote.status()).toBe(201);
  await page.goto(projectUrl);
  await page.locator(`a[href="/runs/${secondRunId}?annotations=1#evidence-${evidenceId}"]`).click();
  await expect(page.getByText("Evidence timeline destination", { exact: true })).toBeVisible();
  await expectNoAxeViolations(page);
  await page.goto(projectUrl);
  await page.getByRole("link", { name: "Compare versions of hello", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("Compare hello");
  await expect(page.getByLabel("Version A", { exact: true })).toHaveValue(firstRun.sample.version_id);
  await page.getByRole("button", { name: "Strings", exact: true }).click();
  await expect(page.getByRole("heading", { level: 2, name: "Strings", exact: true })).toBeVisible();
  await expect(page.getByText("Step A: succeeded · Step B: succeeded", { exact: true })).toBeVisible();
  await expectNoAxeViolations(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
  const downloading = page.waitForEvent("download");
  await page.getByRole("button", { name: "Export comparison JSON report", exact: true }).click();
  const download = await downloading;
  const report = JSON.parse(await readFile((await download.path())!, "utf8"));
  expect(report.schema_version).toBe(4);
  expect(report.scope.kind).toBe("comparison");
  const conclusion = report.annotations.find((item: { kind: string }) => item.kind === "conclusion");
  expect(conclusion.revision).toBe(2);
  expect(conclusion.body).toBe("I checked the cited evidence again.");
  expect(conclusion.cites.length).toBeGreaterThan(0);
  expect(report.comparison.a.version_id).toBe(firstRun.sample.version_id);
});
