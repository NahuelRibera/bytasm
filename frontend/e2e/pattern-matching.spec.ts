// End to end (v0.2), against the real `bytasm serve` + `bytasm worker`:
// inspect and validate the bundled rules → start a run (strings, then YARA-X)
// on an imported fixture → watch both steps finish → inspect findings and
// their byte evidence, check that evidence against the fixture's bytes, and
// search the extracted strings. Fixtures are only read.
import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { FIXTURES_URL } from "../playwright.config";
import { FIXTURE, createProject, expectNoAxeViolations, importFile } from "./helpers";

async function startRun(page: Page) {
  await page.getByRole("button", { name: "Run pattern matching…" }).click();
  const confirm = page.getByRole("group", { name: "Start a run?" });
  await expect(confirm).toContainText("bytasm-rules@0.2.0");
  await page.getByRole("button", { name: "Start run" }).click();
  await expect(page.getByRole("heading", { level: 1, name: /Analysis run/ })).toBeVisible();
  // The page polls until the worker has finished.
  await expect(page.getByTestId("status").first()).toHaveText("Succeeded", { timeout: 30_000 });
}

test("rules → validate → run → findings with byte evidence", async ({ page, request }) => {
  await page.goto(`${FIXTURES_URL}/rules`);
  await expect(page.getByRole("heading", { level: 1, name: /YARA-X rules/ })).toBeVisible();
  await expect(page.getByLabel("Source of rule url_reference")).toContainText('"https://"');
  await page.getByRole("button", { name: "Validate rules" }).click();
  await expect(page.getByTestId("validation-result")).toContainText(/rules compiled with YARA-X/);
  await expectNoAxeViolations(page);

  await createProject(page, FIXTURES_URL, "Pattern matching");
  await importFile(page, FIXTURE("hello_v1-x86_64.exe"), { sample: "hello", label: "v1" });
  await expect(page.getByText("No analysis runs yet for this version.")).toBeVisible();
  await startRun(page);
  const steps = page.getByRole("region", { name: "Run steps" });
  await expect(steps.getByTestId("status")).toHaveText(["Succeeded", "Succeeded"]);
  await expect(steps.getByRole("link", { name: /Download the raw/ })).toHaveCount(2);

  await expect(page.getByText(/needs human interpretation/)).toBeVisible();
  const table = page.getByRole("region", { name: "Findings table" });
  await expect(table.getByText("url_reference", { exact: true })).toBeVisible();
  await expect(table.getByText("pe_dos_stub_message", { exact: true })).toBeVisible();
  await expect(table.getByText("pe_kernel32_import_name", { exact: true })).toBeVisible();
  await expectNoAxeViolations(page);

  await page.getByRole("button", { name: "Inspect url_reference" }).click();
  const panel = page.getByRole("region", { name: /Evidence/ });
  await expect(panel.getByRole("cell", { name: "https://" })).toBeVisible();
  await expect(panel.getByLabel("Source of rule url_reference")).toBeVisible();
  await expect(page.locator("#evidence-heading")).toBeFocused();
  await expectNoAxeViolations(page);
  await page.keyboard.press("Escape");
  await expect(panel).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Inspect url_reference" })).toBeFocused();

  // The evidence, read through the API, is exactly the fixture's bytes.
  const runId = page.url().split("/runs/")[1]!;
  const findings = await (await request.get(`${FIXTURES_URL}/api/v1/runs/${runId}/findings`)).json();
  const bytes = readFileSync(FIXTURE("hello_v1-x86_64.exe"));
  for (const finding of findings.findings) {
    for (const item of finding.evidence) {
      const slice = bytes.subarray(item.file_offset, item.file_offset + Math.min(item.length, 32));
      expect(slice.toString("hex")).toBe(item.excerpt_hex);
    }
  }

  // The run is listed on the version page, and the history link works.
  await page.getByRole("navigation", { name: "Breadcrumb" }).getByRole("link").click();
  await expect(page.getByRole("region", { name: "Runs of this version" })).toContainText("Succeeded");
});

// Every committed fixture now matches at least one bundled rule, so the
// "No rule matched" wording is covered by the unit tests (RunPage.test.tsx)
// and the backend tests with a test rule set.
test("strings from a run are searchable as plain text with their offsets", async ({ page, request }) => {
  await createProject(page, FIXTURES_URL, "Strings");
  await importFile(page, FIXTURE("hello_v1-x86_64.elf"), { sample: "strings", label: "v1" });
  await startRun(page);
  await page.getByRole("link", { name: /Search the strings/ }).click();
  await expect(page.getByRole("tab", { name: /Strings/ })).toHaveAttribute("aria-selected", "true");
  await page.getByLabel("Search strings").fill("example.invalid");
  await page.getByRole("button", { name: "Search" }).click();
  const table = page.getByRole("region", { name: "Strings table" });
  await expect(table.getByText("bytasm fixture v1: https://example.invalid/help")).toBeVisible();
  await expect(page.getByText("Showing 1–1 of 1.")).toBeVisible();
  await expectNoAxeViolations(page);

  // The offset shown is where those bytes are in the fixture.
  const versionId = page.url().split("/versions/")[1]!.split("?")[0]!;
  const body = await (
    await request.get(`${FIXTURES_URL}/api/v1/sample-versions/${versionId}/strings?query=example.invalid`)
  ).json();
  const [item] = body.items;
  const bytes = readFileSync(FIXTURE("hello_v1-x86_64.elf"));
  expect(bytes.subarray(item.offset, item.offset + item.byte_length).toString("latin1")).toBe(item.value);
});

test.describe("narrow window", () => {
  test.use({ viewport: { width: 360, height: 740 } });

  async function expectNoHorizontalPageScroll(page: Page) {
    const { overflow, widest } = await page.evaluate(() => {
      const root = document.documentElement;
      // Name the outermost element that sticks out, to make a failure actionable.
      const outside = [...document.querySelectorAll("body *")].find(
        (element) =>
          !element.closest(".table-scroll, pre, .code-scroll") &&
          element.getBoundingClientRect().right > root.clientWidth + 0.5,
      );
      const widest = outside
        ? `${outside.tagName.toLowerCase()}.${outside.className} "${(outside.textContent ?? "").slice(0, 40)}"`
        : "";
      return { overflow: root.scrollWidth - root.clientWidth, widest };
    });
    expect(overflow, `page is wider than the viewport (${widest})`).toBeLessThanOrEqual(0);
  }

  test("rules, run and evidence fit a 360 px window", async ({ page }) => {
    await page.goto(`${FIXTURES_URL}/rules`);
    await expect(page.getByLabel("Source of rule url_reference")).toBeVisible();
    await expectNoHorizontalPageScroll(page);
    await expectNoAxeViolations(page);

    await createProject(page, FIXTURES_URL, "Narrow pattern matching");
    await importFile(page, FIXTURE("hello_v1-x86_64.elf"), { sample: "narrow-run", label: "v1" });
    await expectNoHorizontalPageScroll(page);
    await startRun(page);
    await expectNoHorizontalPageScroll(page);
    await page.getByRole("button", { name: "Inspect url_reference" }).click();
    await expect(page.getByRole("region", { name: /Evidence/ })).toBeVisible();
    await expectNoHorizontalPageScroll(page);
    await expectNoAxeViolations(page);
    await page.getByRole("link", { name: /Search the strings/ }).click();
    await expect(page.getByRole("region", { name: "Strings table" })).toBeVisible();
    await expectNoHorizontalPageScroll(page);
    await expectNoAxeViolations(page);
  });
});
