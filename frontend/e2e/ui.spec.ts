// M4 browser tests against real `bytasm serve` processes (see playwright.config.ts).
// Only Bytasm's committed fixtures and bytes generated here are used; nothing is run.
import { expect, test } from "@playwright/test";
import { FIXTURES_URL, SELF_BUILT_URL } from "../playwright.config";
import {
  FIXTURE,
  STATEMENT,
  createProject,
  expectNoAxeViolations,
  hostileElf,
  importFile,
  modifiedFixture,
  tempFile,
} from "./helpers";

test("imports a fixture and shows its identity and metadata", async ({ page }) => {
  await createProject(page, FIXTURES_URL, "UI flow");
  await expect(page.getByText("No samples yet.")).toBeVisible();
  await expectNoAxeViolations(page);

  await page.getByRole("link", { name: "Import a binary" }).first().click();
  await expect(page.getByText(/Do not import downloaded, received, third-party/)).toBeVisible();
  await expect(page.getByText(/only files listed in Bytasm's fixture manifest/)).toBeVisible();
  await expectNoAxeViolations(page);

  await page.getByLabel("File").setInputFiles(FIXTURE("hello_v1-x86_64.exe"));
  await page.getByLabel("Version label (optional)").fill("v1");
  await page.getByLabel("Statement").fill(STATEMENT);
  await page.getByRole("button", { name: "Import" }).click();

  await expect(page.getByTestId("sha256")).toHaveText(
    "71f62a001edac210d19897a84c8b1217fa34ca5d3f94e1cc96e537ca1e4423c1",
  );
  await expect(page.getByText("PE · x86_64")).toBeVisible();
  await expect(page.getByText("bin/hello_v1-x86_64.exe")).toBeVisible();
  await expect(page.getByText("as uploaded, untrusted")).toBeVisible();
  await expect(page.getByRole("cell", { name: ".text", exact: true })).toBeVisible();
  await expect(page.getByText(/is a measurement in bits per byte/)).toBeVisible();
  await expectNoAxeViolations(page);

  await page.getByRole("tab", { name: /Imports/ }).click();
  await expect(page.getByText("KERNEL32.dll")).toBeVisible();

  // Browse back to the project: the sample and its version are listed.
  await page.getByRole("link", { name: "← UI flow" }).click();
  await expect(page.getByRole("article", { name: "Sample hello_v1-x86_64" })).toBeVisible();
  await expect(page.getByRole("link", { name: "v1" })).toBeVisible();
  await expect(page.getByText("Fixture manifest")).toBeVisible();
});

test("refuses a file that is not in the fixture manifest", async ({ page, request }) => {
  await createProject(page, FIXTURES_URL, "Policy refusal");
  await importFile(page, modifiedFixture("hello_v1-x86_64.elf"));
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("Refused by the input policy");
  await expect(alert).toContainText("The file was not parsed or stored.");
  await expectNoAxeViolations(page);

  const projects = await (await request.get(`${FIXTURES_URL}/api/v1/projects`)).json();
  const project = projects.find((p: { name: string }) => p.name === "Policy refusal");
  expect(project.sample_count).toBe(0);
});

test("rejects a renamed ZIP by its content", async ({ page }) => {
  await createProject(page, FIXTURES_URL, "Renamed zip");
  const zip = Buffer.concat([Buffer.from("PK\x03\x04", "latin1"), Buffer.alloc(64)]);
  await importFile(page, tempFile("hello_v1-x86_64.exe", zip));
  await expect(page.getByRole("alert")).toContainText("This file looks like a ZIP archive");
});

test("renders a hostile section name as text (self_built test server)", async ({ page }) => {
  const hostile = '<img src=x onerror="window.__pwned=1">';
  let dialogs = 0;
  page.on("dialog", (dialog) => {
    dialogs += 1;
    void dialog.dismiss();
  });
  await createProject(page, SELF_BUILT_URL, "Escaping");
  await expect(page.getByText(/self_built mode is on/)).toBeVisible();
  await importFile(page, hostileElf(hostile), { sample: hostile });

  await expect(page.getByRole("cell", { name: hostile })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toContainText(hostile);
  await expect(page.getByText("Self-built (operator attestation)").first()).toBeVisible();
  expect(await page.locator("main img").count()).toBe(0);
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined();
  expect(dialogs).toBe(0);
});

test("an import can be done with the keyboard only", async ({ page }) => {
  await createProject(page, FIXTURES_URL, "Keyboard");
  await page.getByRole("link", { name: "Import a binary" }).first().focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Import a binary" })).toBeVisible();

  // A native file dialog cannot be driven by keystrokes in an automated
  // browser; the file chooser is opened from the keyboard and answered.
  const chooser = page.waitForEvent("filechooser");
  await page.getByLabel("File").focus();
  await page.keyboard.press("Space");
  await (await chooser).setFiles(FIXTURE("hello_v1-aarch64.elf"));

  await page.keyboard.press("Tab"); // "A new sample"
  await page.keyboard.press("Tab"); // sample name (prefilled from the file name)
  await page.keyboard.press("Tab"); // version label
  await page.keyboard.type("v-keyboard");
  await page.keyboard.press("Tab"); // basis (fixed)
  await page.keyboard.press("Tab"); // statement
  await page.keyboard.type(STATEMENT);
  await page.keyboard.press("Tab"); // Import button
  await page.keyboard.press("Enter");
  await expect(page.getByText("ELF · aarch64")).toBeVisible();
});

test("a page on another origin cannot create or import anything (Q8)", async ({ page, request }) => {
  await page.route("http://attacker.test/**", (route) =>
    route.fulfill({ contentType: "text/html", body: "<!doctype html><title>attacker</title>" }),
  );
  await page.goto("http://attacker.test/");
  const results = await page.evaluate(async (api) => {
    const attempt = async (init: RequestInit) => {
      try {
        const response = await fetch(`${api}/api/v1/projects`, init);
        return `status:${response.status}`;
      } catch (error) {
        return `blocked:${(error as Error).name}`;
      }
    };
    return {
      withCustomHeader: await attempt({
        method: "POST",
        headers: { "X-Bytasm-Request": "1", "Content-Type": "application/json" },
        body: JSON.stringify({ name: "cross-origin" }),
      }),
      simpleRequest: await attempt({
        method: "POST",
        mode: "no-cors",
        headers: { "Content-Type": "text/plain" },
        body: JSON.stringify({ name: "cross-origin" }),
      }),
    };
  }, FIXTURES_URL);

  // The preflight for the custom header gets no CORS permission.
  expect(results.withCustomHeader).toMatch(/^blocked:/);
  // A "simple" request is sent without the custom header (opaque response) and
  // the server refuses it; either way nothing is created.
  const projects = await (await request.get(`${FIXTURES_URL}/api/v1/projects`)).json();
  expect(projects.map((p: { name: string }) => p.name)).not.toContain("cross-origin");
});
