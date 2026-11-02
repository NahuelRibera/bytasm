// M2 Journey validation (docs/milestones/m2-journey-frontend.md) against the real `bytasm serve` +
// `bytasm worker`: the approved isotipo, the routes M1 left unchanged, the run workstation's
// section index and file map, and reduced atmosphere on the masthead. Screenshots go to
// test-results/m2/ for owner review; they are not pixel baselines.
import { expect, test, type Page } from "@playwright/test";
import { FIXTURES_URL } from "../playwright.config";
import { FIXTURE, createProject, expectNoAxeViolations, importFile } from "./helpers";

const VIEWPORTS = [
  { name: "1440", width: 1440, height: 900 },
  { name: "1024", width: 1024, height: 768 },
  { name: "768", width: 768, height: 1024 },
  { name: "390", width: 390, height: 844 },
  { name: "360", width: 360, height: 740 },
] as const;

async function check(page: Page, shot: string, viewport: string) {
  await page.evaluate(() => document.fonts.ready);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, `${shot} is wider than the ${viewport} px viewport`).toBeLessThanOrEqual(0);
  await expectNoAxeViolations(page);
  await page.screenshot({ path: `test-results/m2/${shot}-${viewport}.png`, fullPage: true });
}

test("the approved isotipo, favicon and display serif load from Bytasm's own origin", async ({ page, request }) => {
  for (const path of ["/branding/bytasm-icon.svg", "/branding/bytasm-icon.png", "/branding/derived/bytasm-icon-180.png"]) {
    const response = await request.get(`${FIXTURES_URL}${path}`);
    expect(response.status(), path).toBe(200);
  }
  await page.goto(`${FIXTURES_URL}/`);
  await expect(page.locator('link[rel="icon"][type="image/svg+xml"]')).toHaveAttribute("href", "/branding/bytasm-icon.svg");
  const mark = page.getByRole("banner").getByRole("link", { name: "Bytasm home" }).locator(".isotipo");
  await expect(mark).toHaveCSS("background-image", /\/branding\/bytasm-icon\.svg/);
  await expect(page.getByRole("heading", { level: 1 })).toHaveCSS("font-family", /Cormorant Garamond/);
  expect(await page.evaluate(() => document.fonts.check('600 40px "Cormorant Garamond Variable"'))).toBe(true);
});

test("Journey screens at every planned viewport", async ({ page }) => {
  test.setTimeout(240_000);
  const external: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(FIXTURES_URL)) external.push(request.url());
  });

  await createProject(page, FIXTURES_URL, "M2 journey review");
  await importFile(page, FIXTURE("hello_v1-x86_64.exe"), { sample: "hello", label: "v1" });
  await expect(page.getByTestId("sha256")).toBeVisible();
  const versionUrl = page.url();
  await page.getByRole("button", { name: "Run pattern matching…" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await expect(page.getByTestId("status").first()).toHaveText("Succeeded", { timeout: 30_000 });
  const runUrl = page.url();

  // The run workstation: index, coverage, and the file map plots the real match offsets.
  await expect(page.getByRole("navigation", { name: "Run sections" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Coverage" })).toBeVisible();
  const map = page.getByRole("img", { name: /Where the matched bytes sit in the file/ });
  await expect(map).toHaveAttribute("aria-label", /3 matched byte ranges/);
  await page.getByRole("button", { name: "Inspect url_reference" }).click();
  await expect(page.locator(".file-map-mark.is-selected")).toHaveCount(1);

  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });

    await page.goto(`${FIXTURES_URL}/`);
    await expect(page.getByRole("heading", { level: 1, name: "Static analysis for unknown lands" })).toBeVisible();
    await expect(page.locator('[data-character="muerte"]')).toBeAttached();
    await check(page, "projects", viewport.name);

    await page.goto(runUrl);
    await expect(page.getByRole("heading", { name: "Understand" })).toBeVisible();
    await check(page, "run", viewport.name);

    await page.goto(versionUrl);
    await expect(page.getByRole("navigation", { name: "Sample version sections" })).toBeVisible();
    await expect(page.getByRole("img", { name: /Sections along the file/ })).toBeVisible();
    await check(page, "version", viewport.name);

    await page.goto(`${FIXTURES_URL}/rules`);
    await expect(page.getByRole("heading", { level: 1, name: /YARA-X rules/ })).toBeVisible();
    await check(page, "rules", viewport.name);

    await page.goto(`${FIXTURES_URL}/tools`);
    await expect(page.getByRole("heading", { level: 1, name: "Tools and profiles" })).toBeVisible();
    await check(page, "tools", viewport.name);
  }

  // Reduced atmosphere removes the scene; the masthead copy and actions stay.
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto(`${FIXTURES_URL}/`);
  await page.getByRole("button", { name: "Reduce atmosphere" }).click();
  await expect(page.locator(".journey-scene")).toBeHidden();
  await expect(page.getByRole("link", { name: "New project" })).toBeVisible();
  await page.screenshot({ path: "test-results/m2/projects-reduced-1440.png" });

  expect(external, "requests left Bytasm's origin").toEqual([]);
});
