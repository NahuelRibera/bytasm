// M2.1 visual refinement (docs/milestones/m2.1-visual-refinement.md) against the real `bytasm serve`
// + `bytasm worker`: the Compare bench and its warning badge, every masthead scene at every planned
// viewport (no overflow, no axe violation), figures framed with their whole head inside the frame,
// and reduced atmosphere removing every scene. Screenshots go to test-results/m2.1/ for review.
import { expect, test, type Locator, type Page } from "@playwright/test";
import { FIXTURES_URL } from "../playwright.config";
import { FIXTURE, STATEMENT, createProject, expectNoAxeViolations, importFile } from "./helpers";

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
  await page.screenshot({ path: `test-results/m2.1/${shot}-${viewport}.png`, fullPage: true });
}

/** The figure's top edge (where every engraving keeps its head) lies inside its frame. Both boxes
 * are read in one layout pass, because sections above can still be rendering. */
async function expectHeadInside(figure: Locator, frameSelector: string) {
  await figure.page().waitForLoadState("networkidle");
  const box = await figure.evaluate((el, selector) => {
    const frame = el.closest(selector);
    if (!frame) return null;
    const f = el.getBoundingClientRect();
    const c = frame.getBoundingClientRect();
    return { top: f.top - c.top, left: f.left - c.left, right: c.right - f.right, opacity: Number(getComputedStyle(el).opacity) };
  }, frameSelector);
  expect(box, "figure sits inside its frame").not.toBeNull();
  expect(box!.top).toBeGreaterThanOrEqual(0);
  expect(box!.left).toBeGreaterThanOrEqual(-1);
  expect(box!.right).toBeGreaterThanOrEqual(-1);
  expect(box!.opacity).toBeGreaterThanOrEqual(0.6);
}

test("M2.1 scenes, Compare and figure framing at every planned viewport", async ({ page }) => {
  test.setTimeout(300_000);
  const external: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(FIXTURES_URL)) external.push(request.url());
  });

  await createProject(page, FIXTURES_URL, "M2.1 refinement review");
  const projectUrl = page.url();
  await importFile(page, FIXTURE("hello_v1-x86_64.elf"), { sample: "hello", label: "v1" });
  await expect(page.getByTestId("sha256")).toBeVisible();
  const versionUrl = page.url();
  await page.getByRole("button", { name: "Run pattern matching…" }).click();
  await page.getByRole("button", { name: "Start run", exact: true }).click();
  await expect(page.getByTestId("status").first()).toHaveText("Succeeded", { timeout: 30_000 });
  const storedRules = await page.locator('a[href^="/rules/"]').first().getAttribute("href");
  expect(storedRules).toMatch(/^\/rules\/[0-9a-f]{32}$/);

  await page.goto(`${projectUrl}/import`);
  await page.getByLabel("File", { exact: true }).setInputFiles(FIXTURE("hello_v2-x86_64.elf"));
  await page.getByRole("radio", { name: "A new version of an existing sample" }).check();
  await page.getByRole("combobox", { name: "Sample", exact: true }).selectOption({ label: "hello" });
  await page.getByLabel("Version label (optional)").fill("v2");
  await page.getByLabel("Statement", { exact: true }).fill(STATEMENT);
  await page.getByRole("button", { name: "Import", exact: true }).click();
  await expect(page.getByRole("heading", { level: 1 })).toContainText("v2");
  await page.goto(projectUrl);
  await page.getByRole("link", { name: "Compare versions of hello", exact: true }).click();
  const compareUrl = page.url();

  // Compare: the bench keeps both selectors and links; the backend's warning is still shown in
  // full, as a labelled note with a badge rather than an amber block.
  await expect(page.getByRole("combobox", { name: "Version A" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Version B" })).toBeVisible();
  const limitation = page.getByRole("note").filter({ hasText: "Limitation" }).first();
  await expect(limitation).toBeVisible();
  await expect(limitation).toContainText(/library association/);
  await expect(page.getByRole("navigation", { name: "Comparison categories" }).getByRole("button")).toHaveCount(8);
  await expect(page.getByRole("button", { name: "Metadata", exact: true })).toHaveAttribute("aria-pressed", "true");

  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });
    for (const [shot, url] of [
      ["compare", compareUrl],
      ["project", projectUrl],
      ["version", versionUrl],
      ["rules-stored", `${FIXTURES_URL}${storedRules}`],
    ] as const) {
      await page.goto(url);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      await check(page, shot, viewport.name);
    }
  }

  // Every figure placement keeps its head inside its frame at desktop width.
  await page.setViewportSize({ width: 1440, height: 900 });
  for (const [url, character] of [
    [`${FIXTURES_URL}/tools`, "automaton"],
    [`${FIXTURES_URL}/rules`, "wizard"],
    [`${FIXTURES_URL}${storedRules}`, "executioner"],
  ] as const) {
    await page.goto(url);
    await expectHeadInside(page.locator(`.mast [data-character="${character}"]`), ".mast");
  }
  await page.goto(versionUrl);
  await expectHeadInside(page.locator('.band-scene [data-character="mystic"]'), ".band-scene");
  // No character stands beside a project's samples: its mast is architecture only.
  await page.goto(projectUrl);
  await expect(page.locator(".mast .mast-scene-architecture")).toBeAttached();
  await expect(page.locator(".mast [data-character]")).toHaveCount(0);

  // The hero draws the rider inside the scene, on its ridge; no star sits on the rider.
  await page.goto(`${FIXTURES_URL}/`);
  await expect(page.locator('.journey-scene image[href="/art/chars/muerte.cutout.png"]')).toBeAttached();

  // Reduced atmosphere removes every mast scene; titles and actions stay.
  await page.getByRole("button", { name: "Reduce atmosphere" }).click();
  for (const url of [compareUrl, `${FIXTURES_URL}/tools`, versionUrl]) {
    await page.goto(url);
    await expect(page.locator(".mast-scene")).toBeHidden();
    await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  }
  await page.goto(versionUrl);
  await expect(page.locator(".band-art")).toBeHidden();
  await page.screenshot({ path: "test-results/m2.1/version-reduced-1440.png" });
  await page.getByRole("button", { name: /atmosphere/ }).click();

  expect(external, "requests left Bytasm's origin").toEqual([]);
});
