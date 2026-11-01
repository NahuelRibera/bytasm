// M1 visual validation (docs/design/FRONTEND_ROADMAP.md §9) against the real `bytasm serve` +
// `bytasm worker`: the shell, Projects, Project, Run and 404 at the four planned viewports.
// Every screen must fit without page-level horizontal scroll and stay free of axe violations.
// Screenshots go to test-results/m1/ for owner review; they are not pixel baselines.
import { expect, test, type Page } from "@playwright/test";
import { FIXTURES_URL } from "../playwright.config";
import { FIXTURE, createProject, expectNoAxeViolations, importFile } from "./helpers";

const VIEWPORTS = [
  { name: "1440", width: 1440, height: 900 },
  { name: "1024", width: 1024, height: 768 },
  { name: "390", width: 390, height: 844 },
  { name: "360", width: 360, height: 740 },
] as const;

async function check(page: Page, shot: string, viewport: string) {
  await page.evaluate(() => document.fonts.ready);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow, `${shot} is wider than the ${viewport} px viewport`).toBeLessThanOrEqual(0);
  await expectNoAxeViolations(page);
  await page.screenshot({ path: `test-results/m1/${shot}-${viewport}.png`, fullPage: true });
}

test("character masks and fonts are served from Bytasm's own origin", async ({ request }) => {
  for (const name of ["crow", "scavenger", "nohead"]) {
    const response = await request.get(`${FIXTURES_URL}/art/chars/${name}.cutout.png`);
    expect(response.status()).toBe(200);
    expect(response.headers()["content-type"]).toContain("image/png");
  }
  const page = await (await request.get(`${FIXTURES_URL}/`)).text();
  expect(page).not.toMatch(/fonts\.googleapis|fonts\.gstatic/);
});

test("M1 screens at every planned viewport", async ({ page }) => {
  test.setTimeout(180_000);
  const external: string[] = [];
  page.on("request", (request) => {
    if (!request.url().startsWith(FIXTURES_URL)) external.push(request.url());
  });

  // A run with findings to show steps, the selected finding and the inspector.
  await createProject(page, FIXTURES_URL, "M1 visual review");
  const projectUrl = page.url();
  await importFile(page, FIXTURE("hello_v1-x86_64.exe"), { sample: "hello", label: "v1" });
  await expect(page.getByTestId("sha256")).toBeVisible();
  await page.getByRole("button", { name: "Run pattern matching…" }).click();
  await page.getByRole("button", { name: "Start run" }).click();
  await expect(page.getByRole("heading", { level: 1, name: /Analysis run/ })).toBeVisible();
  await expect(page.getByTestId("status").first()).toHaveText("Succeeded", { timeout: 30_000 });
  const runUrl = page.url();

  for (const viewport of VIEWPORTS) {
    await page.setViewportSize({ width: viewport.width, height: viewport.height });

    // Projects, empty: the crow placement. The list is stubbed empty because other specs share the server.
    await page.route("**/api/v1/projects", (route) =>
      route.request().method() === "GET" ? route.fulfill({ json: [] }) : route.continue(),
    );
    await page.goto(`${FIXTURES_URL}/`);
    await expect(page.getByRole("heading", { name: "No projects yet" })).toBeVisible();
    await expect(page.locator('[data-character="crow"]')).toBeAttached();
    await check(page, "projects-empty", viewport.name);
    await page.unroute("**/api/v1/projects");

    await page.goto(`${FIXTURES_URL}/`);
    await expect(page.getByRole("region", { name: "Projects table" })).toBeVisible();
    await check(page, "projects", viewport.name);

    await page.goto(projectUrl);
    await expect(page.getByRole("region", { name: "Versions of hello" })).toBeVisible();
    await expect(page.locator(".binary-art")).toHaveCount(0);
    await check(page, "project", viewport.name);

    await page.route("**/api/v1/projects/*/samples", (route) => route.fulfill({ json: [] }));
    await page.goto(projectUrl);
    await expect(page.getByText("No samples yet.")).toBeVisible();
    await expect(page.locator('[data-character="scavenger"]')).toBeAttached();
    await check(page, "project-empty", viewport.name);
    await page.unroute("**/api/v1/projects/*/samples");

    await page.goto(runUrl);
    await expect(page.getByRole("region", { name: "Findings table" })).toBeVisible();
    await page.getByRole("button", { name: "Inspect url_reference" }).click();
    await expect(page.getByRole("region", { name: /^Evidence:/ })).toBeVisible();
    await expect(page.locator(".binary-art")).toHaveCount(0);
    await check(page, "run", viewport.name);

    await page.goto(`${FIXTURES_URL}/nowhere`);
    await expect(page.getByRole("heading", { level: 1, name: "Not found" })).toBeVisible();
    await check(page, "not-found", viewport.name);
  }

  // Reduced atmosphere hides decorative art and survives a reload.
  await page.goto(`${FIXTURES_URL}/nowhere`);
  await page.getByRole("button", { name: "Reduce atmosphere" }).click();
  await expect(page.locator('[data-character="nohead"]')).toBeHidden();
  await page.reload();
  await expect(page.locator("html")).toHaveAttribute("data-atmosphere", "off");
  await expect(page.locator('[data-character="nohead"]')).toBeHidden();

  expect(external, "requests left Bytasm's origin").toEqual([]);
});

test.describe("reduced motion", () => {
  test.use({ reducedMotion: "reduce" });

  test("motion tokens collapse to zero", async ({ page }) => {
    await page.goto(`${FIXTURES_URL}/`);
    const duration = await page.evaluate(() => getComputedStyle(document.documentElement).getPropertyValue("--dur-2").trim());
    expect(["0ms", "0s"]).toContain(duration);
  });
});
