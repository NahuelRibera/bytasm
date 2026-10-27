// Narrow windows (blueprint 7.4): every v0.1 screen fits a 360 px viewport
// without horizontal page scrolling (wide tables scroll inside their own
// container), and stays free of axe violations there.
import { expect, test, type Page } from "@playwright/test";
import { FIXTURES_URL } from "../playwright.config";
import { FIXTURE, createProject, expectNoAxeViolations, importFile } from "./helpers";

test.use({ viewport: { width: 360, height: 740 } });

async function expectNoHorizontalPageScroll(page: Page) {
  const overflow = await page.evaluate(() => {
    const root = document.documentElement;
    return root.scrollWidth - root.clientWidth;
  });
  expect(overflow, "page is wider than the viewport").toBeLessThanOrEqual(0);
}

test("every screen fits a 360 px window", async ({ page }) => {
  await createProject(page, FIXTURES_URL, "Narrow window project with a fairly long name");
  await expectNoHorizontalPageScroll(page);
  await expectNoAxeViolations(page);

  await page.getByRole("link", { name: "Import a binary" }).first().click();
  await expect(page.getByRole("heading", { name: "Import a binary" })).toBeVisible();
  await expectNoHorizontalPageScroll(page);
  await expectNoAxeViolations(page);

  await page.goBack();
  await importFile(page, FIXTURE("exports_v1-x86_64.dll"), { sample: "narrow", label: "v1" });
  await expect(page.getByTestId("sha256")).toBeVisible();
  await expectNoHorizontalPageScroll(page);
  await expectNoAxeViolations(page);
  for (const tab of ["Imports", "Exports", "Sections"]) {
    const control = page.getByRole("tab", { name: new RegExp(tab) });
    if ((await control.count()) === 0) continue;
    await control.click();
    await expectNoHorizontalPageScroll(page);
  }

  await page.goto(`${FIXTURES_URL}/`);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expectNoHorizontalPageScroll(page);
});
