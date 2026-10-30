import { expect, test } from "@playwright/test";
import { FIXTURES_URL } from "../playwright.config";
import { expectNoAxeViolations } from "./helpers";

test("optional Ghidra diagnostics are honest, accessible and do not enable an analysis profile", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto(`${FIXTURES_URL}/tools`);
  const panel = page.getByRole("region", { name: "Ghidra diagnostics" });
  await expect(panel.getByRole("heading", { name: "Optional Ghidra provider" })).toBeVisible();
  await expect(panel.getByText("Analysis unavailable.", { exact: true })).toBeVisible();
  await expect(panel.getByText(/Health check: not run/)).toBeVisible();
  await expect(panel.getByRole("button")).toHaveCount(0);
  const response = await page.request.get(`${FIXTURES_URL}/api/v1/tools`);
  const data = await response.json();
  expect(data.optional_providers[0].available).toBe(false);
  expect(data.optional_providers[0].analysis_enabled).toBe(false);
  expect(data.profiles.map((profile: { id: string }) => profile.id)).toEqual(["default-static", "full-static"]);
  await expectNoAxeViolations(page);
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
});
