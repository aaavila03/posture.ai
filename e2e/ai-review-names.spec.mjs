// Browser test: the four buttons that ask for an AI review have the same name.
import { test, expect } from "@playwright/test";

test("every AI review button is called Review with AI", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");

  for (const id of ["#btn-ai-assess", "#btn-vendor-ai"]) await expect(page.locator(id)).toHaveText("✨ Review with AI");
  // These two are drawn with their forms: on the Risk review step of a posture snapshot report, and the Risk scoring step of a threat assessment.
  await page.locator('.tab[data-view="assessments"]').click();
  await page.locator("#assessment-table button.row-name").first().click();
  await expect(page.locator("#btn-snapshot-review")).toHaveText("✨ Review with AI");
  await page.goto("/demo/");
  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#tra-table button.row-name").first().click();
  await page.locator("#tra-steps button").nth(3).click();
  await expect(page.locator("#btn-tra-ai-review")).toHaveText("✨ Review with AI");
  expect(errors, "no errors on the page").toEqual([]);
});
