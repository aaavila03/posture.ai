// Browser test: the stage filter has no numbers and the impact and criticality choices say Medium, not Moderate.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
  await page.locator('.tab[data-view="register"]').click();
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

test("the stage filter reads like the Stage column and still filters", async ({ page }) => {
  expect(await page.locator("#filter-status option").allTextContents()).toEqual(["All stages", "Identified", "Assessment", "In treatment", "Monitoring", "Accepted", "Closed"]);
  await page.locator("#filter-status").selectOption({ label: "In treatment" });
  const stages = await page.locator("#risk-table tbody tr td:nth-child(7)").allInnerTexts();
  expect(stages.length).toBeGreaterThan(0);
  expect([...new Set(stages.map((s) => s.trim()))]).toEqual(["In treatment"]);
});

test("impact and criticality say Medium, and a saved 3. Moderate criticality still shows and is kept", async ({ page }) => {
  await page.evaluate(() => {
    const risks = JSON.parse(localStorage.getItem("riskpilot.risks"));
    risks.find((r) => r.id === "R-004").assetCriticality = "3. Moderate";
    localStorage.setItem("riskpilot.risks", JSON.stringify(risks));
  });
  await page.reload();
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr", { hasText: "R-004" }).locator("button.row-name").click();
  const criticality = page.locator('#risk-form select[name="assetCriticality"]');
  expect(await criticality.evaluate((el) => [el.value, el.selectedOptions[0].textContent])).toEqual(["3. Moderate", "Medium"]);
  const texts = await page.locator("#risk-form option, #risk-filters option").allTextContents();
  expect(texts).toContain("Medium");
  expect(texts.join("|")).not.toMatch(/Moderate/);
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("riskpilot.risks")).find((r) => r.id === "R-004").assetCriticality)).toBe("3. Moderate");
});
