// Browser test: the record tables show dates like "Jan 1, 2027", never as 2027-01-01.
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
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

for (const [view, table] of [["register", "#risk-table"], ["vendors", "#vendor-table"], ["exceptions", "#exception-table"], ["assessments", "#assessment-table"], ["threats", "#tra-table"]]) {
  test(`${view}: dates read like Jan 1, 2027`, async ({ page }) => {
    await page.locator(`.tab[data-view="${view}"]`).click();
    await expect(page.locator(`${table} tbody tr`).first()).toBeVisible();
    const text = await page.locator(`${table} tbody`).innerText();
    expect(text).toMatch(/\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{1,2}, \d{4}\b/);
    expect(text, "no stored-style dates left").not.toMatch(/\d{4}-\d{2}-\d{2}/);
  });
}
