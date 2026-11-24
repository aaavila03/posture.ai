// Browser test for the Risk Ledger, Vendors, Exceptions, Posture Snapshots and Threat Posture Assessments tables: there is no Edit button, and a record opens from its name.
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

for (const [view, table, name, dialog] of [["register", "#risk-table", "button.row-name", "#risk-dialog"], ["vendors", "#vendor-table", "button.vendor-name", "#vendor-dialog"], ["exceptions", "#exception-table", "button.row-name", "#risk-dialog"],
  ["assessments", "#assessment-table", "button.row-name", "#assessment-dialog"], ["threats", "#tra-table", "button.row-name", "#tra-dialog"]]) {
  test(`${view}: no Edit button, as many cells as headings, and the name opens the record`, async ({ page }) => {
    await page.locator(`.tab[data-view="${view}"]`).click();
    const row = page.locator(`${table} tbody tr`).first();
    await expect(row).toBeVisible();
    await expect(page.locator(`${table} tbody`).getByRole("button", { name: /^(Edit|View)$/ })).toHaveCount(0);
    expect(await row.locator("td").count()).toBe(await page.locator(`${table} thead th`).count());
    await row.locator(name).click();
    await expect(page.locator(dialog)).toHaveAttribute("open", "");
  });
}
