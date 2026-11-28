// Browser test: leaving a tab clears its search, filters and dashboard-tile filter.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors on the page").toEqual([]);
});

const open = (page, view) => page.locator(`.tab[data-view="${view}"]`).click();
const rows = (page, table) => page.locator(`${table} tbody tr`);

test("a tile's filter is gone after leaving the tab", async ({ page }) => {
  for (const [tile, view, table, pill] of [["overdue", "register", "#risk-table", "#cell-filter"], ["riskyVendors", "vendors", "#vendor-table", "#vendor-quick-filter"]]) {
    await open(page, view);
    const all = await rows(page, table).count();
    await open(page, "dashboard");
    await page.locator(`[data-kpi="${tile}"]`).click();
    await expect(page.locator(pill)).toBeVisible();
    expect(await rows(page, table).count()).toBeLessThan(all);
    await open(page, "dashboard");
    await open(page, view);
    await expect(page.locator(pill)).toBeHidden();
    await expect(rows(page, table)).toHaveCount(all);
  }
  // A heat map cell is the same.
  await open(page, "dashboard");
  await page.locator("#heatmap .cell").filter({ hasText: /\d/ }).first().click();
  await expect(page.locator("#cell-filter")).toBeVisible();
  await open(page, "vendors");
  await open(page, "register");
  await expect(page.locator("#cell-filter")).toBeHidden();
});

test("searches and drop-downs are cleared on every list tab", async ({ page }) => {
  for (const [view, table, search, select] of [["register", "#risk-table", "#search", "#filter-status"], ["vendors", "#vendor-table", "#vendor-search", "#vendor-filter-tier"],
    ["exceptions", "#exception-table", "#exception-search", "#exception-approved-filter"], ["assessments", "#assessment-table", "#assessment-search", "#assessment-status-filter"],
    ["threats", "#tra-table", "#tra-search", "#tra-status-filter"]]) {
    await open(page, view);
    const all = await rows(page, table).count();
    await page.locator(select).selectOption({ index: 1 });
    await page.locator(search).fill("nothing matches this");
    await open(page, "dashboard");
    await open(page, view);
    await expect(page.locator(search), view).toHaveValue("");
    await expect(page.locator(select), view).toHaveValue("");
    await expect(rows(page, table), view).toHaveCount(all);
  }
  // Opening a record stays on the tab, so its filters stay too.
  await open(page, "register");
  await page.locator("#search").fill("VPN");
  await page.locator("#risk-table button.row-name").first().click();
  await expect(page.locator("#search")).toHaveValue("VPN");
});
