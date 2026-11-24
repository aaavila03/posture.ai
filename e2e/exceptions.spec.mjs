// Browser test for exception expiry dates: the Exceptions tab, its filter, the editor field and the Due soon reminders.
// The clock is fixed because the sample data has fixed dates.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.clock.install({ time: new Date("2026-11-24T12:00:00") });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

const row = (page, id) => page.locator("#exception-table tbody tr", { hasText: id });

test("exceptions: an Expires column shows expired and expiring exceptions, and it can be filtered", async ({ page }) => {
  await page.locator('.tab[data-view="exceptions"]').click();
  await expect(page.locator("#exception-table thead")).toContainText("Expires");

  // R-004 expired on Nov 10, R-006 expires in 16 days, R-005 is far away and gets no badge.
  await expect(row(page, "R-004")).toContainText("Nov 10, 2026");
  await expect(row(page, "R-004").locator(".badge.critical", { hasText: "Expired" })).toBeVisible();
  await expect(row(page, "R-006")).toContainText("Expires in 16 days");
  await expect(row(page, "R-005")).toContainText("Jun 30, 2027");
  await expect(row(page, "R-005")).not.toContainText("Expire");

  const filter = page.locator("#exception-expiry-filter");
  await filter.selectOption("expired");
  await expect(page.locator("#exception-table tbody tr")).toHaveCount(1);
  await expect(row(page, "R-004")).toBeVisible();
  await filter.selectOption("soon");
  await expect(page.locator("#exception-table tbody tr")).toHaveCount(1);
  await expect(row(page, "R-006")).toBeVisible();
  await filter.selectOption("");
  await expect(page.locator("#exception-table tbody tr")).toHaveCount(3);
});

test("exceptions: setting the expiry in the risk editor updates the tab, the filter and the reminders", async ({ page }) => {
  // The dashboard lists the expired exception on R-004's row, together with its other dates.
  await page.locator('.tab[data-view="dashboard"]').click();
  const reminder = page.locator("#due-soon li", { has: page.locator('a[data-edit="R-004"]') });
  await expect(reminder).toHaveCount(1);
  await expect(reminder).toContainText("Exception expired Nov 10, 2026");

  // Give R-004 a later expiry in the editor: the field is next to "Exception approved?".
  await reminder.locator("a").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  const field = page.locator('#risk-form input[name="exceptionExpiry"]');
  await expect(field).toHaveValue("2026-11-10");
  await field.fill("2027-09-30");
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("riskpilot.risks")).find((r) => r.id === "R-004").exceptionExpiry);
  expect(saved).toBe("2027-09-30");
  await page.locator("#btn-cancel").click();

  // It is no longer expired in the Exceptions tab, and the reminder no longer mentions the exception.
  await page.locator('.tab[data-view="exceptions"]').click();
  await expect(row(page, "R-004")).toContainText("Sep 30, 2027");
  await expect(row(page, "R-004")).not.toContainText("Expired");
  await page.locator("#exception-expiry-filter").selectOption("expired");
  await expect(page.locator("#exception-table tbody tr")).toHaveCount(0);
  await page.locator('.tab[data-view="dashboard"]').click();
  await expect(page.locator("#due-soon li", { has: page.locator('a[data-edit="R-004"]') })).not.toContainText("Exception");
});
