// Browser smoke test for the dashboard's "Due soon" reminders. It starts from an empty demo page, so it has its own setup.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  // The sample data has fixed dates, so the browser's clock is fixed too and the result is the same every day.
  await page.clock.install({ time: new Date("2026-11-24T12:00:00") });
  await page.goto("/demo/");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

test("reminders: empty at first, then overdue and due-soon rows that open the record", async ({ page }) => {
  const card = page.locator("#due-soon");
  const badge = page.locator("#dashboard-tab-count");

  // Nothing is due in an empty workspace.
  await expect(card).toContainText("Nothing is due in the next 30 days");
  await expect(badge).toHaveText("");

  // Sample data has overdue treatments and reviews, plus vendors that were never assessed.
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
  await page.locator('.tab[data-view="dashboard"]').click();
  await expect(card.locator('.due-group[data-due="overdue"]')).toBeVisible();
  await expect(card.locator('.due-group[data-due="overdue"] h3')).toContainText("Overdue");
  await expect(card).toContainText("overdue");
  await expect(card).toContainText("No review on record");
  await expect(badge).not.toHaveText("");

  // The links are as readable as the Top risks links, not the browser's default dark blue on the dark page.
  const colour = (selector) => page.locator(selector).first().evaluate((el) => getComputedStyle(el).color);
  expect(await colour("#due-soon li a")).toBe(await colour("#top-risks li a"));

  // One row per record: a risk with both a treatment date and a review date is not listed twice.
  const ids = await card.locator("li a").evaluateAll((links) => links.map((a) => a.textContent.split(" · ")[0]));
  expect(new Set(ids).size).toBe(ids.length);
  const r004 = card.locator("li", { has: page.locator('a[data-edit="R-004"]') });
  await expect(r004).toHaveCount(1);
  await expect(r004).toContainText("Treatment due");
  await expect(r004).toContainText("Review due");

  // A risk link opens the risk in the Risk Ledger.
  await r004.locator("a").click();
  await expect(page.locator(".tab.active")).toHaveAttribute("data-view", "register");
  await expect(page.locator("#risk-dialog")).toHaveAttribute("open", "");
  await expect(page.locator("#dialog-title")).toContainText("R-004");
  await page.locator("#btn-cancel").click();

  // A vendor link opens the vendor in the Vendors tab.
  await page.locator('.tab[data-view="dashboard"]').click();
  await card.locator('a[data-open-vendor="V-002"]').click();
  await expect(page.locator(".tab.active")).toHaveAttribute("data-view", "vendors");
  await expect(page.locator("#vendor-dialog")).toHaveAttribute("open", "");
  await expect(page.locator("#vendor-dialog-title")).toContainText("V-002");
});

test("reminders: closing a risk takes it off the list", async ({ page }) => {
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
  await page.locator('.tab[data-view="dashboard"]').click();
  const row = page.locator('#due-soon a[data-edit="R-003"]');
  await expect(row).toHaveCount(1);

  // Set the risk's stage to Closed and save: it no longer needs a reminder.
  await row.click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await page.locator('#risk-form details summary', { hasText: "Workflow" }).click();
  await page.locator('#risk-form select[name="status"]').selectOption("Closed");
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  await page.locator("#btn-cancel").click();
  await page.locator('.tab[data-view="dashboard"]').click();
  await expect(page.locator('#due-soon a[data-edit="R-003"]')).toHaveCount(0);
});
