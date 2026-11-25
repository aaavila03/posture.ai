// Browser test: level labels read V.LOW, LOW, MED, HIGH, V.HIGH or CRIT on screen, with the full word on hover.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

for (const [view, table] of [["register", "#risk-table"], ["exceptions", "#exception-table"], ["vendors", "#vendor-table"], ["assessments", "#assessment-table"], ["threats", "#tra-table"]]) {
  test(`${view}: levels read like MED, with the full word on hover`, async ({ page }) => {
    await page.locator(`.tab[data-view="${view}"]`).click();
    const labels = page.locator(`${table} tbody .badge.level`);
    await expect(labels.first()).toBeVisible();
    for (const text of await labels.locator('[aria-hidden="true"]').allTextContents()) expect(text).toMatch(/^(V\.LOW|LOW|MED|HIGH|V\.HIGH|CRIT)$/);
    const first = labels.first();
    const full = await first.getAttribute("data-tip");
    expect(full).toMatch(/^(Very Low|Low|Medium|Moderate|High|Very High|Critical)$/);
    await first.hover();
    await expect(page.locator("#tooltip")).toHaveText(full);
    // The full word is there for screen readers but takes no room.
    expect((await first.locator(".sr-only").boundingBox()).width).toBeLessThanOrEqual(1);
  });
}

test("the threat summary and the risk editor use the same names", async ({ page }) => {
  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#tra-table tbody tr").first().locator("button.row-name").click();
  await page.locator("#tra-steps button").nth(4).click();
  const names = await page.locator('#tra-body .tra-count .badge.level [aria-hidden="true"]').allTextContents();
  expect(names.slice(0, 5)).toEqual(["V.HIGH", "HIGH", "MED", "LOW", "V.LOW"]);
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="1"]').click();
  await expect(page.locator('#risk-score .badge.level [aria-hidden="true"]').first()).toHaveText(/^(LOW|MED|HIGH|CRIT)$/);
});
