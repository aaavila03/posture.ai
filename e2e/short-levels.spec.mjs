// Browser test: level labels read V.LOW, LOW, MED, HIGH or CRIT on screen, with the full word on hover.
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
    for (const text of await labels.locator('[aria-hidden="true"]').allTextContents()) expect(text).toMatch(/^(V\.LOW|LOW|MED|HIGH|CRIT)$/);
    const first = labels.first();
    const full = await first.getAttribute("data-tip");
    expect(full).toMatch(/^(Very Low|Low|Medium|Moderate|High|Critical)$/);
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
  expect(names.slice(0, 5)).toEqual(["CRIT", "HIGH", "MED", "LOW", "V.LOW"]);
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="1"]').click();
  await expect(page.locator('#risk-score .badge.level [aria-hidden="true"]').first()).toHaveText(/^(LOW|MED|HIGH|CRIT)$/);
});

// The top level is Critical on every screen, even where snapshots and assessments store it as Very High.
test("no screen says Very High or V.HIGH, in labels, filters or the snapshot editor", async ({ page }) => {
  const clean = async (selector) => expect(await page.locator(selector).first().innerText()).not.toMatch(/Very High|V\.HIGH/);
  for (const view of ["dashboard", "register", "vendors", "exceptions", "assessments", "threats"]) {
    await page.locator(`.tab[data-view="${view}"]`).click();
    await clean(".view.active");
  }
  await page.locator('.tab[data-view="assessments"]').click();
  await expect(page.locator("#assessment-level-filter option", { hasText: "Critical" })).toHaveCount(1);
  // Choosing Critical in the filter still finds the snapshots stored as Very High.
  await page.locator("#assessment-level-filter").selectOption({ label: "Critical" });
  await expect(page.locator("#assessment-table tbody tr").first()).toBeVisible();
  await expect(page.locator('#assessment-table tbody .badge.level [aria-hidden="true"]').first()).toHaveText("CRIT");
  await page.locator("#assessment-table tbody tr").first().locator("button.row-name").click();
  expect(await page.locator("#assessment-dialog select option").allTextContents()).not.toContain("Very High");
  expect(await page.locator("#assessment-dialog").innerText()).not.toMatch(/Very High|V\.HIGH/);
  await page.locator('#assessment-dialog .close-x').first().click();
  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#tra-table tbody tr").first().locator("button.row-name").click();
  for (let i = 0; i < 5; i++) {
    await page.locator("#tra-steps button").nth(i).click();
    expect(await page.locator("#tra-dialog").innerText()).not.toMatch(/Very High|V\.HIGH/);
  }
});
