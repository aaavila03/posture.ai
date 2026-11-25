// Browser test for risk appetite: the Settings limits, and where being outside appetite shows up.
// Sample data sets an appetite of Medium (High for Third-Party/Supply Chain). Its residual levels: R-001, R-002, R-004 and
// R-005 are Medium, the rest Low. The clock is fixed because the sample data has fixed dates.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.clock.install({ time: new Date("2026-11-24T12:00:00") });
  // The print dialog is stubbed before the page loads, so an export is checked by the report it builds.
  await page.addInitScript(() => { window.print = () => {}; });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

// Sets the limits in Settings and saves: the default, and optionally a limit for a category.
async function setAppetite(page, level, categories = {}) {
  await page.locator('.tab[data-view="settings"]').click();
  await page.locator("#appetite-default").selectOption(level);
  for (const [category, limit] of Object.entries(categories)) {
    await page.locator(`[data-appetite-category="${category}"]`).selectOption(limit);
  }
  await page.locator("#btn-appetite-save").click();
  await expect(page.locator("#toast")).toHaveText(level ? "Risk appetite saved" : "Risk appetite cleared");
}

const registerRow = (page, id) => page.locator("#risk-table tbody tr", { hasText: id });
const badges = (page) => page.locator("#risk-table tbody .badge", { hasText: "Outside appetite" });

test("appetite: the sample limits are shown, and nothing is outside a Medium limit", async ({ page }) => {
  await page.locator('.tab[data-view="settings"]').click();
  await expect(page.locator("#appetite-default")).toHaveValue("Medium");
  await expect(page.locator('[data-appetite-category="Third-Party/Supply Chain"]')).toHaveValue("High");
  await expect(page.locator('[data-appetite-category="Data Breach"]')).toHaveValue("");

  await page.locator('.tab[data-view="register"]').click();
  await expect(registerRow(page, "R-001")).toBeVisible();
  await expect(badges(page)).toHaveCount(0);
  await page.locator('.tab[data-view="dashboard"]').click();
  await expect(page.locator('[data-kpi="outsideAppetite"] .kpi-val')).toHaveText("0");
});

test("appetite: a stricter limit flags risks in the register, the editor, the dashboard and the filter", async ({ page }) => {
  await setAppetite(page, "Low");

  // Register: R-001, R-002 and R-004 are Medium, above a Low limit. R-005 is Medium too, but third parties are allowed High.
  await page.locator('.tab[data-view="register"]').click();
  await expect(badges(page)).toHaveCount(3);
  for (const id of ["R-001", "R-002", "R-004"]) await expect(registerRow(page, id).locator(".badge", { hasText: "Outside appetite" })).toBeVisible();
  await expect(registerRow(page, "R-005").locator(".badge", { hasText: "Outside appetite" })).toHaveCount(0);
  await expect(registerRow(page, "R-004").locator(".badge[data-tip]:not(.level)")).toHaveAttribute("data-tip", "Outside appetite: residual Medium is above the Low limit for Vulnerability/Patching.");

  // The filter, once an appetite is set.
  await page.locator("#btn-filters").click();
  const filter = page.locator('[data-rf="appetite"]');
  await expect(filter).toBeVisible();
  await filter.selectOption("Outside appetite");
  await expect(page.locator("#risk-table tbody tr")).toHaveCount(3);
  await filter.selectOption("Within appetite");
  await expect(page.locator("#risk-table tbody tr")).toHaveCount(5);
  await filter.selectOption("");

  // The risk editor says where the risk stands, under the scores.
  await registerRow(page, "R-004").locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="1"]').click();
  // The badge says "Outside appetite", so the sentence beside it only gives the reason and does not say it again.
  const note = page.locator("#risk-appetite");
  await expect(note.locator(".badge")).toHaveText("Outside appetite");
  await expect(note).toContainText("residual Medium is above the Low limit for Vulnerability/Patching.");
  expect(await note.innerText()).not.toMatch(/appetite.*appetite/is);
  await page.locator("#btn-cancel").click();

  // The dashboard tile counts them and opens the filtered register.
  await page.locator('.tab[data-view="dashboard"]').click();
  await expect(page.locator('[data-kpi="outsideAppetite"] .kpi-val')).toHaveText("3");
  await expect(page.locator("#top-risks .badge", { hasText: "Outside appetite" }).first()).toBeVisible();
  await page.locator('[data-kpi="outsideAppetite"]').click();
  await expect(page.locator(".tab.active")).toHaveAttribute("data-view", "register");
  await expect(page.locator("#risk-table tbody tr")).toHaveCount(3);
});

test("appetite: a category can have its own limit, and clearing the appetite removes every flag", async ({ page }) => {
  // Vulnerability/Patching may go up to Critical, so R-004 is inside appetite again.
  await setAppetite(page, "Low", { "Vulnerability/Patching": "Critical" });
  await page.locator('.tab[data-view="register"]').click();
  await expect(badges(page)).toHaveCount(2);
  await expect(registerRow(page, "R-004").locator(".badge", { hasText: "Outside appetite" })).toHaveCount(0);

  // With no appetite nothing is flagged: no badges, no tile, no filter.
  await setAppetite(page, "");
  await expect(page.locator("#appetite-categories")).toBeHidden();
  await page.locator('.tab[data-view="register"]').click();
  await expect(badges(page)).toHaveCount(0);
  await page.locator("#btn-filters").click();
  await expect(page.locator('[data-rf="appetite"]')).toBeHidden();
  await page.locator('.tab[data-view="dashboard"]').click();
  await expect(page.locator('[data-kpi="outsideAppetite"]')).toHaveCount(0);
});

test("appetite: a risk outside appetite with no treatment date and no exception is listed as needing attention", async ({ page }) => {
  await setAppetite(page, "Low");
  await page.locator('.tab[data-view="dashboard"]').click();
  // Every outside risk has a treatment date or an exception at first, so nothing needs attention.
  await expect(page.locator('#due-soon [data-due="attention"]')).toHaveCount(0);

  // While R-001 has a review date coming up, being outside appetite is added to its row there, not listed twice.
  await page.locator('#due-soon a[data-edit="R-001"]').click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await page.locator('#risk-form input[name="due"]').fill("");
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  await page.locator("#btn-cancel").click();
  await page.locator('.tab[data-view="dashboard"]').click();
  const shared = page.locator("#due-soon li", { has: page.locator('a[data-edit="R-001"]') });
  await expect(shared).toHaveCount(1);
  await expect(shared).toContainText("Review due");
  await expect(shared).toContainText("Outside appetite, with no treatment date or exception");
  await expect(page.locator('#due-soon [data-due="attention"]')).toHaveCount(0);

  // With no dates at all, it moves to Needs attention.
  await shared.locator("a").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await page.locator('#risk-form input[name="nextReview"]').fill("");
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  await page.locator("#btn-cancel").click();

  await page.locator('.tab[data-view="dashboard"]').click();
  const group = page.locator('#due-soon [data-due="attention"]');
  await expect(group.locator("h3")).toContainText("Needs attention");
  await expect(group.locator("li", { has: page.locator('a[data-edit="R-001"]') })).toContainText("Outside appetite, with no treatment date or exception");
});

test("appetite: the risk PDF and the CSV say where each risk stands", async ({ page }) => {
  await setAppetite(page, "Low");

  // The PDF has a Risk appetite row in the summary.
  await page.locator('.tab[data-view="register"]').click();
  await registerRow(page, "R-004").locator("button.row-name").click();
  await page.locator("#btn-risk-pdf").click();
  const facts = page.locator("#assessment-print .pr-summary tbody tr", { hasText: "Risk appetite" });
  await expect(facts).toHaveCount(1);
  expect(await facts.textContent()).toMatch(/Outside appetite\s*Limit: Low/);
  await page.locator("#btn-cancel").click();

  // The CSV has the two columns, worked out for each risk.
  const [download] = await Promise.all([page.waitForEvent("download"), page.locator("#btn-export-csv").click()]);
  const text = await (await import("node:fs/promises")).readFile(await download.path(), "utf8");
  const [header, ...lines] = text.trim().split("\n");
  const cols = header.split(",").map((c) => c.replace(/^"|"$/g, ""));
  expect(cols).toEqual(expect.arrayContaining(["appetiteLimit", "outsideAppetite"]));
  const line = lines.find((l) => l.startsWith('"R-004"') || l.startsWith("R-004"));
  expect(line).toBeTruthy();
  const cell = (name) => line.split('","')[cols.indexOf(name)].replace(/^"|"$/g, "");
  expect(cell("appetiteLimit")).toBe("Low");
  expect(cell("outsideAppetite")).toBe("Yes");
});

test("appetite: the AI assess button has room below the appetite line in the risk editor", async ({ page }) => {
  await page.locator('.tab[data-view="register"]').click();
  await registerRow(page, "R-004").locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="1"]').click();
  await expect(page.locator("#risk-appetite")).toContainText("appetite");
  const gap = await page.evaluate(() => document.querySelector("#btn-ai-assess").getBoundingClientRect().top - document.querySelector("#risk-appetite").getBoundingClientRect().bottom);
  expect(gap, "space between the appetite line and the AI assess button").toBeGreaterThanOrEqual(12);
});
