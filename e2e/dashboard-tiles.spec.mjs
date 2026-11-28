// Browser test: the dashboard counts residual risk, and each tile's and heat map cell's number matches the list it opens.
import { test, expect } from "@playwright/test";

test("every tile's number matches its click-through, and Critical and High are residual", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
  // A risk of each kind that inherent and residual counting would treat differently.
  await page.evaluate(() => {
    const risks = JSON.parse(localStorage.getItem("riskpilot.risks"));
    const set = (i, l, im, rl, ri) => Object.assign(risks[i], { likelihood: l, impact: im, residualLikelihood: rl, residualImpact: ri, status: "In treatment" });
    set(0, 5, 5, 5, 5); // Critical before and after
    set(1, 5, 5, 3, 4); // Critical before, High after
    set(2, 5, 4, 1, 4); // Critical before, Low after
    localStorage.setItem("riskpilot.risks", JSON.stringify(risks));
  });
  await page.reload();
  const dashboard = () => page.locator('.tab[data-view="dashboard"]').click();
  await dashboard();
  await expect(page.locator('[data-kpi="avgInherent"]')).toHaveCount(0);

  for (const [key, label] of [["critical", "CRITICAL"], ["high", "HIGH"]]) {
    const count = Number(await page.locator(`[data-kpi="${key}"] .kpi-val`).innerText());
    expect(count, key).toBeGreaterThan(0);
    await page.locator(`[data-kpi="${key}"]`).click();
    await expect(page.locator("#risk-table tbody tr")).toHaveCount(count);
    // The level column shows the same level the tile counted.
    expect(await page.locator("#risk-table tbody td:nth-child(6) .badge.level [aria-hidden]").allInnerTexts()).toEqual(Array(count).fill(label));
    await dashboard();
  }

  for (const [key, table] of [["active", "#risk-table"], ["overdue", "#risk-table"], ["riskyVendors", "#vendor-table"], ["vendorsDue", "#vendor-table"]]) {
    const count = Number(await page.locator(`[data-kpi="${key}"] .kpi-val`).innerText());
    await page.locator(`[data-kpi="${key}"]`).click();
    // An empty list has one row saying so, without a name to open.
    await expect(page.locator(`${table} tbody tr`).filter({ has: page.locator("button.row-name, button.vendor-name") }), key).toHaveCount(count);
    await dashboard();
  }
  // The heat map places each risk by its residual likelihood and impact, and a cell lists exactly its risks.
  const cells = await page.locator("#heatmap .cell").evaluateAll((els) => els.filter((el) => el.textContent).map((el) => [el.dataset.l, el.dataset.i, Number(el.textContent)]));
  expect(cells.reduce((sum, [, , n]) => sum + n, 0)).toBe(Number(await page.locator('[data-kpi="active"] .kpi-val').innerText()));
  expect(cells.filter(([l, i]) => l === "5" && i === "5")).toEqual([["5", "5", 1]]);
  for (const [l, i, count] of cells) {
    await page.locator(`#heatmap .cell[data-l="${l}"][data-i="${i}"]`).click();
    await expect(page.locator("#risk-table tbody tr"), `cell ${l}x${i}`).toHaveCount(count);
    await dashboard();
  }

  // Top risks are ranked and numbered by residual score.
  const scores = (await page.locator("#top-risks .badge.level").allInnerTexts()).map(Number);
  expect(scores[0]).toBe(25);
  expect(scores).toEqual([...scores].sort((a, b) => b - a));
  expect(errors, "no errors on the page").toEqual([]);
});
