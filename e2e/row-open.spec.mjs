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

test("register: no Inherent risk column, full width or beside the open risk, and the residual level stays", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.locator('.tab[data-view="register"]').click();
  const headings = () => page.locator("#risk-table thead th:visible").allInnerTexts().then((t) => t.map((x) => x.trim().toLowerCase()));
  expect(await headings()).toEqual(["id", "risk", "category", "control", "owner", "residual risk", "stage", "due"]);
  // With a risk open beside the table, the narrow table keeps the residual level.
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await expect(page.locator("body")).toHaveClass(/risk-split/);
  // Up to 1600px the owner is left out too, so the due date stays in view.
  expect(await headings()).toEqual(["id", "risk", "residual risk", "due"]);
  expect(await page.locator("#risk-table tbody tr").first().locator("td:visible").count()).toBe(4);
  await page.setViewportSize({ width: 1728, height: 900 });
  expect(await headings()).toEqual(["id", "risk", "owner", "residual risk", "due"]);
});

test("register: opens sorted by residual risk, highest first", async ({ page }) => {
  await page.locator('.tab[data-view="register"]').click();
  // The ledger doesn't show the score, so each row's residual score is worked out from the saved risk.
  await expect(page.locator("#risk-table tbody tr").first()).toBeVisible();
  const ids = await page.locator("#risk-table tbody tr td:first-child").allInnerTexts();
  const scores = await page.evaluate((ids) => {
    const risks = JSON.parse(localStorage.getItem("riskpilot.risks"));
    return ids.map((id) => { const r = risks.find((x) => x.id === id.trim()); return Number(r.residualLikelihood || r.likelihood) * Number(r.residualImpact || r.impact); });
  }, ids);
  expect(scores.length).toBeGreaterThan(3);
  const numbers = scores.map(Number);
  expect(numbers).toEqual([...numbers].sort((a, b) => b - a));
  expect(new Set(numbers).size, "the sample has different scores, so the order means something").toBeGreaterThan(1);
});

for (const [view, table] of [["register", "#risk-table"], ["exceptions", "#exception-table"]]) {
  test(`${view}: the residual column shows the level only, with no score number`, async ({ page }) => {
  await page.locator(`.tab[data-view="${view}"]`).click();
  const cells = page.locator(`${table} tbody tr td:nth-child(6)`);
  await expect(cells.first()).toBeVisible();
  for (const text of await cells.evaluateAll((els) => els.map((el) => el.querySelector(".badge.level [aria-hidden]").textContent + "|" + el.textContent))) {
    const [label, all] = text.split("|");
    expect(label).toMatch(/^(LOW|MED|HIGH|CRITICAL)$/);
    expect(all.replace(/Outside appetite/, "")).not.toMatch(/\d/);
  }
});
}

test("register: the Stage column shows the state without its number, and still sorts in lifecycle order", async ({ page }) => {
  const stages = ["Identified", "Assessment", "In treatment", "Monitoring", "Accepted", "Closed"];
  await page.locator('.tab[data-view="register"]').click();
  const cells = page.locator("#risk-table tbody tr td:nth-child(7)");
  await expect(cells.first()).toBeVisible();
  for (const text of await cells.allInnerTexts()) expect(stages).toContain(text.trim());
  await page.locator('#risk-table th[data-sort="status"]').click();
  const positions = (await cells.allInnerTexts()).map((t) => stages.indexOf(t.trim()));
  expect(new Set(positions).size, "the sample has several stages").toBeGreaterThan(2);
  expect(positions).toEqual([...positions].sort((a, b) => a - b));
});
