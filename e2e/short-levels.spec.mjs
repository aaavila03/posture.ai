// Browser test: level labels read LOW, MED, HIGH or CRIT on screen, with the full word on hover.
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
    const labels = page.locator(`${table} tbody ${view === "exceptions" ? ".level-score " : ""}.badge.level`);
    await expect(labels.first()).toBeVisible();
    for (const text of await labels.locator('[aria-hidden="true"]').allTextContents()) expect(text).toMatch(/^(LOW|MED|HIGH|CRIT)$/);
    const first = labels.first();
    const full = await first.getAttribute("data-tip");
    expect(full).toMatch(/^(Low|Medium|High|Critical)$/);
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
  expect(names).toEqual(["CRIT", "HIGH", "MED", "LOW", "CRIT", "HIGH", "MED", "LOW"]);
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="1"]').click();
  await expect(page.locator('#risk-score .badge.level [aria-hidden="true"]').first()).toHaveText(/^(LOW|MED|HIGH|CRIT)$/);
});

// The top level is Critical on every screen, even where snapshots and assessments store it as Very High.
test("no screen says Very High, Very Low or Moderate, in labels, filters or the editors", async ({ page }) => {
  const clean = async (selector) => expect(await page.locator(selector).first().innerText()).not.toMatch(/Very High|V\.HIGH|Very Low|V\.LOW/);
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
  const choices = await page.locator("#assessment-dialog select option").allTextContents();
  expect(choices).not.toContain("Very High");
  expect(choices).not.toContain("Very Low");
  expect(await page.locator("#assessment-dialog").innerText()).not.toMatch(/Very High|V\.HIGH|Very Low|V\.LOW/);
  await page.locator('#assessment-dialog .close-x').first().click();
  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#tra-table tbody tr").first().locator("button.row-name").click();
  for (let i = 0; i < 5; i++) {
    await page.locator("#tra-steps button").nth(i).click();
    expect(await page.locator("#tra-dialog").innerText()).not.toMatch(/Very High|V\.HIGH|Very Low|V\.LOW/);
  }
});

// A snapshot saved with Very Low reads Low, keeps its stored value, and is found by the Low filter.
test("a record saved as Very Low reads Low and is not changed by opening and saving it", async ({ page }) => {
  await page.evaluate(() => {
    const list = JSON.parse(localStorage.getItem("riskpilot.assessments"));
    list[0].inherentRisk = "Very Low";
    localStorage.setItem("riskpilot.assessments", JSON.stringify(list));
  });
  await page.reload();
  const id = await page.evaluate(() => JSON.parse(localStorage.getItem("riskpilot.assessments"))[0].id);
  await page.locator('.tab[data-view="assessments"]').click();
  await page.locator("#assessment-level-filter").selectOption({ label: "Low" });
  const row = page.locator("#assessment-table tbody tr", { hasText: id });
  await expect(row.locator('.badge.level [aria-hidden="true"]')).toHaveText("LOW");
  await row.locator("button.row-name").click();
  const select = page.locator('#assessment-dialog select[data-path="inherentRisk"]');
  expect(await select.evaluate((el) => [el.value, el.selectedOptions[0].textContent])).toEqual(["Very Low", "Low"]);
  expect((await select.locator("option").allTextContents()).filter((t) => t === "Low")).toHaveLength(1);
  await page.locator('#assessment-form .snap-foot button[type="submit"]').click();
  expect(await page.evaluate((wanted) => JSON.parse(localStorage.getItem("riskpilot.assessments")).find((a) => a.id === wanted).inherentRisk, id)).toBe("Very Low");
});

test("threat assessments call the middle level Medium, in the filter, the summary and the scoring note", async ({ page }) => {
  await page.locator('.tab[data-view="threats"]').click();
  expect(await page.locator("#tra-rating-filter option").allTextContents()).toEqual(["All impact ratings", "Critical", "High", "Medium", "Low"]);
  await page.locator("#tra-rating-filter").selectOption({ label: "Medium" });
  await expect(page.locator("#tra-table tbody tr").first()).toBeVisible();
  await page.locator("#tra-table tbody tr").first().locator("button.row-name").click();
  await page.locator("#tra-steps button").nth(3).click();
  await expect(page.locator("#tra-body")).toContainText("Medium 16–49");
  for (const i of [3, 4]) {
    await page.locator("#tra-steps button").nth(i).click();
    const tips = await page.locator("#tra-body .badge.level").evaluateAll((els) => els.map((el) => el.dataset.tip));
    expect(tips).toContain("Medium");
    expect(tips).not.toContain("Moderate");
  }
  await expect(page.locator("#tra-steps")).not.toContainText("Moderate");
});

test("the exception column shows short statuses at the level label size, and the filter uses the same words", async ({ page }) => {
  await page.locator('.tab[data-view="exceptions"]').click();
  await expect(page.locator("#exception-table thead th").nth(3)).toHaveText("Exception");
  const labels = page.locator("#exception-table tbody tr td:nth-child(4) .badge");
  const codes = await labels.locator('[aria-hidden="true"]').allTextContents();
  expect(codes.length).toBe(await page.locator("#exception-table tbody tr").count());
  for (const code of codes) expect(code).toMatch(/^(PEND|APPR|REJ|NONE)$/);
  expect([...new Set(await labels.evaluateAll((els) => els.map((el) => Math.round(el.getBoundingClientRect().width))))]).toEqual([68]);
  expect(await page.locator("#exception-approved-filter option").allTextContents()).toEqual(["All statuses", "Approved", "Rejected", "None", "Pending"]);
  await page.locator("#exception-approved-filter").selectOption({ label: "Rejected" });
  await expect(labels.first().locator('[aria-hidden="true"]')).toHaveText("REJ");
});

test("the expiry labels are the same small size and fit even in a wide font", async ({ page }) => {
  await page.locator('.tab[data-view="exceptions"]').click();
  const labels = page.locator("#exception-table tbody tr td:nth-child(5) .badge");
  await expect(labels.first()).toBeVisible();
  for (const code of await labels.locator('[aria-hidden="true"]').allTextContents()) expect(code).toMatch(/^(EXPIRED|TODAY|\d+ DAYS?)$/);
  expect([...new Set(await labels.evaluateAll((els) => els.map((el) => Math.round(el.getBoundingClientRect().width))))]).toEqual([68]);
  const cut = await page.evaluate(() => ["EXPIRED", "TODAY", "30 DAYS", "APPR", "NONE"].filter((text) => {
    const el = document.createElement("span"); el.className = "badge level high"; el.style.fontFamily = "Verdana, DejaVu Sans"; el.textContent = text;
    document.body.append(el); const over = el.scrollWidth > el.clientWidth; el.remove(); return over;
  }));
  expect(cut).toEqual([]);
});
