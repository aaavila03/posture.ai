// Browser smoke test: opens the demo page and walks through each editor the way a person would.
// It checks that the screens work together (steps, Save, AI cards, PDF exports), which the unit tests can't see.
// The print dialog is stubbed, so an export is checked by the report it builds.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  // Fail on any uncaught error or console error from the app.
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.addInitScript(() => { window.__printed = 0; window.print = () => { window.__printed++; }; });
  await page.goto("/demo/");
  // Sample data gives every tab something to open.
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

const toast = (page) => page.locator("#toast");
const report = (page) => page.locator("#assessment-print .pr-doc");
const reportHeadings = async (page) => (await report(page).locator(":scope > .pr-section > h2").allTextContents()).map((t) => t.trim());
const footerOnOneRow = (page, form) => page.evaluate((sel) => {
  const tops = [...document.querySelectorAll(`${sel} .form-foot button`)].filter((b) => b.offsetParent).map((b) => Math.round(b.getBoundingClientRect().top));
  return new Set(tops).size === 1;
}, form);

test("every tab opens", async ({ page }) => {
  for (const view of ["dashboard", "vendors", "register", "exceptions", "assessments", "threats", "settings"]) {
    await page.locator(`.tab[data-view="${view}"]`).click();
    await expect(page.locator(`#view-${view}`)).toBeVisible();
  }
});

test("the demo has no workspace to delete, so the delete controls stay hidden", async ({ page }) => {
  await page.locator('.tab[data-view="settings"]').click();
  // Deleting a workspace is for owners in a hosted workspace; the demo only has Delete all data.
  await expect(page.locator("#btn-clear")).toBeVisible();
  await expect(page.locator("#ws-danger")).toBeHidden();
  await expect(page.locator("#btn-ws-delete")).toBeHidden();
  await expect(page.locator("#ws-delete-dialog")).not.toHaveAttribute("open", "");
});

test("vendor: three steps, AI review, Save keeps it open, PDF export", async ({ page }) => {
  await page.locator('.tab[data-view="vendors"]').click();
  await page.locator('#vendor-table button.vendor-name[data-vendor="V-002"]').click();
  const dialog = page.locator("#vendor-dialog");
  await expect(dialog).toHaveAttribute("open", "");

  // Steps: one section at a time, Back and Next at the ends, footer on one row.
  await expect(page.locator('[data-vstep-panel="0"]')).toBeVisible();
  await expect(page.locator("#btn-vendor-back")).toBeDisabled();
  await page.locator('#vendor-steps [data-vstep="1"]').click();
  await expect(page.locator('[data-vstep-panel="1"]')).toBeVisible();
  await page.locator("#btn-vendor-next").click();
  await expect(page.locator('[data-vstep-panel="2"]')).toBeVisible();
  await expect(page.locator("#btn-vendor-next")).toBeDisabled();
  expect(await footerOnOneRow(page, "#vendor-form")).toBe(true);

  // The AI review (the offline rules here) fills the final section; vendors don't go into the risk ledger.
  await expect(page.locator("#btn-vendor-to-risk")).toHaveCount(0);
  await page.locator("#btn-vendor-ai").click();
  const review = page.locator("#vendor-ai-panel .pr-review");
  await expect(review).toBeVisible();
  await expect(review.locator(".pr-callout")).toContainText(/Reject|Approve|Needs more/);
  await expect(review.locator("table tbody tr").first()).toBeVisible();

  // Save keeps the window open, on the same step, with the review still shown.
  await page.locator('#vendor-form button[type="submit"]').click();
  await expect(toast(page)).toHaveText("Vendor saved");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator('[data-vstep-panel="2"]')).toBeVisible();
  await expect(review).toBeVisible();

  // The PDF has the review, and every section after the summary starts a new page.
  await page.locator("#btn-vendor-pdf").click();
  expect(await page.evaluate(() => window.__printed)).toBe(1);
  expect(await reportHeadings(page)).toEqual(["Vendor summary", "Vendor review (rule-based)", "Security controls", "Notes and evidence"]);
  const breaks = await report(page).locator(":scope > .pr-section").evaluateAll((els) => els.map((e) => getComputedStyle(e).breakBefore));
  expect(breaks).toEqual(["auto", "page", "page", "page"]);
});

test("vendor: a blank name sends you back to the first step", async ({ page }) => {
  await page.locator('.tab[data-view="vendors"]').click();
  await page.locator("#btn-vendor-add").click();
  await page.locator('#vendor-steps [data-vstep="2"]').click();
  await page.locator('#vendor-form button[type="submit"]').click();
  await expect(page.locator('[data-vstep-panel="0"]')).toBeVisible();
  await expect(page.locator("#vendor-dialog")).toHaveAttribute("open", "");
});

test("risk: steps, AI assessment, treatment plan, Save keeps it open, PDF export", async ({ page }) => {
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr", { hasText: "R-004" }).locator("button, a").first().click();
  const dialog = page.locator("#risk-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator("#dialog-title")).toContainText("R-004");

  // Ownership lives in the first step.
  await expect(page.locator('[data-rstep-panel="0"] summary', { hasText: "Ownership" })).toBeVisible();
  await page.locator('#risk-steps [data-rstep="1"]').click();
  expect(await footerOnOneRow(page, "#risk-form")).toBe(true);

  // AI assess shows a PDF-style card; Apply to form fills the plan, and the card then leaves out what is applied.
  await page.locator("#btn-ai-assess").click();
  await expect(page.locator("#ai-panel .pr-review")).toBeVisible();
  await page.locator("#btn-apply-ai").click();
  await expect(page.locator("#ai-panel")).toContainText("already in the treatment plan");

  // The plan shows as a formatted preview with priority badges, and no raw bracket text.
  await page.locator('#risk-steps [data-rstep="2"]').click();
  const preview = page.locator("#risk-plan-preview");
  await expect(preview).toBeVisible();
  await expect(preview.locator("tbody tr").first()).toBeVisible();
  await expect(preview.locator(".pr-badge").first()).toBeVisible();
  await expect(preview).not.toContainText("[");

  // Clearing the plan hides the preview; the Add to plan row brings a formatted line back.
  await page.locator('#risk-form [name="controls"]').fill("");
  await expect(preview).toBeHidden();
  await page.locator("#plan-fn").selectOption("Detect");
  await page.locator("#plan-pri").selectOption("High");
  await page.locator("#plan-control").fill("Monitor VPN logins");
  await page.locator("#btn-plan-add").click();
  await expect(preview.locator("tbody tr")).toHaveCount(1);
  await expect(preview).toContainText("Monitor VPN logins");

  // Save keeps the window open and the assessment is saved with the risk.
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(toast(page)).toHaveText("Risk saved");
  await expect(dialog).toHaveAttribute("open", "");
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("riskpilot.risks")).find((r) => r.id === "R-004"));
  expect(saved.aiAssessment?.rationale).toBeTruthy();
  expect(saved.controls).toContain("[Detect/High] Monitor VPN logins");

  // The PDF has the assessment and the plan as a table, with no raw bracket text.
  await page.locator("#btn-risk-pdf").click();
  expect(await page.evaluate(() => window.__printed)).toBe(1);
  const headings = await reportHeadings(page);
  expect(headings).toEqual(expect.arrayContaining(["Risk summary", "Assessment", "Risk assessment (rule-based)", "Treatment", "Ownership"]));
  const treatment = report(page).locator("section", { has: page.locator("h2", { hasText: /^Treatment$/ }) });
  // The report is only there for printing, so it is checked by what it holds, not by what is visible.
  await expect(treatment.locator("h3", { hasText: "Treatment plan" })).toHaveCount(1);
  await expect(treatment.locator("table.pr-table:not(.pr-summary) tbody tr")).toHaveCount(1);
  expect(await treatment.textContent()).not.toContain("[Detect/High]");
});

test("snapshot: the AI review button needs a key, and Save closes the snapshot", async ({ page }) => {
  await page.locator('.tab[data-view="assessments"]').click();
  await page.locator("#view-assessments tbody tr", { hasText: "AI meeting notes" }).locator("button, a").first().click();
  const dialog = page.locator("#assessment-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await page.locator('#assessment-steps [data-snap-step="1"]').click();
  await expect(page.locator("#btn-snapshot-review")).toBeVisible();
  await expect(page.locator("#snapshot-ai-card")).toBeHidden();
  // Without an API key the review is refused with a clear message.
  await page.locator("#btn-snapshot-review").click();
  await expect(toast(page)).toContainText("API key");
  await page.locator('#assessment-form .snap-foot button[type="submit"]').click();
  await expect(toast(page)).toHaveText("Assessment saved");
  await expect(dialog).not.toHaveAttribute("open", "");
});

test("threat posture assessment: Save keeps it open and the PDF has the gaps", async ({ page }) => {
  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#view-threats tbody tr", { hasText: "Claude Enterprise" }).locator("button, a").first().click();
  const dialog = page.locator("#tra-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  expect(await footerOnOneRow(page, "#tra-form")).toBe(true);

  // Edit the summary notes on the last step and save: the window stays open on that step.
  await page.locator("#tra-steps button").nth(4).click();
  await page.locator('#tra-body [data-path="summaryNotes"]').fill("Checked by the smoke test");
  await page.locator('#tra-form button[type="submit"]').click();
  await expect(toast(page)).toHaveText("Assessment saved");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator('#tra-body [data-path="summaryNotes"]')).toHaveValue("Checked by the smoke test");

  // The PDF has the report sections, including a row for every control gap.
  await page.locator("#btn-tra-pdf").click();
  expect(await page.evaluate(() => window.__printed)).toBe(1);
  const headings = await reportHeadings(page);
  expect(headings).toEqual(expect.arrayContaining(["Assessment summary", "Business impact", "Asset profile", "Risk summary", "Control gaps", "Summary notes"]));
  const gaps = report(page).locator("section", { has: page.locator("h2", { hasText: /^Control gaps$/ }) });
  await expect(gaps.locator("tbody tr")).toHaveCount(14);
});
