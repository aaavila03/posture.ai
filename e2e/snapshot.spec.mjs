// Browser test for the Posture Snapshot: Save keeps it open like the other editors, and the saved AI review is in the PDF.
// The AI call is replaced with a canned result and a dummy key is set only to get past the key check; nothing is sent anywhere.
import { test, expect } from "@playwright/test";

const REVIEW = {
  summary: "Two recommendations need stronger responses and one new gap was found around audit logging.",
  rows: [{ id: "R1", domain: "Data protection", recommendation: "", inherent: "Very High", strategy: "Mitigate", residual: "Medium", treatment: "" }],
  new_rows: [{ domain: "Logging", recommendation: "Turn on audit logging for administrator actions", inherent: "High", strategy: "Mitigate", residual: "Low", treatment: "Enable in the admin console." }],
  solution_risk_level: "High", scope: "Replace the built-in extractor.", software_functionality: "Opens archives.", summary_notes: "Acceptable with conditions.",
  executive_summary: { outcome: "No objection with conditions", ot_impact: "No", additional_compliance: "No", top_risks: "Crafted archives", top_recommendations: "Enforce updates" },
};

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.addInitScript(() => { window.print = () => {}; sessionStorage.setItem("riskpilot.apiKey", "test-stub-key"); });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
  // Replace the AI call: the review comes back as a fixed result.
  await page.evaluate(async (review) => {
    const { LocalAI } = await import("/ai.js");
    LocalAI.prototype.reviewSnapshot = async () => review;
  }, REVIEW);
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

const saveButton = (page) => page.locator('#assessment-form .snap-foot button[type="submit"]');
const stored = (page) => page.evaluate(() => JSON.parse(localStorage.getItem("riskpilot.assessments")));

test("snapshot: saving a new snapshot keeps it open, gives it an ID and does not add a copy on the next save", async ({ page }) => {
  await page.locator('.tab[data-view="assessments"]').click();
  const before = (await stored(page)).length;
  await page.locator("#btn-assessment-add").click();
  const dialog = page.locator("#assessment-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator("#btn-assessment-delete")).toBeHidden();

  await page.locator('#assessment-body [data-path="solution"]').first().fill("Stay-open check");
  await saveButton(page).click();
  await expect(page.locator("#toast")).toHaveText("Assessment saved");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator("#assessment-title")).toContainText("Stay-open check");
  await expect(page.locator("#assessment-title")).toContainText(/A-\d{3}/);
  await expect(page.locator("#btn-assessment-delete")).toBeVisible();
  expect(await stored(page)).toHaveLength(before + 1);

  // A second save updates the same snapshot.
  await saveButton(page).click();
  expect(await stored(page)).toHaveLength(before + 1);

  // Cancel closes it without a prompt, since everything is saved.
  await page.locator("#btn-assessment-cancel").click();
  await expect(dialog).not.toHaveAttribute("open", "");
});

test("snapshot: a blank request name is refused and Save leaves the snapshot open", async ({ page }) => {
  await page.locator('.tab[data-view="assessments"]').click();
  await page.locator("#btn-assessment-add").click();
  await saveButton(page).click();
  await expect(page.locator("#toast")).toContainText("Add the request name first");
  await expect(page.locator("#assessment-dialog")).toHaveAttribute("open", "");
});

test("snapshot: the saved AI review comes back on reopening and its summary is in the PDF once", async ({ page }) => {
  await page.locator('.tab[data-view="assessments"]').click();
  await page.locator("#view-assessments tbody tr", { hasText: "AI meeting notes" }).locator("button, a").first().click();
  await page.locator('#assessment-steps [data-snap-step="1"]').click();
  await page.locator("#btn-snapshot-review").click();
  const card = page.locator("#snapshot-ai-card");
  await expect(card).toBeVisible();
  await expect(card).toContainText(REVIEW.summary);
  await saveButton(page).click();
  await expect(page.locator("#toast")).toHaveText("Assessment saved");
  const saved = (await stored(page)).find((a) => /AI meeting notes/.test(a.solution));
  expect(saved.aiAssessment.summary).toBe(REVIEW.summary);

  // The PDF has the review's summary, dated, once; the tables are in the report's own sections, so they are not repeated.
  await page.locator("#btn-assessment-pdf").click();
  const report = page.locator("#assessment-print .pr-doc");
  const headings = (await report.locator(":scope > .pr-section > h2").allTextContents()).map((t) => t.trim());
  expect(headings.filter((h) => h.startsWith("AI review"))).toHaveLength(1);
  const section = report.locator("section", { has: page.locator("h2", { hasText: /^AI review/ }) });
  expect(await section.textContent()).toContain(REVIEW.summary);
  await expect(section.locator("table")).toHaveCount(0);
  const order = headings.map((h) => h.replace(/ ·.*/, ""));
  expect(order.indexOf("Recommendations / actions")).toBeLessThan(order.indexOf("AI review"));
  expect(order.indexOf("AI review")).toBeLessThan(order.indexOf("Next steps / implementation hand-off"));
});

test("snapshot: with no AI review the PDF has no AI review section", async ({ page }) => {
  await page.locator('.tab[data-view="assessments"]').click();
  await page.locator("#view-assessments tbody tr", { hasText: "Label printer" }).locator("button, a").first().click();
  await page.locator("#btn-assessment-pdf").click();
  const headings = (await page.locator("#assessment-print .pr-doc > .pr-section > h2").allTextContents()).map((t) => t.trim());
  expect(headings.some((h) => h.startsWith("AI review"))).toBe(false);
});
