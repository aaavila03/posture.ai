// Browser test for linking a threat posture assessment's control gap to a risk: the button on the gap, the prefilled risk,
// the source line in the risk editor and its link back, and what it says once the assessment is deleted.
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

// Opens the sample threat posture assessment on its Risk scoring step.
async function openGaps(page) {
  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#view-threats tbody tr", { hasText: "Claude Enterprise" }).locator("button, a").first().click();
  await page.locator("#tra-steps button").nth(3).click();
}

test("a gap creates a prefilled risk with a source line, which survives saving and links back", async ({ page }) => {
  await openGaps(page);
  const firstGap = page.locator("#tra-body .tra-gap").first();
  const gapText = (await firstGap.locator(".tra-gap-text").innerText()).trim();
  await firstGap.getByRole("button", { name: "Create risk from this gap" }).click();

  // The register opens a new, unsaved risk filled in from the gap.
  await expect(page.locator(".tab.active")).toHaveAttribute("data-view", "register");
  await expect(page.locator("#risk-form")).toBeVisible();
  await expect(page.locator("#dialog-title")).toHaveText("New risk");
  await expect(page.locator('#risk-form input[name="title"]')).toHaveValue(gapText.slice(0, 200));
  await expect(page.locator('#risk-form input[name="asset"]')).toHaveValue("Claude Enterprise (sample)");
  expect(await page.locator('#risk-form textarea[name="description"]').inputValue()).toContain(gapText);
  const source = page.locator("#risk-source");
  await expect(source).toContainText("From threat posture assessment T-");
  await expect(source).toContainText("Claude Enterprise");
  await expect(source).not.toContainText("deleted");

  // Saved, it keeps the source.
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  const id = (await page.locator("#dialog-title").innerText()).split(" · ")[0];
  await page.locator("#btn-cancel").click();
  await page.locator("#risk-table tbody tr", { hasText: id }).locator("button.row-name").click();
  await expect(page.locator("#risk-source")).toContainText("From threat posture assessment T-");

  // The link opens that assessment.
  await page.locator("#risk-source a").click();
  await expect(page.locator(".tab.active")).toHaveAttribute("data-view", "threats");
  await expect(page.locator("#tra-title")).toContainText("Claude Enterprise");
});

test("a new risk has no source line, and closing a prefilled risk asks first", async ({ page }) => {
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#btn-add").click();
  await expect(page.locator("#risk-source")).toBeHidden();
  await page.locator("#btn-cancel").click();

  let asked = 0;
  page.removeAllListeners("dialog");
  page.on("dialog", (dialog) => { asked++; dialog.dismiss(); });
  await openGaps(page);
  await page.locator("#tra-body .tra-gap").first().getByRole("button", { name: "Create risk from this gap" }).click();
  await page.locator("#btn-cancel").click();
  expect(asked, "closing the unsaved prefilled risk asks").toBe(1);
  await expect(page.locator("#risk-form")).toBeVisible();
});

test("when the source assessment is deleted the risk stays and says so", async ({ page }) => {
  await openGaps(page);
  await page.locator("#tra-body .tra-gap").first().getByRole("button", { name: "Create risk from this gap" }).click();
  await page.locator('#risk-form button[type="submit"]').click();
  await expect(page.locator("#toast")).toHaveText("Risk saved");
  const id = (await page.locator("#dialog-title").innerText()).split(" · ")[0];
  await page.locator("#btn-cancel").click();

  await page.locator('.tab[data-view="threats"]').click();
  await page.locator("#view-threats tbody tr", { hasText: "Claude Enterprise" }).locator("button, a").first().click();
  await page.locator("#btn-tra-delete").click();
  await expect(page.locator("#view-threats tbody tr", { hasText: "Claude Enterprise" })).toHaveCount(0);

  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr", { hasText: id }).locator("button.row-name").click();
  await expect(page.locator("#risk-source")).toContainText("That assessment has been deleted");
  await expect(page.locator("#risk-source a")).toHaveCount(0);
});
