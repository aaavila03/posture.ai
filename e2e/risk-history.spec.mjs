// Browser test for a risk's change history. The history comes from the hosted database, so demo mode doesn't show it;
// this checks that, and that the real history code runs in the browser and escapes what it shows.
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

test("demo mode has no History section, for a new risk or a saved one", async ({ page }) => {
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#btn-add").click();
  await expect(page.locator("#risk-history-section")).toBeHidden();
  await page.locator("#btn-cancel").click();
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await expect(page.locator("#risk-history-section")).toBeHidden();
  await expect(page.locator("#risk-comments")).toBeVisible();
});

test("the history lines render in the browser and escape what the database returns", async ({ page }) => {
  const html = await page.evaluate(async () => {
    const { historyHtml } = await import("/risk-history.js");
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const box = document.createElement("ul");
    box.innerHTML = historyHtml([
      { at: "2026-11-24T10:00:00Z", actor_email: "carol@acme.test", action: "update", changes: { status: { from: "Identified", to: "<img src=x onerror=window.__pwned=1>" } } },
      { at: "2026-11-23T10:00:00Z", actor_email: "carol@acme.test", action: "insert", changes: null },
    ], { esc });
    return { text: box.innerText, images: box.querySelectorAll("img").length, pwned: window.__pwned === 1 };
  });
  expect(html.text).toContain("Stage");
  expect(html.text).toContain("Identified");
  expect(html.text).toContain("<img src=x onerror=window.__pwned=1>");
  expect(html.text).toContain("Created the risk");
  expect(html.images).toBe(0);
  expect(html.pwned).toBe(false);
});
