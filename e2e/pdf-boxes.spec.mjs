// Browser test: every coloured box in every PDF is the same small size, holds its words, and no report shows risk scores
// or numbered ratings. Covers the risk, vendor, posture snapshot and threat assessment reports and the printed briefing.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(() => { window.print = () => {}; });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors on the page").toEqual([]);
});

// The boxes in `root` as printed: their sizes, any whose words don't fit, and their words.
const boxes = (page, root, selector) => page.evaluate(([root, selector]) => {
  const shown = [...document.querySelector(root).querySelectorAll(selector)].filter((el) => el.getClientRects().length);
  return {
    count: shown.length,
    sizes: [...new Set(shown.map((el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.width)}x${Math.round(r.height)}`; }))],
    cut: shown.filter((el) => el.scrollWidth > el.clientWidth + 1).map((el) => el.innerText),
    words: [...new Set(shown.map((el) => el.innerText.trim()))],
  };
}, [root, selector]);

const numbered = /\b[1-5]\.\s+(Very low|Low|Medium|Moderate|High|Very high|Critical|Rare|Unlikely|Possible|Likely|Almost certain)\b|\bof 25\b|Average score|\bScore \d/i;

const reports = [["register", "#risk-table", "button.row-name", "#btn-risk-pdf"], ["vendors", "#vendor-table", "button.vendor-name", "#btn-vendor-pdf"],
  ["assessments", "#assessment-table", "button.row-name", "#btn-assessment-pdf"], ["threats", "#tra-table", "button.row-name", "#btn-tra-pdf"]];
for (const [view, table, name, button] of reports) {
  test(`${view} PDF: one small box size and no scores`, async ({ page }) => {
    await page.locator(`.tab[data-view="${view}"]`).click();
    const rows = page.locator(`${table} tbody tr`);
    await (view === "assessments" ? rows.filter({ has: page.locator(".badge") }) : rows).first().locator(name).click();
    await page.locator(button).click();
    await page.emulateMedia({ media: "print" });
    await page.setViewportSize({ width: 700, height: 1000 });
    const found = await boxes(page, "#assessment-print", ".pr-badge, .pr-pill");
    expect(found.count).toBeGreaterThan(0);
    expect(found.sizes).toEqual(["59x13"]);
    expect(found.cut).toEqual([]);
    expect(await page.locator("#assessment-print").innerText()).not.toMatch(numbered);
    // Nothing is wider than the page, even with a wide font: a printout that is too wide gets shrunk, boxes and all.
    await page.evaluate(() => { const sheet = new CSSStyleSheet(); sheet.replaceSync("* { font-family: Verdana, DejaVu Sans !important; }"); document.adoptedStyleSheets = [sheet]; });
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(0);
    expect((await boxes(page, "#assessment-print", ".pr-badge, .pr-pill")).cut).toEqual([]);
  });
}

test("the printed briefing uses the same boxes, with levels as words and no scores", async ({ page }) => {
  await page.locator('.tab[data-view="analyst"]').click();
  await page.locator("#btn-report").click();
  await expect(page.locator("#view-analyst .rh-doc")).toBeVisible();
  // On screen the level boxes keep their short capitals.
  await expect(page.locator("#view-analyst .rh-doc .badge.level [aria-hidden]").first()).toHaveText(/^(LOW|MED|HIGH|CRITICAL)$/);
  await page.locator("#btn-print-report").click();
  await page.emulateMedia({ media: "print" });
  // The briefing itself is on the page, without the app around it.
  await expect(page.locator("#view-analyst .rh-doc")).toBeVisible();
  await expect(page.locator(".sidebar")).toBeHidden();
  await expect(page.locator("#briefing-panel > summary")).toBeHidden();
  await expect(page.locator(".topbar")).toBeHidden();
  const found = await boxes(page, "#view-analyst .rh-doc", ".badge");
  expect(found.count).toBeGreaterThan(0);
  expect(found.sizes).toEqual(["59x13"]);
  expect(found.cut).toEqual([]);
  for (const word of found.words) expect(word).toMatch(/^(Low|Medium|High|Critical)$/i);
  const text = await page.locator("#view-analyst .rh-doc").innerText();
  expect(text).not.toMatch(/Avg score|Residual \d/i);
});
