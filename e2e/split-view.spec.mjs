// Browser test: the table beside an open record doesn't cut any column off. From 1280px it fits; narrower, it scrolls.
import { test, expect } from "@playwright/test";

const TABLES = [["register", "#risk-table", "button.row-name"], ["exceptions", "#exception-table", "button.row-name"], ["vendors", "#vendor-table", "button.vendor-name"],
  ["assessments", "#assessment-table", "button.row-name"], ["threats", "#tra-table", "button.row-name"]];

async function openRecord(page, [view, table, name], { width, font = "" }) {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width, height: 900 });
  await page.goto("/demo/");
  // A wide font too, since fonts differ between computers.
  if (font) await page.evaluate((f) => { const sheet = new CSSStyleSheet(); sheet.replaceSync(`* { font-family: ${f} !important; }`); document.adoptedStyleSheets = [sheet]; }, font);
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await page.locator(`.tab[data-view="${view}"]`).click();
  await page.locator(`${table} tbody ${name}`).first().click();
  await expect(page.locator("body")).toHaveClass(/-split/);
  const size = await page.evaluate((t) => { const el = document.querySelector(t), card = el.parentElement; return { over: el.getBoundingClientRect().width - card.clientWidth, scrolls: getComputedStyle(card).overflowX }; }, table);
  expect(errors).toEqual([]);
  return size;
}

for (const entry of TABLES) {
  for (const [width, font] of [[1280, ""], [1280, "Verdana, DejaVu Sans"], [1440, "Verdana, DejaVu Sans"]]) {
    test(`${entry[0]} beside an open record at ${width}px${font ? " with a wide font" : ""}: nothing is cut off`, async ({ page }) => {
      const { over } = await openRecord(page, entry, { width, font });
      expect(over, "the table fits its space").toBeLessThanOrEqual(0.5);
    });
  }
  test(`${entry[0]} beside an open record at 1100px: a table that doesn't fit can be scrolled to`, async ({ page }) => {
    const { scrolls } = await openRecord(page, entry, { width: 1100 });
    expect(scrolls).toBe("auto");
  });
}
