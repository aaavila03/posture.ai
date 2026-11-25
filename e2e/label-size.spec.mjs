// Browser test: every coloured label is the same size, on every screen and in the printed reports, and none is cut off.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.addInitScript(() => { window.print = () => {}; });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

// The visible labels' sizes, and any whose text doesn't fit inside them.
const measure = (page, selector) => page.evaluate((selector) => {
  const shown = [...document.querySelectorAll(selector)].filter((el) => el.getClientRects().length);
  return {
    count: shown.length,
    sizes: [...new Set(shown.map((el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.width)}x${Math.round(r.height)}`; }))],
    cut: shown.filter((el) => el.scrollWidth > el.clientWidth + 1).map((el) => el.textContent),
  };
}, selector);

for (const view of ["dashboard", "vendors", "register", "exceptions", "assessments", "threats"]) {
  test(`${view}: all labels are one size and none is cut off`, async ({ page }) => {
    await page.locator(`.tab[data-view="${view}"]`).click();
    const { count, sizes, cut } = await measure(page, ".view.active .badge");
    expect(count).toBeGreaterThan(0);
    expect(sizes).toHaveLength(1);
    expect(cut).toEqual([]);
  });
}

test("every label text the app can show fits the one size", async ({ page }) => {
  const result = await page.evaluate(() => {
    const texts = ["Very Low", "Low", "Moderate", "Medium", "High", "Very High", "Critical", "4. Critical", "2. Medium", "25 Critical", "Yes", "No", "Approved", "Not approved", "Awaiting approval",
      "Expired", "Expires today", "Expires in 30 days", "Within appetite", "Outside appetite", "Completed", "On time", "Overdue", "At risk", "Member"];
    const box = document.createElement("div");
    document.body.append(box);
    const labels = texts.map((text) => { const el = document.createElement("span"); el.className = "badge medium"; el.textContent = text; box.append(el); return el; });
    const out = { sizes: [...new Set(labels.map((el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.width)}x${Math.round(r.height)}`; }))], cut: labels.filter((el) => el.scrollWidth > el.clientWidth).map((el) => el.textContent) };
    box.remove();
    return out;
  });
  expect(result.sizes).toHaveLength(1);
  expect(result.cut).toEqual([]);
});

// Each report as it prints: labels one size, text inside them, and each inside its table cell.
const reports = [["register", "#risk-table", "button.row-name", "#btn-risk-pdf"], ["vendors", "#vendor-table", "button.vendor-name", "#btn-vendor-pdf"],
  ["assessments", "#assessment-table", "button.row-name", "#btn-assessment-pdf"], ["threats", "#tra-table", "button.row-name", "#btn-tra-pdf"]];
for (const [view, table, name, button] of reports) {
  test(`${view} PDF: labels are one size and stay inside their cells`, async ({ page }) => {
    await page.locator(`.tab[data-view="${view}"]`).click();
    // A record that has labels of its own (some have no risk level yet).
    const row = view === "assessments" ? page.locator(`${table} tbody tr`, { has: page.locator(".badge") }).first() : page.locator(`${table} tbody tr`).first();
    await row.locator(name).click();
    await page.locator(button).click();
    await page.emulateMedia({ media: "print" });
    // A4 at 96dpi, less the margins.
    await page.setViewportSize({ width: 700, height: 1000 });
    const result = await page.evaluate(() => {
      const labels = [...document.querySelectorAll("#assessment-print .pr-badge")].filter((el) => el.getClientRects().length);
      return {
        count: labels.length,
        sizes: [...new Set(labels.map((el) => { const r = el.getBoundingClientRect(); return `${Math.round(r.width)}x${Math.round(r.height)}`; }))],
        cut: labels.filter((el) => el.scrollWidth > el.clientWidth + 1).map((el) => el.textContent),
        outside: labels.filter((el) => { const cell = el.closest("td, th"); return cell && el.getBoundingClientRect().right > cell.getBoundingClientRect().right + 1; }).map((el) => el.textContent),
      };
    });
    expect(result.count).toBeGreaterThan(0);
    expect(result.sizes).toHaveLength(1);
    expect(result.cut).toEqual([]);
    expect(result.outside, "no label sticks out of its table cell").toEqual([]);
  });
}

// The labels are wider than some words need, so check no table is pushed past its card (it would be cut off, not scroll).
for (const [width, font] of [[1280, ""], [1280, "Verdana, DejaVu Sans"], [1440, ""], [1440, "Verdana, DejaVu Sans"]]) {
  test(`at ${width}px every record table fits its card${font ? " with a wide font" : ""}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    // Fonts differ between computers; a wide one is tried so the tables don't only fit with the one used here.
    if (font) await page.evaluate((f) => { const sheet = new CSSStyleSheet(); sheet.replaceSync(`* { font-family: ${f} !important; }`); document.adoptedStyleSheets = [sheet]; }, font);
    for (const [view, table] of [["vendors", "#vendor-table"], ["register", "#risk-table"], ["exceptions", "#exception-table"], ["assessments", "#assessment-table"], ["threats", "#tra-table"]]) {
      await page.locator(`.tab[data-view="${view}"]`).click();
      const over = await page.evaluate((t) => { const el = document.querySelector(t); return el.getBoundingClientRect().width - el.parentElement.getBoundingClientRect().width; }, table);
      expect(over, `${view} table is not wider than its card`).toBeLessThanOrEqual(0);
    }
  });
}
