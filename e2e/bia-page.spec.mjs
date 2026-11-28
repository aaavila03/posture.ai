// Browser test: the business impact part of the threat posture assessment PDF is one page of its own. Checked with every
// impact rated, the longest description in every cell, long names and a wide font.
import { test, expect } from "@playwright/test";

// The printable area of a letter page inside the report's margins (see @page in styles.css), in CSS pixels.
const mm = 96 / 25.4;
const PAGE = { width: (215.9 - 28) * mm, height: (279.4 - 30) * mm };

test("business impact fills no more than one page, with a page to itself", async ({ page }) => {
  await page.setViewportSize({ width: Math.floor(PAGE.width), height: 1000 });
  await page.goto("/demo/");
  await page.evaluate(async () => {
    const { traReportHtml } = await import("/tra.js");
    const { IMPACT_ROWS } = await import("/tra-library.js");
    const longest = (r) => "ABCDE"[r.levels.map((l) => l.length).indexOf(Math.max(...r.levels.map((l) => l.length)))];
    const assessment = { assetName: "Enterprise resource planning and billing platform (production, all regions)", assessmentDate: "2026-09-30",
      assetOwner: "Alexandra Montgomery-Fitzgerald", riskOwner: "Christopher Vanderbilt-Okafor", department: "Information Technology and Business Operations",
      profile: { assetTypes: [], auth: {}, vendor: "Example vendor" }, answers: {}, gapDetails: {},
      impact: Object.fromEntries(IMPACT_ROWS.map((r) => [r.id, { c: longest(r), i: longest(r), a: longest(r) }])) };
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
    document.querySelector("#assessment-print").innerHTML = traReportHtml(assessment, { esc, id: "T-001" });
    document.body.classList.add("printing-assessment");
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(".pr-doc, .pr-doc * { font-family: Verdana, 'DejaVu Sans' !important; }");
    document.adoptedStyleSheets = [sheet];
  });
  await page.emulateMedia({ media: "print" });

  const section = page.locator("#assessment-print .pr-bia");
  await expect(section.locator("table").last().locator("tbody tr")).toHaveCount(16);
  for (const fact of ["T-001", "Alexandra Montgomery-Fitzgerald", "Christopher Vanderbilt-Okafor", "Overall business impact"]) await expect(section).toContainText(fact, { ignoreCase: true });
  const size = await section.evaluate((el) => ({ height: el.getBoundingClientRect().height, wider: el.scrollWidth - el.clientWidth, before: getComputedStyle(el).breakBefore, next: getComputedStyle(el.nextElementSibling).breakBefore }));
  expect(size.height).toBeLessThan(PAGE.height);
  expect(size.wider).toBeLessThanOrEqual(0);
  expect([size.before, size.next]).toEqual(["page", "page"]);
});
