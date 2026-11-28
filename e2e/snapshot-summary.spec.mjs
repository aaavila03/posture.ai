// Browser test: in the posture snapshot PDF the executive summary starts right under the title, even when it is too long
// to fit on the first page.
import { test, expect } from "@playwright/test";

// The printable area of a letter page inside the report's margins (see @page in styles.css), in CSS pixels.
const mm = 96 / 25.4;
const PAGE = { width: (215.9 - 28) * mm, height: (279.4 - 30) * mm };

test("a long executive summary still starts on the first page", async ({ page }) => {
  await page.setViewportSize({ width: Math.floor(PAGE.width), height: 1000 });
  await page.goto("/demo/");
  await page.evaluate(async () => {
    const { reportHtml } = await import("/assessments.js");
    const many = (what) => Array.from({ length: 8 }, (_, i) => `${what} ${i + 1}: a crafted file could write outside the target folder and run code with the user's rights, which could spread to shared drives.`).join("\n");
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
    document.querySelector("#assessment-print").innerHTML = reportHtml({ solution: "File archive utility", topRisks: many("Risk"), topRecommendations: many("Recommendation") }, { esc, id: "A-001" });
    document.body.classList.add("printing-assessment");
  });
  await page.emulateMedia({ media: "print" });

  const found = await page.evaluate(() => {
    const cover = document.querySelector("#assessment-print .pr-cover").getBoundingClientRect();
    const exec = document.querySelector("#assessment-print .pr-exec");
    return { gap: exec.getBoundingClientRect().top - cover.bottom, height: cover.height + exec.getBoundingClientRect().height,
      breaks: [exec, ...exec.querySelectorAll("tr")].map((el) => getComputedStyle(el).breakInside) };
  });
  expect(found.height, "the summary is too long for the first page").toBeGreaterThan(PAGE.height);
  expect(found.gap).toBeLessThan(30);
  // Nothing may hold the summary or a long row together, which would push it to the next page.
  expect([...new Set(found.breaks)]).toEqual(["auto"]);
});
