// Browser test: gap severity labels in an AI vendor review have a smaller box than the other labels, with nothing cut off.
import { test, expect } from "@playwright/test";

test("severity labels in the AI vendor review are small, equal and not cut off", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  await page.goto("/demo/");
  const result = await page.evaluate(async () => {
    const { vendorReviewHtml } = await import("/vendors.js");
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const box = document.createElement("div");
    box.className = "pr-doc pr-review";
    box.style.fontFamily = "Verdana, DejaVu Sans";
    box.innerHTML = vendorReviewHtml({ recommendation: "Approve with conditions", risk_tier: "High", summary: "Summary.",
      gaps: ["High", "Medium", "Low"].map((severity) => ({ severity, gap: "A gap", remediation: "Fix it" })) }, esc);
    document.body.append(box);
    const size = (el) => { const r = el.getBoundingClientRect(); return { text: el.textContent, width: Math.round(r.width), height: Math.round(r.height), cut: el.scrollWidth > el.clientWidth }; };
    const out = { severity: [...box.querySelectorAll(".pr-table .pr-badge")].map(size), tier: size(box.querySelector(".pr-callout .pr-badge")) };
    box.remove();
    return out;
  });
  expect(result.severity.map((s) => s.text)).toEqual(["High", "Medium", "Low"]);
  expect(new Set(result.severity.map((s) => `${s.width}x${s.height}`)).size).toBe(1);
  expect(result.severity.some((s) => s.cut)).toBe(false);
  expect(result.severity[0].width).toBeLessThan(result.tier.width * 0.7);
  expect(result.severity[0].height).toBeLessThan(result.tier.height);
  expect(errors).toEqual([]);
});
