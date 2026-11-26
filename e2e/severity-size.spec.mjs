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

// The risk review (which a risk opened from the Exceptions tab shows too) and the snapshot review use the same small box.
test("risk and snapshot AI review labels are the same small box, with nothing cut off", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  await page.goto("/demo/");
  const result = await page.evaluate(async () => {
    const { riskAssessmentHtml } = await import("/risk-report.js");
    const { reviewCardHtml } = await import("/assessments.js");
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const rating = (s) => (s >= 20 ? { label: "Critical", cls: "critical" } : s >= 12 ? { label: "High", cls: "high" } : s >= 6 ? { label: "Medium", cls: "medium" } : { label: "Low", cls: "low" });
    const risk = riskAssessmentHtml({ likelihood: 5, impact: 5, residual_likelihood: 3, residual_impact: 2, recommended_controls: [{ csf_function: "Protect", priority: "Medium", control: "MFA" }] },
      { likelihood: 1, impact: 1 }, { esc, helpers: { rating, riskLevel: (s) => `4. ${rating(s).label}`, level: (names, n) => names[n - 1] } });
    const snapshot = reviewCardHtml({ rows: [{ id: "R1", domain: "Data", inherent: "Very High", strategy: "Mitigate", residual: "Very Low" }], added: [], filled: [] }, { esc });
    const measure = (html) => {
      const box = document.createElement("div");
      box.style.fontFamily = "Verdana, DejaVu Sans";
      box.innerHTML = html.includes("pr-review") ? html : `<div class="pr-doc pr-review">${html}</div>`;
      document.body.append(box);
      const out = [...box.querySelectorAll(".pr-badge")].map((el) => { const r = el.getBoundingClientRect(); return { text: el.textContent, size: `${Math.round(r.width)}x${Math.round(r.height)}`, cut: el.scrollWidth > el.clientWidth }; });
      box.remove();
      return out;
    };
    return { risk: measure(risk), snapshot: measure(snapshot) };
  });
  expect(result.risk.map((l) => l.text)).toEqual(["Critical", "Medium", "Medium"]);
  expect(result.snapshot.map((l) => l.text)).toEqual(["Critical", "Low"]);
  const all = [...result.risk, ...result.snapshot];
  expect(new Set(all.map((l) => l.size))).toEqual(new Set(["59x13"]));
  expect(all.filter((l) => l.cut)).toEqual([]);
  expect(errors).toEqual([]);
});

// The treatment plan under a risk's Treatment & Review step, as a risk opened from the Exceptions tab shows it.
test("treatment plan priorities are the same small box", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await page.locator('.tab[data-view="exceptions"]').click();
  await page.locator("#exception-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await page.locator('#risk-form textarea[name="controls"]').fill("- [Protect/High] Patch the VPN\n- [Detect/Medium] Alert on logins\n- [Recover/Low] Test restores");
  const labels = page.locator("#risk-plan-preview .pr-badge");
  await expect(labels).toHaveCount(3);
  expect(await labels.evaluateAll((els) => els.map((el) => { const r = el.getBoundingClientRect(); return `${el.textContent} ${Math.round(r.width)}x${Math.round(r.height)} ${el.scrollWidth > el.clientWidth}`; })))
    .toEqual(["High 59x13 false", "Medium 59x13 false", "Low 59x13 false"]);
  expect(errors).toEqual([]);
});
