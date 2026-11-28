// Browser test: the briefing's posture estimated without AI counts vendors as well as register risks.
import { test, expect } from "@playwright/test";

test("a vendor at critical or high risk raises the posture; an offboarded one doesn't", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  await page.goto("/demo/");
  const briefing = await page.evaluate(async () => {
    const { renderReport } = await import("/report.js");
    const risk = { id: "R-001", title: "A risk", category: "Other", status: "In treatment", likelihood: 2, impact: 2, residualLikelihood: 1, residualImpact: 2, inherent: 4, residual: 2 };
    const vendor = (residualTier, status = "Active") => ({ id: "V-001", name: "A vendor", residualTier, status });
    const read = (vendors) => {
      const el = document.createElement("div");
      el.innerHTML = renderReport({ risks: [risk], vendors, ai: null, generatedAt: new Date().toISOString(), title: "Example" });
      return [el.querySelector(".rh-posture-badge strong").textContent, el.querySelector(".rh-headline").textContent];
    };
    return { none: read([]), medium: read([vendor("Medium")]), high: read([vendor("High")]), critical: read([vendor("Critical")]),
      two: read([vendor("Critical"), vendor("Critical")]), gone: read([vendor("Critical", "Offboarded")]) };
  });
  const plain = "1 active risks, 0 critical, across 1 categories.";
  expect(briefing.none).toEqual(["Low", plain]);
  expect(briefing.medium).toEqual(["Low", plain]);
  expect(briefing.high).toEqual(["Guarded", plain]);
  expect(briefing.critical).toEqual(["Elevated", `${plain} 1 vendor at critical risk.`]);
  expect(briefing.two).toEqual(["High", `${plain} 2 vendors at critical risk.`]);
  expect(briefing.gone).toEqual(["Low", plain]);
  expect(errors, "no errors on the page").toEqual([]);
});
