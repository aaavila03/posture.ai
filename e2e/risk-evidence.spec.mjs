// Browser test for evidence files on a risk. Files live in the hosted database, so demo mode doesn't show the section;
// this checks that, and runs the real file handling (reading a file, encoding it, turning it back into a download) in the browser.
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

test("demo mode has no Evidence section, for a new risk or a saved one", async ({ page }) => {
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#btn-add").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await expect(page.locator("#risk-evidence-section")).toBeHidden();
  await page.locator("#btn-cancel").click();
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
  await expect(page.locator("#risk-evidence-section")).toBeHidden();
  await expect(page.locator("#risk-comments")).toBeVisible();
});

test("the file picker only offers the allowed types", async ({ page }) => {
  await expect(page.locator("#risk-evidence-file")).toHaveAttribute("accept", ".pdf,.txt,.png,.jpg,.jpeg");
});

test("a chosen file is checked, encoded and turned back into the same bytes, and names are escaped", async ({ page }) => {
  const result = await page.evaluate(async () => {
    const { evidenceProblem, evidenceType, toBase64, fromBase64, evidenceHtml } = await import("/risk-evidence.js");
    const bytes = new Uint8Array(70000).map((_, i) => (i * 7) % 256);
    const file = new File([bytes], "report.pdf", { type: "application/pdf" });
    const data = toBase64(await file.arrayBuffer());
    const back = new Uint8Array(await fromBase64(data, evidenceType(file)).arrayBuffer());
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const list = document.createElement("ul");
    list.innerHTML = evidenceHtml([{ id: "1", name: "<img src=x onerror=window.__pwned=1>.pdf", size: 2048, created_at: "2026-11-24T10:00:00Z" }], { esc, canRemove: true });
    return {
      same: back.length === bytes.length && back.every((b, i) => b === bytes[i]),
      type: evidenceType(file),
      problem: evidenceProblem({ name: file.name, size: file.size, type: file.type }, []),
      html: evidenceProblem({ name: "page.html", size: 10, type: "text/html" }, []),
      images: list.querySelectorAll("img").length, text: list.innerText, pwned: window.__pwned === 1,
    };
  });
  expect(result.same).toBe(true);
  expect(result.type).toBe("application/pdf");
  expect(result.problem).toBe("");
  expect(result.html).toMatch(/PDF, a text file or a PNG or JPEG/);
  expect(result.images).toBe(0);
  expect(result.pwned).toBe(false);
  expect(result.text).toContain("<img src=x onerror=window.__pwned=1>.pdf");
  expect(result.text).toContain("Download");
  expect(result.text).toContain("Remove");
});
