// Browser test for previewing evidence files. Files come from the hosted database, so the real preview code is given a stand-in
// for fetching a file and the real dialog markup: this checks what is shown for each type, that text is shown as text,
// that a PDF opens in a new tab straight from the click, and that closing clears the dialog.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  await page.goto("/demo/");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

// Starts the real preview code with files made in the page: a 1x1 PNG, a text file with markup and a PDF.
async function setup(page, { tabAllowed = true, failFetch = false } = {}) {
  await page.evaluate(async ({ tabAllowed, failFetch }) => {
    const { initEvidencePreview } = await import("/risk-evidence.js");
    const b64 = (s) => btoa(s);
    const files = {
      img: { name: "shot.png", media_type: "image/png", data: "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==" },
      txt: { name: "notes.txt", media_type: "text/plain", data: b64("Findings <img src=x onerror=window.__pwned=1>\nline two") },
      long: { name: "log.txt", media_type: "text/plain", data: b64("x".repeat(150 * 1024)) },
      pdf: { name: "policy.pdf", media_type: "application/pdf", data: b64("%PDF-1.4\n%%EOF") },
    };
    window.__tabs = [];
    window.__toasts = [];
    const tab = { location: { href: "" }, opener: "set", closed: false, close() { this.closed = true; } };
    window.__preview = initEvidencePreview({
      $: (selector) => document.querySelector(selector),
      toast: (message) => window.__toasts.push(message),
      getFile: async (id) => { if (failFetch) throw new Error("no such file"); return files[id]; },
      openTab: (...args) => { window.__tabs.push(args); return tabAllowed ? tab : null; },
    });
    window.__tab = tab;
    window.__row = (id, media_type) => ({ id, name: files[id].name, media_type });
  }, { tabAllowed, failFetch });
}
const preview = (page, id, type) => page.evaluate(([id, type]) => window.__preview(window.__row(id, type)).then(() => "ok", (e) => e.message), [id, type]);

test("an image opens in the dialog, and closing clears it", async ({ page }) => {
  await setup(page);
  expect(await preview(page, "img", "image/png")).toBe("ok");
  const dialog = page.locator("#evidence-preview-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator("#evidence-preview-title")).toHaveText("shot.png");
  await expect(page.locator("#evidence-preview-image")).toBeVisible();
  await expect(page.locator("#evidence-preview-text")).toBeHidden();
  await expect.poll(() => page.locator("#evidence-preview-image").evaluate((img) => img.complete && img.naturalWidth)).toBe(1);
  expect(await page.locator("#evidence-preview-image").getAttribute("src")).toMatch(/^blob:/);
  await page.locator("#btn-evidence-preview-close").click();
  await expect(dialog).not.toHaveAttribute("open", "");
  await expect(page.locator("#evidence-preview-image")).not.toHaveAttribute("src", /.+/);
});

test("text is shown as plain text, never as markup, and a long file says it is cut", async ({ page }) => {
  await setup(page);
  await preview(page, "txt", "text/plain");
  const text = page.locator("#evidence-preview-text");
  await expect(text).toBeVisible();
  await expect(page.locator("#evidence-preview-image")).toBeHidden();
  await expect(text).toHaveText("Findings <img src=x onerror=window.__pwned=1>\nline two");
  expect(await text.locator("img").count()).toBe(0);
  expect(await page.evaluate(() => window.__pwned === 1)).toBe(false);
  await expect(page.locator("#evidence-preview-note")).toBeHidden();
  await page.keyboard.press("Escape");

  await preview(page, "long", "text/plain");
  await expect(page.locator("#evidence-preview-note")).toContainText("Showing the first 100 KB of 150 KB");
  expect((await text.textContent()).length).toBe(100 * 1024);
  // Closing clears the text, and the next file does not show the old note.
  await page.locator("#btn-evidence-preview-close").click();
  await expect(text).toHaveText("");
  await preview(page, "txt", "text/plain");
  await expect(page.locator("#evidence-preview-note")).toBeHidden();
});

test("clicking outside the dialog closes it", async ({ page }) => {
  await setup(page);
  await preview(page, "txt", "text/plain");
  await page.mouse.click(5, 5);
  await expect(page.locator("#evidence-preview-dialog")).not.toHaveAttribute("open", "");
});

test("a PDF opens in a new tab opened straight away, cut off from the app, and the dialog stays shut", async ({ page }) => {
  await setup(page);
  expect(await preview(page, "pdf", "application/pdf")).toBe("ok");
  const state = await page.evaluate(() => ({ tabs: window.__tabs, href: window.__tab.href ?? window.__tab.location.href, opener: window.__tab.opener }));
  expect(state.tabs).toEqual([["", "_blank"]]);
  expect(state.href).toMatch(/^blob:/);
  expect(state.opener).toBeNull();
  await expect(page.locator("#evidence-preview-dialog")).not.toHaveAttribute("open", "");
});

test("a blocked pop-up says so, and a failed fetch closes the empty tab and reports the error", async ({ page }) => {
  await setup(page, { tabAllowed: false });
  expect(await preview(page, "pdf", "application/pdf")).toBe("ok");
  expect(await page.evaluate(() => window.__toasts)).toEqual(["Allow pop-ups to preview PDFs, or use Download."]);

  await page.goto("/demo/");
  await setup(page, { failFetch: true });
  expect(await preview(page, "pdf", "application/pdf")).toBe("no such file");
  expect(await page.evaluate(() => window.__tab.closed)).toBe(true);
});

test("a type that can't be previewed does nothing", async ({ page }) => {
  await setup(page);
  expect(await preview(page, "img", "application/zip")).toBe("ok");
  await expect(page.locator("#evidence-preview-dialog")).not.toHaveAttribute("open", "");
  expect(await page.evaluate(() => window.__tabs.length)).toBe(0);
});
