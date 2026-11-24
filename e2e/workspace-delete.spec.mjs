// Browser test for deleting a workspace. The hosted workspace code can't run against the demo page's storage, so it is given
// a stand-in for the database client and a pretend workspace. This checks the real dialog and button code: who sees it,
// that the name must be typed, what is sent to the database, and what happens when the database refuses.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("/demo/");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

// Starts the hosted workspace code once on the page. `refuse` makes the database reject the deletion.
async function startWorkspace(page, { role = "owner", refuse = false } = {}) {
  await page.evaluate(async ({ role, refuse }) => {
    window.__rpc = [];
    window.__messages = [];
    window.__backupClicks = 0;
    // Every query returns no rows; rpc calls are recorded.
    const rows = new Proxy(function () {}, { get: (_, prop) => (prop === "then" ? (resolve) => resolve({ data: [], error: null }) : () => rows), apply: () => rows });
    const client = {
      from: () => rows,
      rpc: async (name, args) => { window.__rpc.push({ name, args }); return refuse ? { data: null, error: { message: "permission denied" } } : { data: null, error: null }; },
      auth: { getUser: async () => ({ data: { user: {} } }) },
    };
    const { initWorkspace } = await import("/workspace.js");
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    initWorkspace({
      $: (selector) => document.querySelector(selector), escapeHtml: esc, toast: (m) => window.__messages.push(m), download: () => {},
      ctx: { client, org: { id: "11111111-1111-1111-1111-111111111111", name: "Acme Corp", role }, user: { id: "u1" } },
      onRenamed: () => {}, signOut: (m) => window.__messages.push(`SIGNOUT: ${m}`), onProfile: () => {},
    });
    // The backup button reuses Export JSON: count its clicks instead of downloading.
    document.querySelector("#btn-export-json").addEventListener("click", (e) => { window.__backupClicks++; e.stopImmediatePropagation(); }, true);
  }, { role, refuse });
  await page.locator('.tab[data-view="settings"]').click();
}

const deleteCalls = (page) => page.evaluate(() => window.__rpc.filter((c) => c.name === "delete_workspace"));

test("only an owner is offered workspace deletion", async ({ page }) => {
  await startWorkspace(page, { role: "admin" });
  await expect(page.locator("#ws-danger")).toBeHidden();
  await page.goto("/demo/");
  await startWorkspace(page, { role: "owner" });
  await expect(page.locator("#ws-danger")).toBeVisible();
  await expect(page.locator("#ws-delete-name")).toHaveText("Acme Corp");
});

test("deleting needs the workspace name typed exactly, and cancelling sends nothing", async ({ page }) => {
  await startWorkspace(page);
  await page.locator("#btn-ws-delete").click();
  const dialog = page.locator("#ws-delete-dialog");
  await expect(dialog).toHaveAttribute("open", "");
  await expect(page.locator("#ws-delete-title")).toHaveText("Acme Corp");
  const confirm = page.locator("#btn-ws-delete-confirm");
  const input = page.locator("#ws-delete-input");
  await expect(confirm).toBeDisabled();
  for (const wrong of ["Acme", "acme corp", "Acme Corpp", "Acme  Corp"]) {
    await input.fill(wrong);
    await expect(confirm).toBeDisabled();
  }
  await input.fill("Acme Corp");
  await expect(confirm).toBeEnabled();

  // Cancel closes the dialog and nothing reaches the database.
  await page.locator("#btn-ws-delete-cancel").click();
  await expect(dialog).not.toHaveAttribute("open", "");
  expect(await deleteCalls(page)).toEqual([]);
  // Opening it again starts empty.
  await page.locator("#btn-ws-delete").click();
  await expect(input).toHaveValue("");
  await expect(confirm).toBeDisabled();
});

test("the backup button runs the JSON export", async ({ page }) => {
  await startWorkspace(page);
  await page.locator("#btn-ws-delete").click();
  await page.locator("#btn-ws-delete-backup").click();
  expect(await page.evaluate(() => window.__backupClicks)).toBe(1);
  expect(await deleteCalls(page)).toEqual([]);
});

test("confirming deletes the workspace by id and name, closes the dialog and signs out", async ({ page }) => {
  await startWorkspace(page);
  await page.locator("#btn-ws-delete").click();
  await page.locator("#ws-delete-input").fill("Acme Corp");
  await page.locator("#btn-ws-delete-confirm").click();
  await expect(page.locator("#ws-delete-dialog")).not.toHaveAttribute("open", "");
  expect(await deleteCalls(page)).toEqual([{ name: "delete_workspace", args: { org: "11111111-1111-1111-1111-111111111111", confirm_name: "Acme Corp" } }]);
  expect(await page.evaluate(() => window.__messages)).toContain("SIGNOUT: The workspace was deleted.");
});

test("when the database refuses, the dialog stays open, shows the error and does not sign out", async ({ page }) => {
  await startWorkspace(page, { refuse: true });
  await page.locator("#btn-ws-delete").click();
  await page.locator("#ws-delete-input").fill("Acme Corp");
  await page.locator("#btn-ws-delete-confirm").click();
  await expect.poll(async () => (await deleteCalls(page)).length).toBe(1);
  await expect(page.locator("#ws-delete-dialog")).toHaveAttribute("open", "");
  await expect(page.locator("#btn-ws-delete-confirm")).toBeEnabled();
  const messages = await page.evaluate(() => window.__messages);
  expect(messages).toContain("permission denied");
  expect(messages.some((m) => m.startsWith("SIGNOUT"))).toBe(false);
});

test("a wrong name never reaches the database, even if the form is submitted anyway", async ({ page }) => {
  await startWorkspace(page);
  await page.locator("#btn-ws-delete").click();
  await page.locator("#ws-delete-input").fill("Acme Corpp");
  await page.locator("#ws-delete-form").evaluate((form) => form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true })));
  expect(await deleteCalls(page)).toEqual([]);
});
