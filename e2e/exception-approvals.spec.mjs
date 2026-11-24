// Browser test for exception approvals. Hosted mode can't run on the demo page, so the real panel code is given a stand-in
// for the database (kept in the page) and the real markup in the risk editor. This checks what each role sees and can do,
// that nobody can decide their own request, what is sent, and that what the database returns is escaped.
// Demo mode keeps its ordinary approval fields.
import { test, expect } from "@playwright/test";

test.beforeEach(async ({ page }) => {
  page.errors = [];
  page.on("pageerror", (err) => page.errors.push(err.message));
  page.on("console", (msg) => { if (msg.type() === "error") page.errors.push(msg.text()); });
  page.on("dialog", (dialog) => dialog.accept(dialog.type() === "prompt" ? "The system was replaced" : undefined));
  await page.clock.install({ time: new Date("2026-11-24T12:00:00") });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
});

test.afterEach(async ({ page }) => {
  expect(page.errors, "no errors in the console").toEqual([]);
});

const panel = (page) => page.locator("#risk-exception-panel");
async function openTreatment(page) {
  await page.locator('.tab[data-view="register"]').click();
  await page.locator("#risk-table tbody tr").first().locator("button.row-name").click();
  await page.locator('#risk-steps [data-rstep="2"]').click();
}

// Starts the real panel as a given person, with a database stand-in that remembers what it is asked.
async function startPanel(page, { role, userId = "me", risk = {}, requests = [] }) {
  await page.evaluate(async ({ role, userId, risk, requests }) => {
    const { initExceptionPanel } = await import("/exceptions.js");
    // The app starts the panel once; a test starts it for each person, so the element is replaced to drop the earlier one's handler.
    const element = document.querySelector("#risk-exception-panel");
    element.replaceWith(element.cloneNode(false));
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    window.__calls = [];
    window.__toasts = [];
    window.__risk = { id: "R-004", title: "Unpatched VPN", ...risk };
    window.__requests = requests;
    const record = (name, ...args) => { window.__calls.push([name, ...args]); };
    window.__panel = initExceptionPanel({
      $: (selector) => document.querySelector(selector), esc, today: () => "2026-11-24",
      toast: (message, isError) => window.__toasts.push(isError ? `ERROR: ${message}` : message),
      getRole: () => role, getUserId: () => userId,
      api: {
        list: async () => window.__requests,
        request: async (id, req) => {
          record("request", id, req);
          window.__requests = [{ id: "q1", renewal: window.__risk.exceptionApproved === "Yes", reason: req.reason, proposed_expiry: req.expiry, status: "requested", requested_by: userId, requested_by_email: "me@acme.test", requested_at: "2026-11-24T12:00:00Z" }, ...window.__requests];
          window.__risk = { ...window.__risk, logException: "Yes", exceptionPending: "2026-11-24" };
        },
        decide: async (id, approve, note) => { record("decide", id, approve, note); },
        withdraw: async (id) => { record("withdraw", id); },
        revoke: async (id, note) => { record("revoke", id, note); },
      },
      onChanged: async () => window.__risk,
    });
    window.__panel.show(window.__risk);
  }, { role, userId, risk, requests });
}
const calls = (page) => page.evaluate(() => window.__calls);
const toasts = (page) => page.evaluate(() => window.__toasts);
const pendingRequest = (by) => ({ id: "q9", renewal: false, reason: "Vendor <b>cannot</b> upgrade", proposed_expiry: "2027-02-01", status: "requested", requested_by: by, requested_by_email: `${by}@acme.test`, requested_at: "2026-11-20T10:00:00Z" });

test("demo mode keeps the ordinary approval fields and has no exception panel", async ({ page }) => {
  await openTreatment(page);
  await expect(page.locator('select[name="exceptionApproved"]')).toBeVisible();
  await expect(page.locator('input[name="exceptionExpiry"]')).toBeVisible();
  await expect(page.locator('select[name="exceptionApproved"]')).toBeEnabled();
  await expect(panel(page)).toBeHidden();
});

test("an analyst requests an exception: a reason and an end date are needed, and it then waits", async ({ page }) => {
  await openTreatment(page);
  await startPanel(page, { role: "analyst", risk: { logException: "Yes" } });
  await expect(panel(page)).toContainText("has not been requested for approval");
  await panel(page).getByRole("button", { name: "Request exception" }).click();
  await panel(page).getByRole("button", { name: "Send for approval" }).click();
  expect(await toasts(page)).toEqual(["ERROR: Give a reason for the exception."]);
  await panel(page).locator("[data-exc-reason]").fill("  Legacy system cannot be patched  ");
  await panel(page).getByRole("button", { name: "Send for approval" }).click();
  expect((await toasts(page)).at(-1)).toBe("ERROR: Choose when the exception ends.");
  await panel(page).locator("[data-exc-expiry]").fill("2026-11-24");
  await panel(page).getByRole("button", { name: "Send for approval" }).click();
  expect((await toasts(page)).at(-1)).toBe("ERROR: The end date must be in the future.");
  await panel(page).locator("[data-exc-expiry]").fill("2027-02-01");
  await panel(page).getByRole("button", { name: "Send for approval" }).click();
  expect(await calls(page)).toEqual([["request", "R-004", { reason: "Legacy system cannot be patched", expiry: "2027-02-01" }]]);
  await expect(panel(page).locator(".badge")).toHaveText("Awaiting approval");
  await expect(panel(page)).toContainText("Legacy system cannot be patched");
  // The maker can withdraw it; an analyst cannot decide.
  await expect(panel(page).getByRole("button", { name: "Withdraw request" })).toBeVisible();
  await expect(panel(page).getByRole("button", { name: "Approve" })).toHaveCount(0);
  await expect(panel(page).getByRole("button", { name: "Request exception" })).toHaveCount(0);
});

test("an approver decides someone else's request: a rejection needs a note", async ({ page }) => {
  await openTreatment(page);
  await startPanel(page, { role: "approver", userId: "dave", risk: { logException: "Yes", exceptionPending: "2026-11-20" }, requests: [pendingRequest("carol")] });
  await expect(panel(page).locator(".badge")).toHaveText("Awaiting approval");
  await expect(panel(page)).toContainText("Vendor <b>cannot</b> upgrade");
  expect(await panel(page).locator("b").count()).toBe(0);
  await expect(panel(page).getByRole("button", { name: "Withdraw request" })).toHaveCount(0);
  await panel(page).getByRole("button", { name: "Reject" }).click();
  expect((await toasts(page)).at(-1)).toBe("ERROR: Add a note saying why it is rejected.");
  expect(await calls(page)).toEqual([]);
  await panel(page).locator("[data-exc-note]").fill("Fix it instead");
  await panel(page).getByRole("button", { name: "Reject" }).click();
  expect(await calls(page)).toEqual([["decide", "q9", false, "Fix it instead"]]);

  await startPanel(page, { role: "approver", userId: "dave", risk: { logException: "Yes", exceptionPending: "2026-11-20" }, requests: [pendingRequest("carol")] });
  await panel(page).getByRole("button", { name: "Approve" }).click();
  expect(await calls(page)).toEqual([["decide", "q9", true, ""]]);
  expect((await toasts(page)).at(-1)).toBe("Exception approved");
});

test("nobody can decide their own request, whatever their role", async ({ page }) => {
  await openTreatment(page);
  for (const role of ["approver", "admin", "owner"]) {
    await startPanel(page, { role, userId: "me", risk: { logException: "Yes", exceptionPending: "2026-11-20" }, requests: [pendingRequest("me")] });
    await expect(panel(page).getByRole("button", { name: "Approve" })).toBeDisabled();
    await expect(panel(page).getByRole("button", { name: "Reject" })).toBeDisabled();
    await expect(panel(page)).toContainText("Someone else must decide a request you made");
    expect(await calls(page)).toEqual([]);
  }
});

test("an approved exception offers a renewal to analysts and a revoke to approvers; an expired one says so", async ({ page }) => {
  await openTreatment(page);
  const approved = { logException: "Yes", exceptionApproved: "Yes", exceptionExpiry: "2027-03-01", exceptionApprovedBy: "dave@acme.test", exceptionApprovedDate: "2026-11-01" };
  await startPanel(page, { role: "analyst", risk: approved });
  await expect(panel(page).locator(".badge")).toHaveText("Approved");
  await expect(panel(page)).toContainText("Approved by dave@acme.test on 2026-11-01, until 2027-03-01.");
  await expect(panel(page).getByRole("button", { name: "Request renewal" })).toBeVisible();
  await expect(panel(page).getByRole("button", { name: "Revoke…" })).toHaveCount(0);

  await startPanel(page, { role: "approver", risk: approved });
  await panel(page).getByRole("button", { name: "Revoke…" }).click();
  expect(await calls(page)).toEqual([["revoke", "R-004", "The system was replaced"]]);

  await startPanel(page, { role: "analyst", risk: { ...approved, exceptionExpiry: "2026-11-23" } });
  await expect(panel(page).locator(".badge")).toHaveText("Expired");
  await expect(panel(page)).toContainText("Request a renewal");
  // Approved before approvals were tracked.
  await startPanel(page, { role: "analyst", risk: { logException: "Yes", exceptionApproved: "Yes", exceptionExpiry: "2027-03-01" } });
  await expect(panel(page)).toContainText("recorded before approvals were tracked");
});

test("a viewer sees where an exception stands but has no buttons, and an unsaved risk asks for a save first", async ({ page }) => {
  await openTreatment(page);
  await startPanel(page, { role: "viewer", risk: { logException: "Yes", exceptionApproved: "Yes", exceptionExpiry: "2027-03-01", exceptionApprovedBy: "dave@acme.test" } });
  await expect(panel(page)).toContainText("Approved by dave@acme.test");
  await expect(panel(page).locator("button:not(summary)")).toHaveCount(0);
  await page.evaluate(() => window.__panel.show(null));
  await expect(panel(page)).toContainText("Save the risk first");
});
