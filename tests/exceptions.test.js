// Risk exceptions as a process (hosted mode). Run with: node --test tests/exceptions.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { expiryStatus } from "../reminders.js";
import { ROLE_RANK, canRequest, canDecide, canRevoke, canWithdraw, requestProblem, decideProblem, exceptionState, requestHtml, requestsHtml, exceptionCellHtml, expiryLabelHtml, EXCEPTION_MAX_DAYS } from "../exceptions.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const today = "2026-11-24";

test("the roles rank viewer < analyst < approver < admin < owner, in the app, the AI function and the database", () => {
  assert.deepEqual(Object.keys(ROLE_RANK), ["viewer", "analyst", "approver", "admin", "owner"]);
  assert.deepEqual(Object.values(ROLE_RANK), [1, 2, 3, 4, 5]);
  const handler = readFileSync(new URL("../supabase/functions/ai/handler.js", import.meta.url), "utf8");
  assert.match(handler, /const RANK = \{ viewer: 1, analyst: 2, approver: 3, admin: 4, owner: 5 \}/);
  const workspace = readFileSync(new URL("../workspace.js", import.meta.url), "utf8");
  assert.match(workspace, /const RANK = \{ viewer: 1, analyst: 2, approver: 3, admin: 4, owner: 5 \}/);
  const sql = readFileSync(new URL("../supabase/migrations/20261128000001_exception_approvals.sql", import.meta.url), "utf8");
  assert.match(sql, /'viewer' then 1 when 'analyst' then 2 when 'approver' then 3 when 'admin' then 4 when 'owner' then 5/);
  assert.match(readFileSync(new URL("../supabase/migrations/20261128000000_approver_role.sql", import.meta.url), "utf8"), /add value if not exists 'approver' before 'admin'/);
});

test("who can request, decide and revoke", () => {
  assert.deepEqual(["viewer", "analyst", "approver", "admin", "owner"].map(canRequest), [false, true, true, true, true]);
  assert.deepEqual(["viewer", "analyst", "approver", "admin", "owner"].map(canDecide), [false, false, true, true, true]);
  assert.deepEqual(["viewer", "analyst", "approver", "admin", "owner"].map(canRevoke), [false, false, true, true, true]);
  assert.equal(canDecide(undefined), false);
});

test("nobody decides their own request, and only approvers and above decide", () => {
  const request = { requested_by: "u1" };
  assert.equal(decideProblem(request, { role: "approver", userId: "u2" }), "");
  assert.equal(decideProblem(request, { role: "owner", userId: "u2" }), "");
  assert.match(decideProblem(request, { role: "approver", userId: "u1" }), /Someone else must decide/);
  assert.match(decideProblem(request, { role: "owner", userId: "u1" }), /Someone else must decide/);
  assert.match(decideProblem(request, { role: "analyst", userId: "u2" }), /Only approvers/);
});

test("a request can be withdrawn by its maker or an admin, while it waits", () => {
  const request = { status: "requested", requested_by: "u1" };
  assert.equal(canWithdraw(request, { role: "analyst", userId: "u1" }), true);
  assert.equal(canWithdraw(request, { role: "approver", userId: "u2" }), false);
  assert.equal(canWithdraw(request, { role: "admin", userId: "u2" }), true);
  assert.equal(canWithdraw(request, { role: "owner", userId: "u2" }), true);
  assert.equal(canWithdraw(request, { role: "viewer", userId: "u1" }), false);
  assert.equal(canWithdraw({ ...request, status: "approved" }, { role: "owner", userId: "u1" }), false);
});

test("a request needs a reason and an end date in the future, within two years", () => {
  assert.equal(requestProblem({ reason: "Legacy system", expiry: "2027-01-01" }, today), "");
  assert.match(requestProblem({ reason: "  ", expiry: "2027-01-01" }, today), /reason/);
  assert.match(requestProblem({ reason: "x", expiry: "" }, today), /Choose when/);
  assert.match(requestProblem({ reason: "x", expiry: "2026-11-24" }, today), /in the future/);
  assert.match(requestProblem({ reason: "x", expiry: "2026-01-01" }, today), /in the future/);
  assert.equal(requestProblem({ reason: "x", expiry: "2028-11-23" }, today), "");   // 730 days
  assert.match(requestProblem({ reason: "x", expiry: "2028-11-24" }, today), /two years/);
  assert.equal(EXCEPTION_MAX_DAYS, 730);
  assert.match(readFileSync(new URL("../supabase/migrations/20261128000001_exception_approvals.sql", import.meta.url), "utf8"), /current_date \+ 730/);
});

test("where an exception stands is worked out from the risk's fields", () => {
  assert.equal(exceptionState({}, today).state, "none");
  assert.match(exceptionState({ logException: "Yes" }, today).text, /has not been requested/);
  const requested = exceptionState({ logException: "Yes", exceptionPending: "2026-11-20" }, today);
  assert.deepEqual([requested.state, requested.badge], ["requested", "Awaiting approval"]);
  const approved = exceptionState({ exceptionApproved: "Yes", exceptionExpiry: "2027-03-01", exceptionApprovedBy: "dave@acme.test", exceptionApprovedDate: "2026-11-01" }, today);
  assert.equal(approved.state, "approved");
  assert.equal(approved.text, "Approved by dave@acme.test on 2026-11-01, until 2027-03-01.");
  const expired = exceptionState({ exceptionApproved: "Yes", exceptionExpiry: "2026-11-23", exceptionApprovedBy: "dave@acme.test" }, today);
  assert.equal(expired.state, "expired");
  assert.match(expired.text, /ended on 2026-11-23\. Request a renewal/);
  assert.equal(exceptionState({ exceptionApproved: "Yes", exceptionExpiry: "2026-11-24" }, today).state, "approved");   // the last day still counts
  const renewal = exceptionState({ exceptionApproved: "Yes", exceptionExpiry: "2027-03-01", exceptionPending: "2026-11-20" }, today);
  assert.deepEqual([renewal.state, renewal.text.includes("runs until 2027-03-01")], ["renewal", true]);
  assert.equal(exceptionState({ exceptionApproved: "No" }, today).state, "rejected");
  // Approved before approvals were tracked: no approver recorded.
  assert.match(exceptionState({ exceptionApproved: "Yes", exceptionExpiry: "2027-03-01" }, today).text, /recorded before approvals were tracked/);
  assert.match(exceptionState({ exceptionApproved: "Yes" }, today).text, /with no end date/);
});

test("a request shows who, when, why and how it was decided, with everything escaped", () => {
  const base = { renewal: false, reason: "<b>Cannot patch</b>", proposed_expiry: "2027-01-01", status: "requested", requested_by_email: "carol@acme.test", requested_at: "2026-11-20T10:00:00Z", decided_by_email: null, decided_at: null, decision_note: null };
  const waiting = requestHtml(base, { esc });
  assert.match(waiting, /Request by carol@acme\.test on 2026-11-20 · until 2027-01-01/);
  assert.match(waiting, /Waiting for a decision/);
  assert.ok(!waiting.includes("<b>"));
  const rejected = requestHtml({ ...base, renewal: true, status: "rejected", decided_by_email: "dave@acme.test", decided_at: "2026-11-21T09:00:00Z", decision_note: "Fix it <i>instead</i>" }, { esc });
  assert.match(rejected, /Renewal by carol/);
  assert.match(rejected, /Rejected by dave@acme\.test on 2026-11-21: Fix it &lt;i&gt;instead&lt;\/i&gt;/);
  assert.match(requestHtml({ ...base, status: "approved", decided_by_email: "dave@acme.test", decided_at: "2026-11-21T09:00:00Z" }, { esc }), /Approved by dave/);
  assert.match(requestHtml({ ...base, status: "withdrawn", decided_by_email: "carol@acme.test", decided_at: "2026-11-21T09:00:00Z" }, { esc }), /Withdrawn by carol/);
  assert.match(requestsHtml([], { esc }), /No requests yet/);
});

test("the migration keeps the approval fields behind the database's own functions", () => {
  const sql = readFileSync(new URL("../supabase/migrations/20261128000001_exception_approvals.sql", import.meta.url), "utf8");
  for (const key of ["exceptionApproved", "exceptionExpiry", "exceptionApprovedBy", "exceptionApprovedDate", "exceptionPending"]) assert.ok(sql.includes(`'${key}'`), key);
  assert.match(sql, /current_user not in \('authenticated', 'anon'\)/);
  assert.match(sql, /someone else must decide a request you made/);
  assert.match(sql, /grant select on public\.risk_exceptions to authenticated/);
  assert.ok(!/grant[^;]*(insert|update|delete)[^;]*risk_exceptions/i.test(sql), "the requests are only written by the functions");
  assert.match(sql, /revoke all on function public\.request_exception[^;]+from public, anon/);
});

test("the store sends each action to the right database function", async () => {
  const { CloudStore } = await import("../store.js");
  const calls = [];
  const chain = (result) => new Proxy({}, { get: (_, prop) => (prop === "then" ? (resolve) => resolve(result) : (...args) => { calls.push([prop, ...args]); return chain(result); }) });
  const client = {
    rpc: (name, args) => { calls.push(["rpc", name, args]); return Promise.resolve({ data: null, error: null }); },
    from: (table) => { calls.push(["from", table]); return chain({ data: [{ id: "q1" }], error: null }); },
  };
  const store = new CloudStore({ client, orgId: "org-1", onError: () => {} });
  assert.deepEqual(await store.listExceptions("R-001"), [{ id: "q1" }]);
  assert.ok(calls.some((c) => c[0] === "from" && c[1] === "risk_exceptions"));
  await store.requestException("R-001", { reason: "Legacy", expiry: "2027-01-01" });
  assert.deepEqual(calls.at(-1), ["rpc", "request_exception", { org: "org-1", risk: "R-001", reason: "Legacy", expiry: "2027-01-01" }]);
  await store.decideException("q1", true, "");
  assert.deepEqual(calls.at(-1), ["rpc", "decide_exception", { org: "org-1", request: "q1", approve: true, note: null }]);
  await store.decideException("q1", false, "No");
  assert.deepEqual(calls.at(-1), ["rpc", "decide_exception", { org: "org-1", request: "q1", approve: false, note: "No" }]);
  await store.withdrawException("q1");
  assert.deepEqual(calls.at(-1), ["rpc", "withdraw_exception", { org: "org-1", request: "q1" }]);
  await store.revokeException("R-001", "Replaced");
  assert.deepEqual(calls.at(-1), ["rpc", "revoke_exception", { org: "org-1", risk: "R-001", note: "Replaced" }]);
  assert.equal(typeof (await import("../store.js")).LocalStore.prototype.requestException, "undefined");
});

test("the roles help text under the invite box names every role, in rank order", () => {
  const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
  const help = html.match(/<p class="muted small">Viewer: read-only[^<]*<\/p>/)?.[0] || "";
  const names = ["Viewer", "Analyst", "Approver", "Admin", "Owner"];
  assert.ok(help, "the help text is there");
  names.forEach((name) => assert.ok(help.includes(`${name}:`), name));
  const positions = names.map((name) => help.indexOf(`${name}:`));
  assert.deepEqual([...positions].sort((a, b) => a - b), positions, "in rank order");
});

test("the Exceptions table shows one short status per risk, with the full words on hover", () => {
  const cell = (risk) => exceptionCellHtml(risk, { esc });
  const code = (html) => html.match(/<span aria-hidden="true">([A-Z]+)<\/span>/)[1];
  assert.equal(code(cell({})), "NONE");
  assert.equal(code(cell({ exceptionApproved: "No" })), "REJ");
  assert.equal(code(cell({ exceptionApproved: "Yes" })), "APPR");
  // A first request is pending even if the risk was marked No before.
  assert.equal(code(cell({ exceptionPending: "2026-11-20" })), "PEND");
  assert.equal(code(cell({ exceptionPending: "2026-11-20", exceptionApproved: "No" })), "PEND");
  // A renewal keeps the approval, with a line under it; only one label either way.
  const renewal = cell({ exceptionPending: "2026-11-20", exceptionApproved: "Yes" });
  assert.equal(code(renewal), "APPR");
  assert.match(renewal, /\+ renewal awaiting approval/);
  assert.equal(renewal.match(/class="badge/g).length, 1);
  assert.match(cell({ exceptionApproved: "No" }), /data-tip="Not approved"/);
  assert.ok(!cell({ exceptionApproved: "Yes" }).includes("renewal"));
});

test("the expiry label is short, with the full words on hover", () => {
  const label = (date) => expiryLabelHtml(expiryStatus(date, today), { esc });
  const code = (html) => html.match(/<span aria-hidden="true">([^<]+)<\/span>/)[1];
  assert.equal(code(label("2026-11-23")), "EXPIRED");
  assert.equal(code(label("2026-11-24")), "TODAY");
  assert.equal(code(label("2026-11-25")), "1 DAY");
  assert.equal(code(label("2026-12-24")), "30 DAYS");
  assert.match(label("2026-12-09"), /data-tip="Expires in 15 days"/);
  assert.equal(label("2027-06-30"), "");   // not close yet
  assert.equal(expiryLabelHtml(null, { esc }), "");
});
