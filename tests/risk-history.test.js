// A risk's change history lines (hosted mode). Run with: node --test tests/risk-history.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { historyEntryHtml, historyHtml, HISTORY_FIELDS } from "../risk-history.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const opts = { esc, when: () => "24 Nov 2026" };
const row = (over = {}) => ({ at: "2026-11-24T10:00:00Z", actor_email: "carol@acme.test", action: "update", changes: null, ...over });

test("an insert says the risk was created, by whom and when", () => {
  const html = historyEntryHtml(row({ action: "insert" }), opts);
  assert.match(html, /24 Nov 2026 · carol@acme\.test/);
  assert.match(html, /Created the risk/);
});

test("an update lists each key field with its old and new value", () => {
  const html = historyEntryHtml(row({ changes: { status: { from: "Identified", to: "Treating" }, owner: { from: "", to: "CFO" } } }), opts);
  assert.match(html, /<strong>Stage<\/strong>: “Identified” → “Treating”/);
  assert.match(html, /<strong>Owner<\/strong>: <em>blank<\/em> → “CFO”/);
});

test("likelihood and impact read as words, and anything unexpected is shown as recorded", () => {
  const html = historyEntryHtml(row({ changes: { likelihood: { from: "3", to: "5" }, impact: { from: "", to: "1" }, residualLikelihood: { from: 2, to: "4" },
    residualImpact: { from: "3", to: "9" }, title: { from: "1", to: "2" } } }), opts);
  assert.match(html, /<strong>Likelihood<\/strong>: “Possible” → “Almost certain”/);
  assert.match(html, /<strong>Impact<\/strong>: <em>blank<\/em> → “Very low”/);
  assert.match(html, /<strong>Residual likelihood<\/strong>: “Unlikely” → “Likely”/);
  assert.match(html, /<strong>Residual impact<\/strong>: “Medium” → “9”/);
  assert.match(html, /<strong>Title<\/strong>: “1” → “2”/);
});

test("an update with no key fields says other details changed, and a system change has no email", () => {
  assert.match(historyEntryHtml(row({ changes: null }), opts), /Changed other details/);
  assert.match(historyEntryHtml(row({ changes: {} }), opts), /Changed other details/);
  assert.match(historyEntryHtml(row({ actor_email: null }), opts), /· system/);
});

test("values, names and fields are escaped, and unknown fields are not shown", () => {
  const html = historyEntryHtml(row({ actor_email: "<b>x</b>@acme.test", changes: { title: { from: "<img src=x onerror=alert(1)>", to: "A & B" }, secret: { from: "a", to: "b" } } }), opts);
  assert.ok(!html.includes("<img") && !html.includes("<b>"));
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.match(html, /A &amp; B/);
  assert.ok(!html.includes("secret"));
});

test("a list shows its rows in order, or says there is no history", () => {
  const html = historyHtml([row({ action: "update", changes: { status: { from: "a", to: "b" } } }), row({ action: "insert" })], opts);
  assert.ok(html.indexOf("Stage") < html.indexOf("Created the risk"));
  assert.match(historyHtml([], opts), /No history yet/);
  assert.match(historyHtml(null, opts), /No history yet/);
});

test("the fields shown match the key fields the database records", () => {
  const sql = readFileSync(new URL("../supabase/migrations/20261126000000_risk_history.sql", import.meta.url), "utf8");
  const list = sql.match(/key_fields constant text\[\] := array\[([^\]]+)\]/)[1].match(/'([^']+)'/g).map((s) => s.slice(1, -1));
  assert.deepEqual([...list].sort(), Object.keys(HISTORY_FIELDS).sort());
});

test("the migration keeps the changed-fields list and limits who can read the history", () => {
  const sql = readFileSync(new URL("../supabase/migrations/20261126000000_risk_history.sql", import.meta.url), "utf8");
  assert.match(sql, /jsonb_build_object\('changed', changed, 'changes', changes\)/);
  assert.match(sql, /require_role\(org, 'viewer'\)/);
  assert.match(sql, /revoke all on function public\.risk_history\(uuid, text\) from public, anon/);
});

// The hosted store is the only one with a database client, so these must be on it. They were once added to the demo
// store by mistake, which only showed up in a real hosted workspace.
test("the hosted store has the history and evidence methods, and the demo store does not", async () => {
  const { CloudStore, LocalStore } = await import("../store.js");
  for (const method of ["loadRiskHistory", "listEvidence", "addEvidence", "getEvidence", "removeEvidence"]) {
    assert.equal(typeof CloudStore.prototype[method], "function", `CloudStore.${method}`);
    assert.equal(typeof LocalStore.prototype[method], "undefined", `LocalStore.${method}`);
  }
});

test("the hosted store's methods send the right requests and return the rows", async () => {
  const { CloudStore } = await import("../store.js");
  const calls = [];
  const chain = (result) => new Proxy({}, { get: (_, prop) => (prop === "then" ? (resolve) => resolve(result) : (...args) => { calls.push([prop, ...args]); return chain(result); }) });
  const client = {
    rpc: (name, args) => { calls.push(["rpc", name, args]); return Promise.resolve({ data: [{ action: "insert" }], error: null }); },
    from: (table) => { calls.push(["from", table]); return chain({ data: [{ id: "1", name: "a.pdf" }], error: null }); },
  };
  const store = new CloudStore({ client, orgId: "org-1", onError: () => {} });
  assert.deepEqual(await store.loadRiskHistory("R-001"), [{ action: "insert" }]);
  assert.deepEqual(calls.at(-1), ["rpc", "risk_history", { org: "org-1", risk: "R-001" }]);
  assert.deepEqual(await store.listEvidence("R-001"), [{ id: "1", name: "a.pdf" }]);
  assert.ok(calls.some((c) => c[0] === "from" && c[1] === "risk_evidence"));
  assert.ok(calls.some((c) => c[0] === "eq" && c[1] === "risk_ref" && c[2] === "R-001"));
  await store.addEvidence("R-001", { name: "a.pdf", media_type: "application/pdf", data: "JVBERi0xLjQK" });
  assert.ok(calls.some((c) => c[0] === "insert" && c[1].org_id === "org-1" && c[1].risk_ref === "R-001" && c[1].name === "a.pdf"));
  await store.removeEvidence("1");
  assert.ok(calls.some((c) => c[0] === "delete"));
});
