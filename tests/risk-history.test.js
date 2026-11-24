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
