// The short level names on screen. Run with: node --test tests/levels.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { shortLevel, levelBadge } from "../levels.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

test("every level has its short name, without a number", () => {
  assert.deepEqual(["Very Low", "Low", "Moderate", "Medium", "High", "Very High", "Critical"].map((n) => shortLevel(n)), ["V.LOW", "LOW", "MED", "MED", "HIGH", "V.HIGH", "CRIT"]);
  assert.equal(shortLevel("Critical", "five"), "V.HIGH");   // older snapshots called the top level Critical
  assert.equal(shortLevel("nonsense"), "");
});

test("the label keeps the full word for hover and screen readers, and escapes anything else", () => {
  const html = levelBadge("Medium", { cls: "medium", esc });
  assert.match(html, /class="badge level medium" data-tip="Medium"/);
  assert.match(html, /<span aria-hidden="true">MED<\/span><span class="sr-only">Medium<\/span>/);
  assert.match(levelBadge("Critical", { cls: "critical", esc, prefix: "25" }), /<span aria-hidden="true">25 CRIT<\/span><span class="sr-only">25 Critical<\/span>/);
  assert.equal(levelBadge("<b>odd</b>", { esc }), '<span class="badge ">&lt;b&gt;odd&lt;/b&gt;</span>');
});
