// The short level names on screen. Run with: node --test tests/levels.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { shortLevel, shownLevel, levelBadge } from "../levels.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

test("every level has its short name, without a number", () => {
  assert.deepEqual(["Very Low", "Low", "Moderate", "Medium", "High", "Very High", "Critical"].map((n) => shortLevel(n)), ["LOW", "LOW", "MED", "MED", "HIGH", "CRITICAL", "CRITICAL"]);
  assert.equal(shortLevel("nonsense"), "");
});

test("the label keeps the full word for hover and screen readers, and escapes anything else", () => {
  const html = levelBadge("Medium", { cls: "medium", esc });
  assert.match(html, /class="badge level medium" data-tip="Medium"/);
  assert.match(html, /<span aria-hidden="true">MED<\/span><span class="sr-only">Medium<\/span>/);
  // CRITICAL is marked as the long word, so its text is sized to fit the same box.
  assert.match(levelBadge("Critical", { cls: "critical", esc }), /<span aria-hidden="true" class="long">CRITICAL<\/span><span class="sr-only">Critical<\/span>/);
  assert.ok(!html.includes('class="long"'), "shorter words keep the usual text size");
  assert.equal(levelBadge("<b>odd</b>", { esc }), '<span class="badge ">&lt;b&gt;odd&lt;/b&gt;</span>');
});

test("the top level reads Critical everywhere, though snapshots and assessments store Very High", () => {
  assert.equal(shownLevel("Very High"), "Critical");
  for (const name of ["Low", "Medium", "High", "Critical"]) assert.equal(shownLevel(name), name);
  assert.equal(shownLevel("Moderate"), "Medium");   // threat posture assessments store Moderate
  assert.equal(shownLevel("nonsense"), "nonsense");
  assert.match(levelBadge("Moderate", { cls: "medium", esc }), /data-tip="Medium"/);
  assert.equal(shownLevel("Very Low"), "Low");   // people see no Very Low level
  assert.equal(shownLevel(""), "");
  assert.equal(shownLevel(undefined), "");
  const html = levelBadge("Very High", { cls: "critical", esc });
  assert.match(html, /data-tip="Critical"/);
  assert.match(html, /<span aria-hidden="true" class="long">CRITICAL<\/span><span class="sr-only">Critical<\/span>/);
});
