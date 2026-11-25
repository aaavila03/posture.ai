// The short risk level labels in the tab tables. Run with: node --test tests/levels.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { shortLevel, levelBadge } from "../levels.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

test("four-level scale: risk and vendor tiers", () => {
  assert.deepEqual(["Low", "Medium", "High", "Critical"].map((n) => shortLevel(n)), ["1. L", "2. M", "3. H", "4. C"]);
});

test("five-level scale: snapshots and threat assessments", () => {
  assert.deepEqual(["Very Low", "Low", "Medium", "High", "Very High"].map((n) => shortLevel(n, "five")), ["1. VL", "2. L", "3. M", "4. H", "5. VH"]);
  assert.equal(shortLevel("Moderate", "five"), "3. M");
  assert.equal(shortLevel("Critical", "five"), "5. VH");
});

test("the label keeps the full word for hover and screen readers, and escapes anything else", () => {
  const html = levelBadge("Medium", { cls: "medium", esc });
  assert.match(html, /class="badge level medium" data-tip="Medium"/);
  assert.match(html, /<span aria-hidden="true">2\. M<\/span><span class="sr-only">Medium<\/span>/);
  assert.equal(levelBadge("<b>odd</b>", { esc }), '<span class="badge ">&lt;b&gt;odd&lt;/b&gt;</span>');
});
