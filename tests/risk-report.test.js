// The risk report printed to PDF from the Risk Ledger editor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { riskReportHtml } from "../risk-report.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const score = (l, i) => Number(l) * Number(i);
const rating = (s) => (s >= 20 ? { label: "Critical", cls: "critical" } : s >= 12 ? { label: "High", cls: "high" } : s >= 6 ? { label: "Medium", cls: "medium" } : { label: "Low", cls: "low" });
const LEVELS = ["Low", "Medium", "High", "Critical"];
const helpers = {
  inherent: (r) => score(r.likelihood, r.impact),
  residual: (r) => score(r.residualLikelihood || r.likelihood, r.residualImpact || r.impact),
  rating,
  riskLevel: (s) => `${LEVELS.indexOf(rating(s).label) + 1}. ${rating(s).label}`,
  level: (names, n) => (n >= 1 && n <= 5 ? `${n}. ${names[n - 1]}` : "–"),
  stageLabel: (r) => r.status || "Identified",
  slippage: (r) => (r.due ? { label: "On time", cls: "low" } : null),
};
const risk = {
  title: "Unpatched VPN appliance", description: "Two firmware versions behind <script>.", category: "Vulnerability/Patching",
  likelihood: 4, impact: 4, residualLikelihood: 2, residualImpact: 3, treatment: "Mitigate", controls: "Patch to the current firmware.",
  due: "2026-12-01", owner: "Network Team", status: "In treatment", dataImpact: ["Confidentiality", "Integrity"],
  comments: [{ by: "Aisha", at: "2026-11-01T10:00:00Z", text: "Window booked." }],
};

test("the report shows the risk, its scores and the sections that have data", () => {
  const html = riskReportHtml(risk, { esc, org: "Acme Corp", id: "R-004", helpers });
  assert.match(html, /Risk Report · R-004/);
  assert.match(html, /<h1>Unpatched VPN appliance<\/h1>/);
  assert.match(html, /Acme Corp/);
  assert.match(html, /Inherent risk<\/small><span class="pr-badge high">3\. High<\/span>/);
  assert.match(html, /Residual risk<\/small><span class="pr-badge medium">2\. Medium<\/span>/);
  assert.match(html, /<h2>Risk description<\/h2>/);
  assert.match(html, /<h2>Assessment<\/h2>/);
  assert.match(html, /<h2>Treatment<\/h2>/);
  assert.match(html, /Confidentiality, Integrity/);
  assert.match(html, /<h2>Comment log<\/h2>/);
  assert.match(html, /class="pr-doc pr-risk"/);
});

test("text is escaped", () => {
  const html = riskReportHtml(risk, { esc, id: "R-004", helpers });
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});

test("blank sections are left out", () => {
  const html = riskReportHtml({ title: "Bare risk", likelihood: 2, impact: 2 }, { esc, id: "R-009", helpers });
  for (const absent of ["Risk description", "Ownership", "Workflow &amp; governance", "Comment log"]) assert.doesNotMatch(html, new RegExp(`<h2>${absent}`));
  assert.match(html, /<h2>Assessment<\/h2>/);
  assert.match(html, /Posture\.ai/);
});

test("custom sections with answers are included", () => {
  const sections = [{ name: "Extra", fields: [{ id: "f1", label: "Region" }] }];
  const html = riskReportHtml({ ...risk, custom: { f1: "EMEA" } }, { esc, id: "R-004", helpers, sections });
  assert.match(html, /<h2>Extra<\/h2>/);
  assert.match(html, /EMEA/);
});
