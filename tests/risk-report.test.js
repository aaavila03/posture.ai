// The risk report printed to PDF from the Risk Ledger editor.
import { test } from "node:test";
import assert from "node:assert/strict";
import { riskReportHtml, treatmentPlanHtml } from "../risk-report.js";

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

const ai = {
  category: "Vulnerability/Patching", likelihood: 4, impact: 4, residual_likelihood: 2, residual_impact: 3, treatment: "Mitigate",
  rationale: "Matched indicators of patching risk.", threat_scenarios: ["Exploit via a known CVE"],
  recommended_controls: [
    { control: "Patch to the current firmware", csf_function: "Protect", priority: "High" },
    { control: "Isolate end-of-life systems", csf_function: "Protect", priority: "Medium" },
  ],
  offline: true, at: "2026-11-18T10:00:00Z",
};

test("a saved AI assessment is included in the report", () => {
  const html = riskReportHtml({ ...risk, aiAssessment: ai }, { esc, id: "R-004", helpers });
  assert.match(html, /<h2>Risk assessment \(rule-based\)<\/h2>/);
  assert.match(html, /Matched indicators of patching risk/);
  assert.match(html, /Exploit via a known CVE/);
  const online = riskReportHtml({ ...risk, aiAssessment: { ...ai, offline: false } }, { esc, id: "R-004", helpers });
  assert.match(online, /<h2>AI risk assessment<\/h2>/);
  assert.doesNotMatch(riskReportHtml(risk, { esc, id: "R-004", helpers }), /Risk assessment \(rule-based\)|AI risk assessment/);
});

test("the AI assessment does not repeat what the risk already says", () => {
  const html = riskReportHtml({ ...risk, aiAssessment: ai }, { esc, id: "R-004", helpers });
  // Same scores, category and treatment as the record: no scores table, no suggestion line.
  assert.doesNotMatch(html, /AI-suggested scores/);
  assert.doesNotMatch(html, /The AI suggests/);
  // The control already in the treatment plan is left out; the other one is listed.
  assert.doesNotMatch(html, /<td>Patch to the current firmware<\/td>/);
  assert.match(html, /<td>Isolate end-of-life systems<\/td>/);
});

test("the AI assessment shows only where it differs from the record", () => {
  const differing = { ...ai, likelihood: 5, category: "Other", treatment: "Accept" };
  const html = riskReportHtml({ ...risk, aiAssessment: differing }, { esc, id: "R-004", helpers });
  assert.match(html, /AI-suggested scores/);
  assert.match(html, /The AI suggests category <strong>Other<\/strong> and treatment <strong>Accept<\/strong>/);
});

test("when every recommended control is already in the plan, they are not repeated", () => {
  const all = { ...risk, controls: "Patch to the current firmware.\nIsolate end-of-life systems.", aiAssessment: ai };
  const html = riskReportHtml(all, { esc, id: "R-004", helpers });
  assert.match(html, /All recommended controls are already in the treatment plan/);
  assert.doesNotMatch(html, /<h3>Recommended controls<\/h3>/);
});

test("the treatment plan turns AI control lines into a table and other lines into a list", () => {
  const html = treatmentPlanHtml("Move the VPN behind MFA\n- Review in Q1\n- [Protect/High] Patch internet-facing systems\n- [Identify/Medium] Scan <weekly>", esc);
  assert.match(html, /<ul><li>Move the VPN behind MFA<\/li><li>Review in Q1<\/li><\/ul>/);
  assert.match(html, /<th class="pr-narrow">Function<\/th>/);
  assert.match(html, /<td>Protect<\/td><td><span class="pr-badge high">High<\/span><\/td><td>Patch internet-facing systems<\/td>/);
  assert.match(html, /<span class="pr-badge medium">Medium<\/span><\/td><td>Scan &lt;weekly&gt;<\/td>/);
  assert.doesNotMatch(html, /\[Protect\/High\]/);
});

test("a one-line plan is a paragraph and an empty plan is nothing", () => {
  assert.equal(treatmentPlanHtml("Patch the firmware", esc), "<p>Patch the firmware</p>");
  assert.equal(treatmentPlanHtml("  \n ", esc), "");
});

test("the report shows the treatment plan under the treatment facts", () => {
  const html = riskReportHtml({ ...risk, controls: "- [Protect/High] Patch to the current firmware" }, { esc, id: "R-004", helpers });
  assert.match(html, /<h3>Treatment plan \/ mitigating controls<\/h3>/);
  assert.match(html, /<td>Patch to the current firmware<\/td>/);
});

test("the report shows when a logged exception expires, and only for a logged exception", () => {
  const logged = riskReportHtml({ ...risk, logException: "Yes", exceptionApproved: "Yes", exceptionExpiry: "2026-12-10" }, { esc, id: "R-004", helpers });
  assert.match(logged, /<th>Exception expires<\/th><td>December 10, 2026<\/td>/);
  const notLogged = riskReportHtml({ ...risk, logException: "No", exceptionExpiry: "2026-12-10" }, { esc, id: "R-004", helpers });
  assert.doesNotMatch(notLogged, /Exception expires/);
});

test("the report shows where a risk stands against the risk appetite, only when one is set", () => {
  const appetite = { default: "Medium", categories: {} };
  const within = riskReportHtml({ ...risk, category: "Data Breach" }, { esc, id: "R-004", helpers, appetite });
  // 2 x 3 = 6 residual is Medium, inside a Medium limit.
  assert.match(within, /<th>Risk appetite<\/th><td><span class="pr-badge low">Within appetite<\/span> Limit: Medium<\/td>/);
  const strict = riskReportHtml({ ...risk, category: "Data Breach" }, { esc, id: "R-004", helpers, appetite: { default: "Low", categories: {} } });
  assert.match(strict, /<span class="pr-badge high">Outside appetite<\/span> Limit: Low/);
  assert.doesNotMatch(riskReportHtml(risk, { esc, id: "R-004", helpers }), /Risk appetite/);
  assert.doesNotMatch(riskReportHtml({ ...risk, status: "Closed" }, { esc, id: "R-004", helpers, appetite }), /Risk appetite/);
});
