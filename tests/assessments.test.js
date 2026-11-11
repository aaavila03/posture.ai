// Ad-hoc risk assessments: the AI summary prompt, the offline summary rules, the PDF report
// and bringing assessments from the earlier template into the summary report.
// Run with: node --test tests/assessments.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { assessmentPrompt, summarizeOffline, blankAssessment, upgradeAssessment, highestLevel, reportHtml, HANDOFF_NOTE, LEVELS } from "../assessments.js";

const sample = () => ({
  ...blankAssessment(), solution: "Archive utility", requestor: "Sam Lee", population: "250 users", version: "24.1", licenseType: "Freeware",
  assessmentType: "Commercial software", nercImpact: "No", aiCapability: "No",
  scope: "Replace the built-in extractor", solutionOverview: "Opens and creates archives", topRisks: "Crafted archives\nTampered installer",
  recommendations: [
    { domain: "Patch management", recommendation: "Add to third-party patching", inherent: "High", strategy: "Mitigate", treatment: "Due 1 Dec", residual: "Low" },
    { domain: "Data protection", recommendation: "Hide weak encryption", inherent: "Medium", strategy: "Mitigate", treatment: "", residual: "Medium" },
  ],
});

test("a new assessment starts as a draft with the ten hand-off steps and no contacts", () => {
  const a = blankAssessment();
  assert.equal(a.status, "Draft");
  assert.equal(a.handoff.length, 10);
  assert.equal(a.handoff[0].category, "Open a request");
  assert.equal(a.handoff[9].team, "Enterprise Cyber Risk");
  assert.deepEqual(a.intakeTypes, []);
  assert.ok(a.handoff.every((h) => h.contact === "" && h.actions === ""));
});

test("the highest level reads Very Low to Very High, and Critical as Very High", () => {
  assert.equal(highestLevel(["Low", "Very High", "Medium"]), "Very High");
  assert.equal(highestLevel(["Very Low", "", undefined]), "Very Low");
  assert.equal(highestLevel(["High", "Critical"]), "Very High");
  assert.equal(highestLevel([]), "");
  assert.deepEqual(LEVELS, ["Very Low", "Low", "Medium", "High", "Very High"]);
});

test("the prompt carries the other sections", () => {
  const p = assessmentPrompt(sample());
  for (const s of ["Request name: Archive utility", "Requestor: Sam Lee", "population: 250 users", "license type: Freeware", "Assessment type: Commercial software",
    "NERC CIP: No; AI capability: No", "Replace the built-in extractor", "Opens and creates archives", "Tampered installer",
    "R1 [Patch management] Add to third-party patching | inherent High | response Mitigate | treatment plan: Due 1 Dec | residual Low"]) assert.ok(p.includes(s), s);
  assert.ok(assessmentPrompt(blankAssessment()).includes("Recommendations / actions:\n(none)"));
});

test("offline rules: the highest inherent level sets the risk level", () => {
  const r = summarizeOffline(sample());
  assert.equal(r.risk_level, "High");
  assert.match(r.summary, /^Archive utility \(commercial software\) was assessed for 250 users with 2 recommendations\./);
  assert.match(r.summary, /risk level is High, and Medium once the treatment plans are in place/);
  assert.match(r.summary, /1 recommendation still needs a treatment plan/);
  const flagged = summarizeOffline({ ...sample(), nercImpact: "Yes", aiCapability: "Yes", recommendations: [] });
  assert.match(flagged.summary, /NERC CIP applies and it has AI capability/);
  assert.match(flagged.summary, /No recommendations have been recorded yet/);
  assert.equal(summarizeOffline({ ...blankAssessment(), inherentRisk: "Low" }).risk_level, "Low");
});

test("an assessment from the earlier template becomes a summary report", () => {
  const old = {
    id: "A-003", solution: "ChatGPT Enterprise", status: "Approved", inherentRisk: "Critical", outcome: "No objection with conditions",
    findings: [{ description: "Prompts retained by vendor", businessImpact: "5", likelihood: "4", existingControls: "DPA signed", recommendation: "Ask for zero retention", residual: "Medium", registerId: "R-012" },
      { description: "No SSO", businessImpact: "2", likelihood: "2", recommendation: "Turn on SSO", residual: "Low" }],
    recommendations: [{ recommendation: "Zero data retention", finding: "R1", owner: "Dana" }, { recommendation: "Review in a year", finding: "", owner: "Dana", target: "2027-01-01" }],
  };
  const a = upgradeAssessment(old);
  assert.equal(a.template, 2);
  assert.equal(a.status, "Final");
  assert.equal(a.inherentRisk, "Very High");
  assert.equal(a.recommendations.length, 3);
  assert.deepEqual({ ...a.recommendations[0] }, { domain: "", recommendation: "Risk: Prompts retained by vendor\nZero data retention", inherent: "Very High", strategy: "",
    treatment: "Existing controls: DPA signed", residual: "Medium", registerId: "R-012" });
  assert.equal(a.recommendations[1].recommendation, "Risk: No SSO\nTurn on SSO");
  assert.equal(a.recommendations[1].inherent, "Low");
  assert.equal(a.recommendations[2].recommendation, "Review in a year");
  assert.equal(a.recommendations[2].treatment, "Owner: Dana; Due: 2027-01-01");
  assert.equal(a.handoff.length, 10);
  assert.equal(a.findings.length, 2, "the earlier answers stay on the record");
  assert.equal(a.outcome, "No objection with conditions");
  assert.equal(upgradeAssessment({ status: "In review" }).status, "Draft");
  assert.equal(upgradeAssessment(a), a, "already in the summary report layout");
  const mine = sample();
  assert.equal(upgradeAssessment(mine), mine);
});

test("the PDF report follows the template and leaves out blank sections", () => {
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const a = { ...sample(), scope: "Pilot for <b>finance</b>", status: "Final", inherentRisk: "Very High" };
  a.handoff[1].contact = "Pat Jones";
  const html = reportHtml(a, { esc, org: "Acme", id: "A-007" });
  for (const s of ["Adhoc Risk Assessment Summary Report – FINAL", "Archive utility", "A-007", "Acme", "Sam Lee", "250 users", "Freeware", "Request / scope",
    "Pilot for &lt;b&gt;finance&lt;/b&gt;", "Software functionality", "<li>Tampered installer</li>", "Recommendations / actions", "Patch management", "Add to third-party patching",
    "Risk response strategy", "Due 1 Dec", '<span class="pr-badge critical">Very High</span>', '<span class="pr-badge low">Low</span>',
    "Next steps / implementation hand-off", esc(HANDOFF_NOTE), "Installation support", "Pat Jones", "Risk register"]) assert.ok(html.includes(s), s);
  assert.ok(!html.includes("Assessment summary"), "blank sections are left out");
  assert.ok(!html.includes("<b>finance</b>"), "answers are escaped");
  assert.ok(reportHtml(blankAssessment(), { esc }).includes("Summary Report – DRAFT"));
});
