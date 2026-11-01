// Ad-hoc risk assessments: the AI summary prompt and the offline summary rules.
// Run with: node --test tests/assessments.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { assessmentPrompt, summarizeOffline, blankAssessment, findingInherent, FINAL_STATEMENT } from "../assessments.js";

const sample = () => ({
  ...blankAssessment(), solution: "ChatGPT Enterprise", assessmentType: "AI tool assessment",
  cloudChecks: { sso: { status: "Yes", comment: "Entra ID" }, mfa: { status: "No" } },
  nercAnswers: { bcsi: { status: "No" } },
  findings: [{ description: "Prompts retained by vendor", businessImpact: "4", likelihood: "4", residual: "Medium" }],
  recommendations: [{ recommendation: "Zero data retention", finding: "R1", status: "Open" }],
  dependencyRows: [{ team: "IAM", dependency: "SSO set-up" }],
});

test("finding inherent risk comes from likelihood × business impact", () => {
  assert.equal(findingInherent({ likelihood: "4", businessImpact: "4" }), "High");
  assert.equal(findingInherent({ likelihood: "5", businessImpact: "4" }), "Critical");
  assert.equal(findingInherent({ likelihood: "1", businessImpact: "2" }), "Low");
});

test("the prompt carries the earlier answers", () => {
  const p = assessmentPrompt(sample());
  for (const s of ["ChatGPT Enterprise", "SSO available Yes – Entra ID", "MFA available No", "BCSI? No", "R1: Prompts retained by vendor",
    "inherent High", "residual Medium", "Zero data retention", "IAM: SSO set-up", FINAL_STATEMENT]) assert.ok(p.includes(s), s);
});

test("offline rules: conditions, reviews and risk levels", () => {
  const r = summarizeOffline(sample());
  assert.equal(r.inherent_risk, "High");
  assert.equal(r.residual_risk, "Medium");
  assert.equal(r.outcome, "No objection with conditions");
  assert.equal(r.risk_acceptance_required, "No");
  assert.equal(r.cloud_review_required, "Yes"); // MFA not available
  assert.equal(r.ai_review_required, "Yes");
  assert.equal(r.ot_review_required, "No");
  assert.equal(r.nerc_review_required, "No");
  assert.equal(r.dependencies_identified, "Yes");
  assert.equal(r.final_statement, FINAL_STATEMENT);
});

test("offline rules: critical residual risk is an objection", () => {
  const a = { ...sample(), findings: [{ description: "x", businessImpact: "5", likelihood: "5", residual: "Critical" }], nercAnswers: { bes: { status: "Yes" } } };
  const r = summarizeOffline(a);
  assert.equal(r.outcome, "Objection – not approved");
  assert.equal(r.risk_acceptance_required, "Yes");
  assert.equal(r.nerc_review_required, "Yes");
  assert.match(r.final_statement, /objects/);
});

test("offline comments read naturally", () => {
  const first = (t) => summarizeOffline({ ...blankAssessment(), solution: "X", assessmentType: t }).comments.split(" with ")[0];
  assert.equal(first("AI tool assessment"), "X was assessed as an AI tool assessment");
  assert.equal(first("Infrastructure assessment"), "X was assessed as an infrastructure assessment");
  assert.equal(first("Cloud / SaaS assessment"), "X was assessed as a cloud / SaaS assessment");
  assert.equal(first("OT / ICS assessment"), "X was assessed as an OT / ICS assessment");
});
