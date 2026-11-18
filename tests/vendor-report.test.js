// The vendor risk report printed to PDF from the Vendors tab.
import { test } from "node:test";
import assert from "node:assert/strict";
import { vendorReportHtml } from "../vendors.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const vendor = {
  name: "NetOps MSP", service: "Managed network & firewall services", owner: "Network Team", status: "Active",
  criticality: "Critical", dataSensitivity: "Confidential", access: "Privileged / admin", lastAssessed: "2025-02-01",
  answers: { policy: "Yes", cert: "No", mfa: "Partial", notify: "No" },
  notes: "Shared admin accounts used by MSP engineers.",
};

test("the report shows the vendor, its tiers and the controls", () => {
  const html = vendorReportHtml(vendor, { esc, org: "Acme Corp", id: "V-002" });
  assert.match(html, /Vendor Risk Report · V-002/);
  assert.match(html, /<h1>NetOps MSP<\/h1>/);
  assert.match(html, /Acme Corp/);
  assert.match(html, /Inherent tier<\/small><span class="pr-badge critical">Critical<\/span>/);
  assert.match(html, /Enforces MFA for all staff and administrative access <span class="pr-pill">Key control<\/span><\/td><td><span class="pr-pill">Partial<\/span>/);
  assert.match(html, /Not answered/);
  assert.match(html, /Notes and evidence/);
  assert.match(html, /overdue/);
});

test("blank sections are left out", () => {
  const html = vendorReportHtml({ name: "Snacks Co", criticality: "Low", dataSensitivity: "None", access: "None", answers: {} }, { esc, id: "V-004" });
  for (const absent of ["AI vendor review", "Intake questionnaire", "Vendor contacts", "Notes and evidence"]) assert.doesNotMatch(html, new RegExp(absent));
  assert.match(html, /Posture\.ai/);
});

test("the AI review, intake flags, contacts and custom fields appear when present", () => {
  const html = vendorReportHtml({
    ...vendor,
    aiAssessment: { risk_tier: "High", recommendation: "Approve with conditions", summary: "Privileged access with weak controls.", strengths: ["Encrypts data"],
      gaps: [{ gap: "No MFA for admins", severity: "High", remediation: "Enforce MFA" }], contract_clauses: ["72-hour breach notice"], follow_up_questions: ["Do you have SOC 2?"], at: "2026-11-01T10:00:00Z" },
    intake: { format: "riskpilot-intake", version: 1, submittedAt: "2026-10-30T09:00:00Z", attested: true, profile: { contactName: "Pat Lee", certifications: ["ISO/IEC 27001"] },
      answers: { IAM2: { answer: "No", comment: "Rolling out MFA by Q1" } } },
    contacts: [{ name: "Pat Lee", title: "CISO", email: "pat@netops.example", state: "Active" }],
    custom: { f1: "MSA-2024-17" },
  }, { esc, id: "V-002", sections: [{ id: "s1", name: "Contract", fields: [{ id: "f1", label: "Contract number" }, { id: "f2", label: "Empty field" }] }] });
  assert.match(html, /AI vendor review/);
  assert.match(html, /Approve with conditions/);
  assert.match(html, /No MFA for admins<\/td><td>Enforce MFA/);
  assert.match(html, /72-hour breach notice/);
  assert.match(html, /Intake questionnaire/);
  assert.match(html, /Pat Lee/);
  assert.match(html, /Rolling out MFA by Q1/);
  assert.match(html, /pat@netops\.example/);
  assert.match(html, /Contract number<\/th><td>MSA-2024-17/);
  assert.doesNotMatch(html, /Empty field/);
});

test("vendor-supplied text is escaped", () => {
  const html = vendorReportHtml({ ...vendor, name: "<img src=x onerror=alert(1)>", notes: "<script>x</script>",
    contacts: [{ name: "\"><svg onload=alert(1)>" }] }, { esc, id: "V-9" });
  assert.doesNotMatch(html, /<img src=x|<script>x|<svg onload/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});
