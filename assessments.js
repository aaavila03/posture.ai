// Ad-hoc risk assessments: a cybersecurity review of one solution or technology, following
// the assessment template – executive summary, scope and evidence, data handling, security /
// cloud / AI / OT / NERC CIP considerations, findings, recommendations, determination,
// conditions, follow-up actions, sign-off and a final summary. Findings can be sent to the
// risk register.

import { logoImg } from "./logo.js";

export const ASSESSMENT_TYPES = ["AI tool assessment", "Cloud / SaaS assessment", "Software / application assessment", "Integration assessment",
  "Infrastructure assessment", "OT / ICS assessment", "Third-party / vendor assessment", "Other"];
export const OUTCOMES = ["Pending", "No objection", "No objection with conditions", "Objection – not approved"];
export const STATUSES = ["Draft", "In review", "Approved", "Closed"];
const LEVELS = ["Low", "Medium", "High", "Critical"];
const YN = ["Yes", "No"];
const YNU = ["Yes", "No", "Unknown"];
const LIKELIHOOD = ["1. Rare", "2. Unlikely", "3. Possible", "4. Likely", "5. Almost certain"];
const IMPACT = ["1. Very low", "2. Low", "3. Moderate", "4. High", "5. Very high"];
const PRIORITIES = ["High", "Medium", "Low"];
const ROW_STATUSES = ["Open", "In progress", "Done"];
const DATA_CLASSES = ["Public", "Internal", "Confidential", "Customer", "Employee", "Regulatory"];

const CLOUD_CHECKS = [["provider", "Cloud provider identified"], ["residency", "Data residency reviewed"], ["sso", "SSO available"],
  ["mfa", "MFA available"], ["encRest", "Encryption at rest"], ["encTransit", "Encryption in transit"], ["siem", "SIEM integration available"],
  ["vendorAccess", "Vendor access reviewed"], ["vuln", "Vulnerability management reviewed"], ["moreCloud", "Additional cloud review required"]];
const OT_QUESTIONS = [["ot", "OT connectivity?"], ["ics", "ICS connectivity?"], ["scada", "SCADA connectivity?"], ["opData", "Operational data access?"],
  ["otReview", "OT review required?"], ["engReview", "Engineering review required?"], ["nercReview", "NERC CIP review required?"]];
const NERC_QUESTIONS = [["bes", "Does the solution interact with BES Cyber Systems?"], ["bcsi", "Does the solution access, process, store or transmit BCSI?"],
  ["esp", "Does the solution impact an Electronic Security Perimeter (ESP)?"], ["erc", "Does the solution introduce External Routable Connectivity?"],
  ["applicable", "Is NERC CIP applicability anticipated?"], ["review", "Is a NERC CIP review required?"]];
const APPROVERS = [["reviewer", "Cybersecurity reviewer"], ["assetOwner", "Asset owner"], ["riskOwner", "Risk owner"], ["sponsor", "Business sponsor (optional)"]];

export const FINAL_STATEMENT = "Based on the information provided and the scope reviewed, Enterprise Cyber Risk does not object to the proposed implementation "
  + "provided the identified recommendations, conditions, and compensating controls are implemented. Any material change may require reassessment.";

// Narrative sections: [field, heading, what to cover].
const NARRATIVE = {
  info: ["Assessment information", "Document ownership and accountability, and any relevant business, technical, security, operational, compliance and risk information."],
  scope: ["Request and scope", "The business request, what's in scope and what's excluded. e.g. Review of an AI solution for employee productivity."],
  evidence: ["Assessment inputs and evidence reviewed", "SOC reports, questionnaires, interviews, product documentation. e.g. Reviewed SOC 2 Type II report and security questionnaire."],
  additionalInfo: ["Additional information reviewed", "Emails, clarifications, screenshots, meetings."],
  solutionOverview: ["Solution overview", "What the solution does and its business purpose."],
  dataHandling: ["Solution context and data handling", "Inputs, outputs, storage, processing and integrations."],
  businessImpact: ["Business impact considerations", "Confidentiality, integrity, availability, operational and reputational impacts."],
  security: ["Security considerations", "Identity and access, MFA, encryption, logging, monitoring, vendor controls."],
  cloud: ["Cloud considerations", "SaaS / PaaS / IaaS, Azure / AWS / GCP, data residency, cloud controls, shared responsibility model."],
  ai: ["AI considerations", "Model type, training, human oversight, explainability, prompt handling."],
  ot: ["OT / ICS considerations", "OT, ICS, SCADA, operational impact and reviews."],
  nerc: ["Regulatory and NERC CIP considerations", "BES, BCSI, ESP, external routable connectivity and NERC CIP applicability."],
  dependencies: ["Dependencies and required stakeholder engagement", "Identity, EDS, network, OT, legal and compliance dependencies."],
};
const WRITE_HINT = "Document observations, rationale, controls, gaps, risks, assumptions and conclusions.";

// Repeating rows: the blank row added by "+ Add".
const BLANK = {
  dependencyRows: () => ({ team: "", dependency: "", beforeImplementation: "", status: "" }),
  findings: () => ({ description: "", businessImpact: "3", likelihood: "3", existingControls: "", recommendation: "", residual: "", riskOwner: "" }),
  recommendations: () => ({ recommendation: "", finding: "", priority: "", owner: "", target: "", status: "Open" }),
  actions: () => ({ action: "", owner: "", due: "", status: "Open" }),
};

function rating(s) {
  if (s >= 20) return "Critical";
  if (s >= 12) return "High";
  if (s >= 6) return "Medium";
  return "Low";
}
export const findingInherent = (f) => rating((Number(f.likelihood) || 1) * (Number(f.impact ?? f.businessImpact) || 1));
const levelCls = (l) => String(l || "").toLowerCase();

// The earlier sections as text for the AI summary (everything before the final summary).
export function assessmentPrompt(a) {
  const yn = (group, list) => list.map(([k, q]) => `- ${q} ${a[group]?.[k]?.status || "(not answered)"}${a[group]?.[k]?.comment ? ` – ${a[group][k].comment}` : ""}`).join("\n");
  const notes = (key) => `${NARRATIVE[key][0]}:\n${a[key]?.trim() || "(blank)"}`;
  const lvl = (n, list) => list[Number(n) - 1] || "(not set)";
  return [
    `Solution / technology: ${a.solution || "(not named)"}`,
    `Assessment type: ${a.assessmentType || "(not set)"}; status: ${a.status || "Draft"}; date: ${a.assessmentDate || "(not set)"}`,
    `Asset owner: ${a.assetOwner || "(not set)"}; risk owner: ${a.riskOwner || "(not set)"}; reviewer: ${a.reviewer || "(not set)"}`,
    `Assessor's current outcome: ${a.outcome || "Pending"}; inherent risk: ${a.inherentRisk || "(not set)"}; residual risk: ${a.residualRisk || "(not set)"}`,
    `OT impact: ${a.otImpact || "(not set)"}; NERC CIP impact: ${a.nercImpact || "(not set)"}; additional compliance review: ${a.complianceReview || "(not set)"}`,
    `Top risks:\n${a.topRisks || "(blank)"}`, `Top recommendations:\n${a.topRecommendations || "(blank)"}`,
    ...["info", "scope", "evidence", "additionalInfo", "solutionOverview", "dataHandling"].map(notes),
    `Data classification: ${(a.dataClasses || []).join(", ") || "(none selected)"}${a.dataClassNotes ? ` – ${a.dataClassNotes}` : ""}`,
    notes("businessImpact"), notes("security"),
    `${notes("cloud")}\nCloud checklist:\n${yn("cloudChecks", CLOUD_CHECKS)}`,
    notes("ai"),
    `${notes("ot")}\nOT / ICS questions:\n${yn("otAnswers", OT_QUESTIONS)}`,
    `${notes("nerc")}\nNERC CIP questions:\n${yn("nercAnswers", NERC_QUESTIONS)}`,
    `${notes("dependencies")}\nDependencies:\n${(a.dependencyRows || []).map((d) => `- ${d.team || "?"}: ${d.dependency || "?"} (before implementation: ${d.beforeImplementation || "?"}; status: ${d.status || "?"})`).join("\n") || "(none)"}`,
    `Key findings:\n${(a.findings || []).map((f, i) => `- R${i + 1}: ${f.description || "(no description)"} | business impact ${lvl(f.businessImpact, IMPACT)}, likelihood ${lvl(f.likelihood, LIKELIHOOD)}, inherent ${findingInherent(f)} | existing controls: ${f.existingControls || "(none)"} | recommendation: ${f.recommendation || "(none)"} | residual ${f.residual || "(not set)"}`).join("\n") || "(none)"}`,
    `Recommendations:\n${(a.recommendations || []).map((r, i) => `- ${i + 1}. ${r.recommendation || "?"} (addresses ${r.finding || "?"}; priority ${r.priority || "?"}; status ${r.status || "?"}; target ${r.target || "?"})`).join("\n") || "(none)"}`,
    `Determination: conditions required ${a.conditionsRequired || "(not set)"}; risk acceptance required ${a.riskAcceptance || "(not set)"}; follow-up review required ${a.followUpReview || "(not set)"}${a.determinationComments ? `; comments: ${a.determinationComments}` : ""}`,
    `Conditions:\n${a.conditions || "(none)"}`, `Assumptions:\n${a.assumptions || "(none)"}`,
    `Follow-up actions:\n${(a.actions || []).map((x) => `- ${x.action || "?"} (${x.status || "?"}, due ${x.due || "?"})`).join("\n") || "(none)"}`,
    `Assessor's existing final statement:\n${a.finalStatement || FINAL_STATEMENT}`,
    "",
    "Complete the final assessment summary from these answers.",
  ].join("\n\n");
}

// Demo mode without an API key: the same summary worked out from simple rules.
export function summarizeOffline(a) {
  const yes = (group, keys) => keys.some((k) => a[group]?.[k]?.status === "Yes");
  const findings = a.findings || [];
  const top = (vals) => vals.filter(Boolean).sort((x, y) => LEVELS.indexOf(y) - LEVELS.indexOf(x))[0];
  const inherent = top(findings.map(findingInherent)) || a.inherentRisk || "Medium";
  const residual = top(findings.map((f) => f.residual)) || a.residualRisk || inherent;
  const open = (a.recommendations || []).some((r) => r.status !== "Done") || !!a.conditions?.trim() || a.conditionsRequired === "Yes";
  const cloudGaps = CLOUD_CHECKS.slice(0, 9).some(([k]) => a.cloudChecks?.[k]?.status === "No");
  const r = {
    inherent_risk: inherent, residual_risk: residual,
    risk_acceptance_required: ["High", "Critical"].includes(residual) ? "Yes" : "No",
    compliance_review_required: a.complianceReview === "Yes" || (a.dataClasses || []).includes("Regulatory") ? "Yes" : "No",
    cloud_review_required: yes("cloudChecks", ["moreCloud"]) || cloudGaps ? "Yes" : "No",
    ai_review_required: /ai/i.test(a.assessmentType || "") || !!a.ai?.trim() ? "Yes" : "No",
    ot_review_required: a.otImpact === "Yes" || yes("otAnswers", ["ot", "ics", "scada", "opData", "otReview", "engReview"]) ? "Yes" : "No",
    nerc_review_required: a.nercImpact === "Yes" || yes("otAnswers", ["nercReview"]) || yes("nercAnswers", NERC_QUESTIONS.map(([k]) => k)) ? "Yes" : "No",
    dependencies_identified: (a.dependencyRows || []).length || a.dependencies?.trim() ? "Yes" : "No",
  };
  r.outcome = residual === "Critical" ? "Objection – not approved" : open || r.risk_acceptance_required === "Yes" ? "No objection with conditions" : "No objection";
  const reviews = [["cloud", r.cloud_review_required], ["AI", r.ai_review_required], ["OT", r.ot_review_required], ["NERC CIP", r.nerc_review_required]]
    .filter(([, v]) => v === "Yes").map(([n]) => n);
  r.comments = `${a.solution || "The solution"} was assessed${a.assessmentType ? ` as ${/^[aeiou]/i.test(a.assessmentType) ? "an" : "a"} ${a.assessmentType.replace(/^(?!AI|OT)./, (c) => c.toLowerCase())}` : ""} with ${findings.length} finding${findings.length === 1 ? "" : "s"}; `
    + `inherent risk is ${inherent} and residual risk ${residual}. `
    + (reviews.length ? `Further ${reviews.length > 1 ? `${reviews.slice(0, -1).join(", ")} and ${reviews.at(-1)}` : reviews[0]} review${reviews.length === 1 ? " is" : "s are"} required. ` : "No further specialist reviews were identified. ")
    + (open ? "Open recommendations and conditions must be met before implementation." : "");
  r.final_statement = r.outcome === "Objection – not approved"
    ? "Based on the information provided and the scope reviewed, Enterprise Cyber Risk objects to the proposed implementation. It should not proceed until the identified risks are addressed and the solution is reassessed."
    : a.finalStatement || FINAL_STATEMENT;
  r.rationale = "Worked out from simple rules (no AI): the highest finding sets the risk levels, and any Yes answer or gap in the cloud, AI, OT and NERC CIP sections flags that review.";
  return r;
}

// ---------- PDF report ----------
// A print-ready report of one assessment (printed to PDF with the browser's "Save as PDF").
// Blank sections are left out so the report reads as a finished document.
export function reportHtml(a, { esc, org = "", logo = "", id = "", generated = new Date() }) {
  const has = (v) => (Array.isArray(v) ? v.length > 0 : typeof v === "string" ? v.trim() !== "" : v != null);
  const para = (t) => esc(t).split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
  const lines = (t) => String(t || "").split("\n").map((l) => l.replace(/^\s*[-•·*]\s*/, "").trim()).filter(Boolean);
  const bullets = (t) => `<ul>${lines(t).map((l) => `<li>${esc(l)}</li>`).join("")}</ul>`;
  const badge = (v, cls = levelCls(v)) => (v ? `<span class="pr-badge ${cls}">${esc(v)}</span>` : '<span class="pr-muted">–</span>');
  const yn = (v) => (v === "Yes" ? '<span class="pr-pill yes">Yes</span>' : v === "No" ? '<span class="pr-pill no">No</span>' : v ? `<span class="pr-pill">${esc(v)}</span>` : '<span class="pr-muted">Not answered</span>');
  const outcomeCls = (o) => (/^No objection$/.test(o) ? "low" : /conditions/.test(o) ? "medium" : /Objection/.test(o) ? "critical" : "neutral");
  const date = (d) => (d ? new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : "");
  const fact = (label, v) => `<div class="pr-fact"><div class="pr-label">${label}</div><div>${v || '<span class="pr-muted">–</span>'}</div></div>`;
  let n = 0;
  const sec = (title, inner) => (inner ? `<section class="pr-section"><h2><span class="pr-num">${++n}</span>${esc(title)}</h2>${inner}</section>` : "");
  const narrative = (key, extra = "") => sec(NARRATIVE[key][0], (has(a[key]) ? para(a[key]) : "") + extra);
  const qTable = (group, list, head) => {
    const rows = list.filter(([k]) => a[group]?.[k]?.status || a[group]?.[k]?.comment);
    return rows.length ? `<table class="pr-table"><thead><tr><th>${head}</th><th class="pr-narrow">Response</th><th>Comments</th></tr></thead><tbody>
      ${rows.map(([k, q]) => `<tr><td>${esc(q)}</td><td>${yn(a[group][k].status)}</td><td>${esc(a[group][k].comment || "")}</td></tr>`).join("")}</tbody></table>` : "";
  };
  const table = (cols, rows) => (rows.length ? `<table class="pr-table"><thead><tr>${cols.map(([h, , cls]) => `<th class="${cls || ""}">${h}</th>`).join("")}</tr></thead>
    <tbody>${rows.map((r, i) => `<tr>${cols.map(([, f]) => `<td>${f(r, i)}</td>`).join("")}</tr>`).join("")}</tbody></table>` : "");
  const findings = a.findings || [];
  const lvl = (v, list) => list[Number(v) - 1]?.replace(/^\d\. /, "") || "–";
  const signers = APPROVERS.filter(([k]) => k !== "sponsor" || has(a.approvals?.sponsor?.name));

  return `<article class="pr-doc">
    <header class="pr-cover">
      <div class="pr-cover-top"><span class="pr-brand">${logo}<span>${esc(org || "Posture.ai")}</span></span><span>Ad-Hoc Risk Assessment · ${esc(id)}</span></div>
      <div class="pr-eyebrow">${esc(a.assessmentType || "Cybersecurity risk assessment")}</div>
      <h1>${esc(a.solution || "Untitled assessment")}</h1>
      <div class="pr-cover-meta">${[date(a.assessmentDate), a.status && `Status: ${a.status}`].filter(Boolean).map(esc).join(" · ")}</div>
      <div class="pr-verdict">
        <div class="pr-verdict-item"><small>Assessment outcome</small>${badge(a.outcome || "Pending", outcomeCls(a.outcome || ""))}</div>
        <div class="pr-verdict-item"><small>Inherent risk</small>${badge(a.inherentRisk)}</div>
        <div class="pr-verdict-item"><small>Residual risk</small>${badge(a.residualRisk)}</div>
      </div>
    </header>

    <section class="pr-section pr-summary">
      <h2>Executive summary</h2>
      <div class="pr-facts">
        ${fact("Solution / technology", esc(a.solution))}${fact("Assessment type", esc(a.assessmentType))}
        ${fact("Asset owner", esc(a.assetOwner))}${fact("Risk owner", esc(a.riskOwner))}
        ${fact("Cybersecurity reviewer", esc(a.reviewer))}${fact("Assessment date", esc(date(a.assessmentDate)))}
        ${fact("OT impact", yn(a.otImpact))}${fact("NERC CIP impact", yn(a.nercImpact))}
        ${fact("Additional compliance review", yn(a.complianceReview))}
      </div>
      ${has(a.summaryComments) ? `<div class="pr-callout">${para(a.summaryComments)}</div>` : ""}
      ${has(a.topRisks) || has(a.topRecommendations) ? `<div class="pr-two">
        <div><h3>Top risks</h3>${has(a.topRisks) ? bullets(a.topRisks) : '<p class="pr-muted">–</p>'}</div>
        <div><h3>Top recommendations</h3>${has(a.topRecommendations) ? bullets(a.topRecommendations) : '<p class="pr-muted">–</p>'}</div></div>` : ""}
      <p class="pr-notice">Review the complete assessment below for detailed findings and recommendations.</p>
    </section>

    ${["info", "scope", "evidence", "additionalInfo", "solutionOverview", "dataHandling"].map((k) => narrative(k)).join("")}
    ${sec("Data classification review", (has(a.dataClasses) ? `<p class="pr-chips">${DATA_CLASSES.map((c) => `<span class="pr-chip ${(a.dataClasses || []).includes(c) ? "on" : ""}">${(a.dataClasses || []).includes(c) ? "✓ " : ""}${c}</span>`).join("")}</p>` : "") + (has(a.dataClassNotes) ? para(a.dataClassNotes) : ""))}
    ${narrative("businessImpact")}${narrative("security")}
    ${narrative("cloud", qTable("cloudChecks", CLOUD_CHECKS, "Cloud security area"))}
    ${narrative("ai")}
    ${narrative("ot", qTable("otAnswers", OT_QUESTIONS, "Question"))}
    ${narrative("nerc", qTable("nercAnswers", NERC_QUESTIONS, "Question"))}
    ${narrative("dependencies", table([["Team", (r) => esc(r.team)], ["Dependency", (r) => esc(r.dependency)],
      ["Before implementation", (r) => yn(r.beforeImplementation), "pr-narrow"], ["Status", (r) => esc(r.status), "pr-narrow"]], a.dependencyRows || []))}
    ${sec("Key findings and risks", findings.map((f, i) => `<div class="pr-finding">
        <div class="pr-finding-head"><span class="pr-id">R${i + 1}</span><strong>${esc(f.description || "(no description)")}</strong></div>
        <div class="pr-finding-scores">
          <span>Business impact <b>${esc(lvl(f.businessImpact, IMPACT))}</b></span><span>Likelihood <b>${esc(lvl(f.likelihood, LIKELIHOOD))}</b></span>
          <span>Inherent ${badge(findingInherent(f))}</span><span>Residual ${badge(f.residual)}</span>${f.riskOwner ? `<span>Owner <b>${esc(f.riskOwner)}</b></span>` : ""}
          ${f.registerId ? `<span>Register <b>${esc(f.registerId)}</b></span>` : ""}
        </div>
        <div class="pr-two">
          <div><div class="pr-label">Existing controls</div>${has(f.existingControls) ? para(f.existingControls) : '<p class="pr-muted">None listed</p>'}</div>
          <div><div class="pr-label">Recommendation</div>${has(f.recommendation) ? para(f.recommendation) : '<p class="pr-muted">None listed</p>'}</div>
        </div></div>`).join(""))}
    ${sec("Recommendations", table([["#", (r, i) => i + 1, "pr-narrow"], ["Recommendation", (r) => esc(r.recommendation)], ["Risk addressed", (r) => esc(r.finding), "pr-narrow"],
      ["Priority", (r) => (r.priority ? badge(r.priority, { High: "high", Medium: "medium", Low: "low" }[r.priority]) : ""), "pr-narrow"], ["Owner", (r) => esc(r.owner)],
      ["Target date", (r) => esc(date(r.target)), "pr-narrow"], ["Status", (r) => esc(r.status), "pr-narrow"]], a.recommendations || []))}
    ${sec("Cybersecurity risk determination", `<div class="pr-facts">
        ${fact("Determination", badge(a.outcome || "Pending", outcomeCls(a.outcome || "")))}${fact("Inherent risk", badge(a.inherentRisk))}${fact("Residual risk", badge(a.residualRisk))}
        ${fact("Conditions required", yn(a.conditionsRequired))}${fact("Risk acceptance required", yn(a.riskAcceptance))}${fact("Follow-up review required", yn(a.followUpReview))}
      </div>${has(a.determinationComments) ? para(a.determinationComments) : ""}`)}
    ${sec("Conditions and assumptions", has(a.conditions) || has(a.assumptions) ? `<div class="pr-two">
        <div><h3>Conditions</h3>${has(a.conditions) ? bullets(a.conditions) : '<p class="pr-muted">None</p>'}</div>
        <div><h3>Assumptions</h3>${has(a.assumptions) ? bullets(a.assumptions) : '<p class="pr-muted">None</p>'}</div></div>` : "")}
    ${sec("Follow-up actions", table([["Action item", (r) => esc(r.action)], ["Responsible owner", (r) => esc(r.owner)], ["Due date", (r) => esc(date(r.due)), "pr-narrow"],
      ["Status", (r) => esc(r.status), "pr-narrow"]], a.actions || []))}
    <section class="pr-section pr-final">
      <h2><span class="pr-num">${++n}</span>Final assessment summary</h2>
      <div class="pr-facts">
        ${fact("Assessment outcome", badge(a.outcome || "Pending", outcomeCls(a.outcome || "")))}${fact("Inherent risk", badge(a.inherentRisk))}${fact("Residual risk", badge(a.residualRisk))}
        ${fact("Cloud review required", yn(a.cloudReview))}${fact("AI review required", yn(a.aiReview))}${fact("OT review required", yn(a.otReview))}
        ${fact("NERC CIP review required", yn(a.nercReview))}${fact("Risk acceptance required", yn(a.riskAcceptance))}${fact("Additional compliance review", yn(a.complianceReview))}
        ${fact("Dependencies identified", yn(a.dependenciesIdentified))}
      </div>
      ${has(a.summaryComments) ? `<h3>Comments</h3>${para(a.summaryComments)}` : ""}
      <blockquote class="pr-statement"><div class="pr-label">Final statement</div>${para(a.finalStatement || FINAL_STATEMENT)}</blockquote>
    </section>
    <section class="pr-section pr-signoff">
      <h2><span class="pr-num">${++n}</span>Approval and sign-off</h2>
      <table class="pr-table pr-sign"><thead><tr><th>Role</th><th>Name</th><th>Title</th><th class="pr-narrow">Approval date</th><th>Signature</th></tr></thead><tbody>
        ${signers.map(([k, role]) => { const s = a.approvals?.[k] || {}; return `<tr><td><strong>${esc(role.replace(" (optional)", ""))}</strong></td><td>${esc(s.name || "")}</td><td>${esc(s.title || "")}</td>
          <td>${esc(date(s.date))}${s.approved === "Yes" ? ' <span class="pr-pill yes">Approved</span>' : ""}</td><td class="pr-sigline"></td></tr>`; }).join("")}
      </tbody></table>
    </section>
    <footer class="pr-foot">${esc(org ? `${org} · ` : "")}Confidential · ${esc(id)} · Generated ${esc(generated.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }))} with Posture.ai</footer>
  </article>`;
}

export function blankAssessment() {
  return { status: "Draft", outcome: "Pending", assessmentDate: new Date().toISOString().slice(0, 10), finalStatement: FINAL_STATEMENT,
    dataClasses: [], cloudChecks: {}, otAnswers: {}, nercAnswers: {}, approvals: {},
    dependencyRows: [], findings: [], recommendations: [], actions: [] };
}

const getPath = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
function setPath(obj, path, value) {
  const keys = path.split(".");
  let o = obj;
  for (const k of keys.slice(0, -1)) o = o[k] ??= {};
  o[keys.at(-1)] = value;
}

export function initAssessments({ $, $$, escapeHtml: esc, toast, initial, persist, canEdit, ownerNames, findPerson, scope, addRegisterRisk, onChange, commenter, getAI, afterAI, getOrgName = () => "", getLogo = () => null }) {
  let list = initial || [];
  let draft = null, editingId = null, snapshot = "";
  const dialog = $("#assessment-dialog");
  const body = $("#assessment-body");
  // On wide screens an assessment opens beside the list (split view), like risks and vendors;
  // on phones and tablets it opens as a full dialog.
  const splitView = window.matchMedia("(min-width: 1100px)");

  const nextId = () => `A-${String(list.reduce((m, a) => Math.max(m, Number(String(a.id).replace(/\D/g, "")) || 0), 0) + 1).padStart(3, "0")}`;
  const save = () => { persist(list); onChange?.(); };

  // ---------- list ----------
  function render() {
    const q = $("#assessment-search").value.toLowerCase();
    const st = $("#assessment-status-filter").value, out = $("#assessment-outcome-filter").value;
    const base = scope(list);
    const rows = base
      .filter((a) => !q || JSON.stringify(a).toLowerCase().includes(q))
      .filter((a) => !st || a.status === st)
      .filter((a) => !out || a.outcome === out)
      .sort((a, b) => String(b.assessmentDate || "").localeCompare(String(a.assessmentDate || "")) || b.id.localeCompare(a.id));
    $("#assessment-table tbody").innerHTML = rows.map((a) => `<tr class="${dialog.open && editingId === a.id ? "selected" : ""}">
        <td>${esc(a.id)}</td>
        <td><button type="button" class="link row-name" data-assessment="${esc(a.id)}">${esc(a.solution || "(untitled)")}</button><div class="muted small">${esc(a.assessmentType)}</div></td>
        <td>${esc(a.riskOwner)}</td>
        <td>${esc(a.outcome)}</td>
        <td>${a.inherentRisk ? `<span class="badge ${levelCls(a.inherentRisk)}">${esc(a.inherentRisk)}</span>` : ""}</td>
        <td>${a.residualRisk ? `<span class="badge ${levelCls(a.residualRisk)}">${esc(a.residualRisk)}</span>` : ""}</td>
        <td>${esc(a.status)}</td>
        <td class="nowrap">${esc(a.assessmentDate)}</td>
        <td><button class="small" data-assessment="${esc(a.id)}">${canEdit() ? "Edit" : "View"}</button></td>
      </tr>`).join("");
    $("#empty-assessments").classList.toggle("hidden", rows.length > 0);
    $("#empty-assessments").textContent = base.length ? "No assessments match."
      : list.length ? "None of the assessments list you as the risk owner. Untick “Only risks I own” to see them all."
      : "No assessments yet. Click “+ New assessment” to start one from the template.";
    $("#assessment-count").textContent = rows.length === base.length ? `${base.length} assessment${base.length === 1 ? "" : "s"}` : `Showing ${rows.length} of ${base.length} assessments`;
  }
  $("#assessment-search").addEventListener("input", render);
  $("#assessment-status-filter").addEventListener("change", render);
  $("#assessment-outcome-filter").addEventListener("change", render);

  // ---------- editor fields ----------
  const val = (path) => getPath(draft, path) ?? "";
  const opts = (choices, current, blank = "–") => `${blank === null ? "" : `<option value="">${blank}</option>`}${choices.map((c) => {
    const [v, label] = Array.isArray(c) ? c : [c, c];
    return `<option value="${esc(v)}" ${String(v) === String(current) ? "selected" : ""}>${esc(label)}</option>`;
  }).join("")}`;
  const text = (path, label, extra = "") => `<label ${extra}>${label} <input data-path="${path}" value="${esc(val(path))}" maxlength="500" /></label>`;
  const date = (path, label) => `<label>${label} <input type="date" data-path="${path}" value="${esc(val(path))}" /></label>`;
  const area = (path, label, placeholder = "", rows = 4) => `<label class="full">${label} <textarea data-path="${path}" rows="${rows}" placeholder="${esc(placeholder)}">${esc(val(path))}</textarea></label>`;
  const select = (path, label, choices, extra = "") => `<label ${extra}>${label} <select data-path="${path}">${opts(choices, val(path))}</select></label>`;
  // Owner fields: a pick list of the directory and members (free text until there's anyone to pick).
  const owner = (path, label, extra = "") => {
    const names = ownerNames(), v = val(path);
    if (!names.length) return text(path, label, extra);
    const choices = names.map((n) => [n, n]);
    if (v && !names.includes(v)) choices.push([v, `${v} (not in directory)`]);
    return `<label ${extra}>${label} <select data-path="${path}" data-owner>${opts(choices, v)}</select></label>`;
  };
  const section = (title, inner, open = false) => `<details class="form-section-details assess-section" ${open ? "open" : ""}><summary>${title}</summary>${inner}</details>`;
  const narrative = (key, extra = "") => {
    const [title, hint] = NARRATIVE[key];
    return section(title, `<p class="muted small">${esc(hint)}</p><div class="form-grid">${area(key, "Notes", WRITE_HINT, 5)}${extra}</div>`);
  };
  const question = (group, [key, q], choices = YN) => `<div class="assess-q"><span>${esc(q)}</span>
      <select data-path="${group}.${key}.status" aria-label="${esc(q)}">${opts(choices, val(`${group}.${key}.status`))}</select>
      <input data-path="${group}.${key}.comment" value="${esc(val(`${group}.${key}.comment`))}" placeholder="Comments" maxlength="500" aria-label="Comments" /></div>`;
  const rowsBlock = (kind, title, fields, addLabel) => `<div class="assess-rows">${(draft[kind] || []).map((r, i) => `
      <div class="assess-row"><div class="assess-row-head"><strong>${title(r, i)}</strong>${extraRowHead(kind, r, i)}
        <button type="button" class="link danger edit-only" data-remove="${kind}.${i}" aria-label="Remove">✕</button></div>
        <div class="form-grid">${fields(i, r)}</div></div>`).join("") || '<p class="muted small">None yet.</p>'}
      <button type="button" class="small edit-only" data-add="${kind}">+ ${addLabel}</button></div>`;
  const extraRowHead = (kind, r, i) => {
    if (kind !== "findings") return "";
    const lvl = findingInherent(r);
    return ` <span class="badge ${levelCls(lvl)}" data-finding-level="${i}">Inherent: ${lvl}</span>
      ${r.registerId ? `<span class="tag">In register: ${esc(r.registerId)}</span>` : `<button type="button" class="small edit-only" data-to-register="${i}">Send to risk register</button>`}`;
  };
  const findingLabel = (i) => `R${i + 1}`;

  const findingChoices = () => (draft.findings || []).map((f, k) => [findingLabel(k), `${findingLabel(k)}${f.description ? ` – ${f.description.slice(0, 60)}` : ""}`]);

  function renderBody() {
    const findings = draft.findings || [];
    body.innerHTML = [
      section("Executive summary", `<div class="form-grid">
        <label class="full">Solution / technology <input data-path="solution" value="${esc(val("solution"))}" required maxlength="200" placeholder="e.g. ChatGPT Enterprise, Microsoft Copilot, CrowdStrike Falcon, OT monitoring platform" /></label>
        ${select("assessmentType", "Assessment type", ASSESSMENT_TYPES)}
        ${select("status", "Status", STATUSES)}
        ${owner("assetOwner", "Asset owner")}
        ${owner("riskOwner", "Risk owner")}
        ${owner("reviewer", "Cybersecurity reviewer")}
        ${date("assessmentDate", "Assessment date")}
        ${select("outcome", "Assessment outcome", OUTCOMES)}
        ${select("complianceReview", "Additional compliance review required", YN)}
        ${select("inherentRisk", "Inherent risk", LEVELS)}
        ${select("residualRisk", "Residual risk", LEVELS)}
        <p class="full small muted" id="assess-hint"></p>
        ${select("otImpact", "OT impact", YNU)}
        ${select("nercImpact", "NERC CIP impact", YNU)}
        ${area("topRisks", "Top risks", "One per line", 3)}
        ${area("topRecommendations", "Top recommendations", "One per line", 3)}
      </div>`, true),
      narrative("info"), narrative("scope"), narrative("evidence"), narrative("additionalInfo"), narrative("solutionOverview"), narrative("dataHandling"),
      section("Data classification review", `<p class="muted small">Which kinds of data the solution handles.</p>
        <fieldset class="checks">${DATA_CLASSES.map((c) => `<label><input type="checkbox" data-class="${c}" ${(draft.dataClasses || []).includes(c) ? "checked" : ""} /> ${c}</label>`).join("")}</fieldset>
        <div class="form-grid">${area("dataClassNotes", "Notes", WRITE_HINT, 3)}</div>`),
      narrative("businessImpact"), narrative("security"),
      narrative("cloud", `<div class="full assess-qs"><div class="assess-q head"><span>Cloud security area</span><span>Status</span><span>Comments</span></div>${CLOUD_CHECKS.map((q) => question("cloudChecks", q)).join("")}</div>`),
      narrative("ai"),
      narrative("ot", `<div class="full assess-qs"><div class="assess-q head"><span>Question</span><span>Response</span><span>Comments</span></div>${OT_QUESTIONS.map((q) => question("otAnswers", q)).join("")}</div>`),
      narrative("nerc", `<div class="full assess-qs"><div class="assess-q head"><span>Question</span><span>Response</span><span>Comments</span></div>${NERC_QUESTIONS.map((q) => question("nercAnswers", q)).join("")}</div>`),
      narrative("dependencies", `<div class="full">${rowsBlock("dependencyRows", (r) => esc(r.team || "Dependency"), (i) => `
        ${text(`dependencyRows.${i}.team`, "Team")}${text(`dependencyRows.${i}.dependency`, "Dependency")}
        ${select(`dependencyRows.${i}.beforeImplementation`, "Required before implementation", YN)}${select(`dependencyRows.${i}.status`, "Status", ROW_STATUSES)}`, "Add dependency")}</div>`),
      section("Key findings and risks", rowsBlock("findings", (r, i) => findingLabel(i), (i) => `
        ${area(`findings.${i}.description`, "Risk description", "", 2)}
        ${select(`findings.${i}.businessImpact`, "Business impact", IMPACT.map((l, k) => [String(k + 1), l]))}
        ${select(`findings.${i}.likelihood`, "Likelihood", LIKELIHOOD.map((l, k) => [String(k + 1), l]))}
        ${area(`findings.${i}.existingControls`, "Existing controls", "", 2)}
        ${area(`findings.${i}.recommendation`, "Recommendation", "", 2)}
        ${select(`findings.${i}.residual`, "Residual risk", LEVELS)}
        ${owner(`findings.${i}.riskOwner`, "Risk owner")}`, "Add finding")),
      section("Recommendations", rowsBlock("recommendations", (r, i) => `Recommendation ${i + 1}`, (i) => `
        ${area(`recommendations.${i}.recommendation`, "Recommendation", "", 2)}
        ${select(`recommendations.${i}.finding`, "Risk addressed", findingChoices())}
        ${select(`recommendations.${i}.priority`, "Priority", PRIORITIES)}
        ${owner(`recommendations.${i}.owner`, "Owner")}
        ${date(`recommendations.${i}.target`, "Target date")}
        ${select(`recommendations.${i}.status`, "Status", ROW_STATUSES)}`, "Add recommendation")),
      section("Cybersecurity risk determination", `<div class="form-grid">
        <p class="full small muted">Determination, inherent and residual risk are set in the executive summary.</p>
        ${select("conditionsRequired", "Conditions required", YN)}
        ${select("riskAcceptance", "Risk acceptance required", YN)}
        ${select("followUpReview", "Follow-up review required", YN)}
        ${area("determinationComments", "Comments", "", 3)}</div>`),
      section("Conditions and assumptions", `<p class="muted small">Conditions are required actions. Assumptions are the business, technical, cloud, AI, OT and NERC CIP assumptions relied on during the assessment.</p>
        <div class="form-grid">
        ${area("conditions", "Conditions (one per line)", "e.g. SSO and MFA must be implemented before production deployment.\nOT cybersecurity review required if operational connectivity is introduced.", 4)}
        ${area("assumptions", "Assumptions (one per line)", "e.g. No BCSI will be processed.\nCustomer data will not be used for AI model training.\nCloud services remain in approved hosting regions.", 4)}</div>`),
      section("Follow-up actions", rowsBlock("actions", (r, i) => `Action ${i + 1}`, (i) => `
        ${text(`actions.${i}.action`, "Action item", 'class="full"')}${owner(`actions.${i}.owner`, "Responsible owner")}
        ${date(`actions.${i}.due`, "Due date")}${select(`actions.${i}.status`, "Status", ROW_STATUSES)}`, "Add action")),
      section("Approval and sign-off", `<div class="assess-rows">${APPROVERS.map(([key, role]) => `<div class="assess-row"><div class="assess-row-head"><strong>${role}</strong></div>
        <div class="form-grid">${owner(`approvals.${key}.name`, "Name")}${text(`approvals.${key}.title`, "Title")}${date(`approvals.${key}.date`, "Approval date")}
        ${select(`approvals.${key}.approved`, "Approved", YN)}</div></div>`).join("")}</div>`),
      section("Final assessment summary", `<div class="ai-fill-bar edit-only"><button type="button" class="small" id="btn-assess-ai">✨ Fill with AI</button>
        <span class="small muted">Completes this summary from the answers in the sections above. Review the result before saving.</span></div>
        <div id="assess-ai-panel" class="ai-panel hidden"></div>
        <div class="form-grid">
        <div class="full risk-results" id="assess-final-echo"></div>
        ${select("cloudReview", "Cloud review required", YN)}${select("aiReview", "AI review required", YN)}
        ${select("otReview", "OT review required", YN)}${select("nercReview", "NERC CIP review required", YN)}
        ${select("dependenciesIdentified", "Dependencies identified", YN)}
        ${area("summaryComments", "Comments", "", 3)}
        ${area("finalStatement", "Final statement", "", 4)}</div>`, true),
    ].join("");
    for (const el of body.querySelectorAll(".form-grid, .assess-qs, fieldset.checks")) el.inert = !canEdit();
    refreshDerived();
  }

  // Values shown in more than one place.
  function refreshDerived() {
    const findings = draft.findings || [];
    const highest = (pick) => findings.map(pick).filter(Boolean).sort((a, b) => LEVELS.indexOf(b) - LEVELS.indexOf(a))[0];
    const hint = body.querySelector("#assess-hint");
    if (hint) hint.textContent = findings.length ? `Highest finding: inherent ${highest(findingInherent) || "–"}, residual ${highest((f) => f.residual) || "–"}.` : "Add findings below to see the highest inherent and residual risk.";
    for (const sel of body.querySelectorAll('[data-path$=".finding"]')) {
      const v = sel.value;
      sel.innerHTML = opts(findingChoices(), v);
    }
    const echo = body.querySelector("#assess-final-echo");
    if (echo) {
      const item = (label, v, badge) => `<div class="risk-result"><div class="small muted">${label}</div><div>${v ? (badge ? `<span class="badge ${levelCls(v)}">${esc(v)}</span>` : esc(v)) : "–"}</div></div>`;
      echo.innerHTML = item("Assessment outcome", draft.outcome) + item("Inherent risk", draft.inherentRisk, true) + item("Residual risk", draft.residualRisk, true)
        + item("Risk acceptance required", draft.riskAcceptance) + item("Additional compliance review required", draft.complianceReview);
    }
    (draft.findings || []).forEach((f, i) => {
      const b = body.querySelector(`[data-finding-level="${i}"]`);
      if (b) { const l = findingInherent(f); b.className = `badge ${levelCls(l)}`; b.textContent = `Inherent: ${l}`; }
    });
  }

  body.addEventListener("input", (e) => {
    const path = e.target.dataset.path;
    if (!path) return;
    setPath(draft, path, e.target.value);
    // Picking an approver fills in their title from the directory.
    const m = path.match(/^approvals\.(\w+)\.name$/);
    if (m) {
      const p = findPerson(e.target.value);
      const title = body.querySelector(`[data-path="approvals.${m[1]}.title"]`);
      if (p?.title && title) { title.value = p.title; setPath(draft, `approvals.${m[1]}.title`, p.title); }
    }
    refreshDerived();
  });
  body.addEventListener("change", (e) => {
    if (e.target.dataset.class) {
      draft.dataClasses = [...body.querySelectorAll("[data-class]:checked")].map((c) => c.dataset.class);
    }
  });
  // Redraws the editor (e.g. after adding a row), keeping open sections and the scroll position.
  function rerender() {
    const open = [...body.querySelectorAll("details")].map((d) => d.open);
    const y = $("#assessment-form").scrollTop;
    renderBody();
    body.querySelectorAll("details").forEach((d, i) => { d.open = open[i] ?? d.open; });
    $("#assessment-form").scrollTop = y;
  }
  // ---------- AI: final assessment summary ----------
  // Fields in the final summary are filled in; values set in earlier sections (outcome, risk
  // levels, risk acceptance, compliance review) are filled only where blank, and differences are listed.
  async function fillWithAI() {
    const btn = body.querySelector("#btn-assess-ai"), panel = body.querySelector("#assess-ai-panel");
    panel.classList.remove("hidden");
    panel.innerHTML = '<div class="spinner"></div> Reviewing the assessment…';
    btn.disabled = true;
    try {
      const ctx = await getAI();
      const r = ctx ? await ctx.ai.assessmentSummary(assessmentPrompt(draft)) : summarizeOffline(draft);
      if (ctx) afterAI?.();
      const own = { cloudReview: r.cloud_review_required, aiReview: r.ai_review_required, otReview: r.ot_review_required,
        nercReview: r.nerc_review_required, dependenciesIdentified: r.dependencies_identified, summaryComments: r.comments, finalStatement: r.final_statement };
      const shared = [["outcome", "Assessment outcome", r.outcome, "Pending"], ["inherentRisk", "Inherent risk", r.inherent_risk], ["residualRisk", "Residual risk", r.residual_risk],
        ["riskAcceptance", "Risk acceptance required", r.risk_acceptance_required], ["complianceReview", "Additional compliance review required", r.compliance_review_required]];
      Object.assign(draft, own);
      const differs = [];
      for (const [key, label, value, blank] of shared) {
        if (!draft[key] || draft[key] === blank) draft[key] = value;
        else if (draft[key] !== value) differs.push(`<li>${esc(label)}: AI suggests <strong>${esc(value)}</strong> (you have ${esc(draft[key])}) <button type="button" class="link small" data-ai-accept="${key}" data-value="${esc(value)}">Use AI's</button></li>`);
      }
      rerender();
      const p = body.querySelector("#assess-ai-panel");
      p.classList.remove("hidden");
      p.innerHTML = `<div class="ai-head"><strong>${ctx ? "✨ Claude filled in the final summary" : "Filled in with offline rules"}</strong></div>
        <p class="small">${esc(r.rationale)}</p>
        ${differs.length ? `<p class="small">Where the AI disagrees with earlier answers (kept as you set them):</p><ul class="small">${differs.join("")}</ul>` : ""}
        ${ctx ? "" : '<p class="muted small">Add an Anthropic API key in Settings for a Claude-written summary.</p>'}`;
      body.querySelector("#assess-ai-panel").scrollIntoView({ block: "nearest" });
    } catch (err) {
      panel.innerHTML = `<p class="error-text">AI couldn't fill the summary: ${esc(err.message)}</p>`;
    } finally {
      const b = body.querySelector("#btn-assess-ai");
      if (b) b.disabled = false;
    }
  }

  body.addEventListener("click", (e) => {
    if (e.target.id === "btn-assess-ai" && canEdit()) return fillWithAI();
    if (e.target.dataset.aiAccept) {
      draft[e.target.dataset.aiAccept] = e.target.dataset.value;
      const field = body.querySelector(`[data-path="${e.target.dataset.aiAccept}"]`);
      if (field) field.value = e.target.dataset.value;
      e.target.closest("li").remove();
      refreshDerived();
      return;
    }
    const add = e.target.dataset.add, remove = e.target.dataset.remove, toReg = e.target.dataset.toRegister;
    if (add) { (draft[add] ||= []).push(BLANK[add]()); rerender(); }
    if (remove) {
      const [kind, i] = remove.split(".");
      draft[kind].splice(Number(i), 1);
      rerender();
    }
    if (toReg != null && canEdit()) {
      const f = draft.findings[Number(toReg)];
      if (!f.description?.trim()) return toast("Add a risk description first", true);
      const residualScore = { Low: 4, Medium: 8, High: 12, Critical: 20 }[f.residual];
      const id = addRegisterRisk({
        title: f.description.trim().split("\n")[0].slice(0, 200), description: f.description.trim(), asset: draft.solution || "",
        category: "Other", owner: f.riskOwner || draft.riskOwner || "", assetOwner: draft.assetOwner || "",
        likelihood: Number(f.likelihood) || 3, impact: Number(f.businessImpact) || 3,
        ...(residualScore ? { residualLikelihood: residualScore >= 12 ? 3 : 2, residualImpact: Math.round(residualScore / (residualScore >= 12 ? 3 : 2)) } : {}),
        treatment: "Mitigate", status: "Identified",
        controls: [f.existingControls && `Existing controls: ${f.existingControls.trim()}`, f.recommendation && `Recommendation: ${f.recommendation.trim()}`].filter(Boolean).join("\n"),
        memo: `From ad-hoc risk assessment ${editingId || nextId()}${draft.solution ? ` – ${draft.solution}` : ""}, finding ${findingLabel(Number(toReg))}.`,
        createdBy: commenter(), createdDate: new Date().toISOString().slice(0, 10), comments: [],
      });
      f.registerId = id;
      rerender();
      toast(`Added to the risk register as ${id}. Save the assessment to keep the link.`);
    }
  });

  // ---------- open / close / save ----------
  const state = () => JSON.stringify(draft);
  function open(a) {
    editingId = a?.id ?? null;
    draft = a ? { ...blankAssessment(), ...structuredClone(a) } : blankAssessment();
    $("#assessment-title").textContent = a ? `${a.id} · ${a.solution || "Assessment"}` : "New ad-hoc risk assessment";
    $("#btn-assessment-delete").classList.toggle("hidden", !a);
    renderBody();
    snapshot = state();
    if (splitView.matches) {
      document.documentElement.style.setProperty("--topbar-h", `${$(".topbar").offsetHeight}px`);
      document.body.classList.add("assessment-split");
      if (!dialog.open) dialog.show();
    } else if (!dialog.open) {
      dialog.showModal();
    }
    $("#assessment-form").scrollTop = 0;
    render();
  }
  const confirmDiscard = () => !dialog.open || !canEdit() || state() === snapshot || confirm("Discard your unsaved changes to this assessment?");
  function hide() {
    if (dialog.open) dialog.close();
    document.body.classList.remove("assessment-split");
    draft = null; editingId = null;
    render();
  }
  function close() {
    if (!confirmDiscard()) return false;
    hide();
    return true;
  }

  // Export: prints the report on its own (see #assessment-print in styles.css). The page title
  // becomes the PDF's suggested file name.
  function exportPdf() {
    const id = editingId || nextId();
    const name = `${id} ${draft.solution || "Assessment"} – Ad-Hoc Risk Assessment`;
    $("#assessment-print").innerHTML = reportHtml(draft, { esc, org: getOrgName(), logo: logoImg(getLogo(), "pr-logo", getOrgName()) || $(".topbar .logo-mark")?.outerHTML || "", id });
    const title = document.title;
    document.title = name.replace(/[\\/:*?"<>|]/g, "-");
    document.body.classList.add("printing-assessment");
    const done = () => {
      document.body.classList.remove("printing-assessment");
      document.title = title;
      $("#assessment-print").innerHTML = "";
      window.removeEventListener("afterprint", done);
    };
    window.addEventListener("afterprint", done);
    window.print();
  }
  $("#btn-assessment-pdf").addEventListener("click", () => {
    if (!draft) return;
    if (canEdit() && state() !== snapshot) toast("Exporting what's on screen – remember to save your changes too.");
    exportPdf();
  });

  $("#btn-assessment-add").addEventListener("click", () => { if (confirmDiscard()) open(null); });
  $("#btn-assessment-close").addEventListener("click", close);
  $("#btn-assessment-cancel").addEventListener("click", close);
  dialog.addEventListener("cancel", (e) => { e.preventDefault(); close(); });
  // The side panel isn't modal, so Escape doesn't reach the dialog's cancel event.
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && dialog.open && document.body.classList.contains("assessment-split")) close();
  });
  document.addEventListener("click", (e) => {
    const id = e.target.closest("[data-assessment]")?.dataset.assessment;
    if (!id || (dialog.open && editingId === id)) return;
    if (confirmDiscard()) open(list.find((a) => a.id === id));
  });
  $("#btn-assessment-delete").addEventListener("click", () => {
    if (!editingId || !confirm(`Delete ${editingId}? This can't be undone.`)) return;
    list = list.filter((a) => a.id !== editingId);
    hide();
    save();
    toast("Assessment deleted");
  });
  $("#assessment-form").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!canEdit()) return;
    if (!draft.solution?.trim()) {
      body.querySelector("details").open = true;
      return toast("Add the solution / technology first", true);
    }
    const now = new Date().toISOString();
    if (editingId) list = list.map((a) => (a.id === editingId ? { ...draft, id: editingId, updated: now } : a));
    else list.push({ ...draft, id: nextId(), created: now });
    snapshot = state();
    hide();
    save();
    toast("Assessment saved");
  });

  return {
    render,
    all: () => list,
    close,
    reload(next) { list = next || []; render(); },
    replaceAll(next) { list = next; save(); render(); },
    // Imported from a backup: new IDs where they'd clash.
    addMany(items) {
      for (const a of items) list.push({ ...a, id: /^A-\d{3,6}$/.test(a.id) && !list.some((x) => x.id === a.id) ? a.id : nextId() });
      save(); render();
    },
  };
}
