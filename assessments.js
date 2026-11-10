// Ad-hoc risk assessments: the Adhoc Risk Assessment Summary Report for one request (a piece
// of software or technology) – report details, request / scope, assessment summary, software
// functionality, key risks, a recommendations / actions table with a risk response and
// treatment plan for each row, and the next steps / implementation hand-off to the support
// teams. Rows of the recommendations table can be sent to the risk register.

import { logoImg } from "./logo.js";

export const STATUSES = ["Draft", "Final"];
export const LEVELS = ["Very Low", "Low", "Medium", "High", "Very High"];
export const STRATEGIES = ["Mitigate", "Accept", "Avoid", "Transfer"];
const YN = ["Yes", "No"];
const YNU = ["Yes", "No", "Unknown"];
const SOLUTION_TYPES = ["Commercial software", "Open-source software", "Freeware", "SaaS / cloud service", "Browser extension / add-in",
  "Custom program – macros", "Custom program – scripts", "AI tool", "Hardware / device", "Other"];
const LICENSE_TYPES = ["Commercial / paid", "Subscription", "Open source", "Freeware", "Trial", "Developed in-house"];
const RISK_DOMAINS = ["Access management", "Asset management", "Data protection", "Licensing and compliance", "Logging and monitoring",
  "Malware protection", "Network security", "Patch management", "Software supply chain", "Third party / vendor", "Vulnerability management",
  "AI", "NERC CIP", "Availability"];
const TREATMENT_HINT = "Based on the response, share the additional details: treatment plan details, due date (if not implemented), business justification, compensating controls, etc.";

export const HANDOFF_NOTE = "Once the assessment recommendations and treatment approach have been reviewed and agreed upon, proceed with the applicable next steps below "
  + "to coordinate implementation with the appropriate support team(s). Cyber Risk will support risk tracking through mitigation and closure, as applicable.";
export const HANDOFF_ASK = "Please open a ServiceNow ticket and work with the teams and stakeholders below to move forward.";
// The hand-off table a new assessment starts with: [category, support team]. Points of contact
// are filled in on each assessment.
const HANDOFF_DEFAULT = [["Open a request", "IT ServiceNow"], ["Installation support", "CFC – Endpoint Desktop Services / Device Management"],
  ["Asset management", "IT Asset Management / Cloud Management"], ["Firewall", "Business Innovation Solution"], ["Application / package testing", "CFC"],
  ["SIEM – EDR / logs management, etc.", "CFC"], ["Patch management", "CFC – Endpoint Desktop Services"], ["Vulnerability management", "Cyber Risk and Governance"],
  ["Access management / SSO integration", "Identity and Access Management"], ["Risk register", "Enterprise Cyber Risk"]];
const defaultHandoff = () => HANDOFF_DEFAULT.map(([category, team]) => ({ category, team, contact: "", actions: "" }));

// Text sections: [field, heading, what to cover].
const SECTIONS = [
  ["scope", "Request / scope", "What was requested and why, who it is for, and what is in and out of scope."],
  ["summaryComments", "Assessment summary", "What was reviewed, the overall conclusion and the conditions for moving forward."],
  ["solutionOverview", "Software functionality", "What the software does, how it is installed and used, and what data and systems it touches."],
  ["topRisks", "Key risks noted / identified", "The main risks found, one per line."],
];

// Repeating rows: the blank row added by "+ Add".
const BLANK = {
  recommendations: () => ({ domain: "", recommendation: "", inherent: "", strategy: "", treatment: "", residual: "" }),
  handoff: () => ({ category: "", team: "", contact: "", actions: "" }),
};

// Assessments written with the earlier, longer template used Low to Critical.
const level = (l) => (l === "Critical" ? "Very High" : l || "");
const levelCls = (l) => ({ "very low": "low", "very high": "critical" }[String(l || "").toLowerCase()] || String(l || "").toLowerCase());
export const highestLevel = (levels) => levels.map(level).filter((l) => LEVELS.includes(l)).sort((a, b) => LEVELS.indexOf(b) - LEVELS.indexOf(a))[0] || "";
export const rowId = (i) => `R${i + 1}`;

// Brings an assessment written with the earlier template into this one: its findings become
// rows of the recommendations table and its status becomes Draft or Final. The earlier answers
// stay on the record.
export function upgradeAssessment(a) {
  if (a.template === 2) return a;
  const findings = Array.isArray(a.findings) ? a.findings : [], recs = Array.isArray(a.recommendations) ? a.recommendations : [];
  const legacyInherent = (f) => { const s = (Number(f.likelihood) || 1) * (Number(f.businessImpact) || 1); return s >= 20 ? "Very High" : s >= 12 ? "High" : s >= 6 ? "Medium" : "Low"; };
  const rows = findings.map((f, i) => {
    const mine = recs.filter((r) => r.finding === rowId(i)).map((r) => r.recommendation).filter(Boolean);
    return {
      domain: "", recommendation: [f.description && `Risk: ${f.description}`, ...(mine.length ? mine : [f.recommendation])].filter(Boolean).join("\n"),
      inherent: legacyInherent(f), strategy: "", treatment: f.existingControls ? `Existing controls: ${f.existingControls}` : "", residual: level(f.residual),
      ...(f.registerId ? { registerId: f.registerId } : {}),
    };
  });
  for (const r of recs) {
    if (findings[Number(String(r.finding || "").slice(1)) - 1]) continue;
    rows.push({ ...BLANK.recommendations(), ...r, recommendation: r.recommendation || "",
      treatment: r.treatment || [r.owner && `Owner: ${r.owner}`, r.target && `Due: ${r.target}`].filter(Boolean).join("; ") });
  }
  return { ...a, template: 2, status: ["Approved", "Closed", "Final"].includes(a.status) ? "Final" : "Draft", inherentRisk: level(a.inherentRisk),
    recommendations: rows, handoff: Array.isArray(a.handoff) ? a.handoff : defaultHandoff() };
}

// The other sections as text for the AI-written assessment summary.
export function assessmentPrompt(a) {
  const text = (key) => a[key]?.trim() || "(blank)";
  return [
    `Request name: ${a.solution || "(not named)"}`,
    `Requestor: ${a.requestor || "(not set)"}; population: ${a.population || "(not set)"}; version: ${a.version || "(not set)"}; license type: ${a.licenseType || "(not set)"}`,
    `Solution type: ${a.assessmentType || "(not set)"}; assessor's current solution risk level: ${a.inherentRisk || "(not set)"}`,
    `NERC CIP: ${a.nercImpact || "(not set)"}; AI capability: ${a.aiCapability || "(not set)"}`,
    `Request / scope:\n${text("scope")}`,
    `Software functionality:\n${text("solutionOverview")}`,
    `Key risks noted / identified:\n${text("topRisks")}`,
    `Recommendations / actions:\n${(a.recommendations || []).map((r, i) => `- ${rowId(i)} [${r.domain || "no risk domain"}] ${r.recommendation || "(no recommendation)"} | inherent ${r.inherent || "(not set)"} | response ${r.strategy || "(not set)"} | treatment plan: ${r.treatment || "(none)"} | residual ${r.residual || "(not set)"}`).join("\n") || "(none)"}`,
    `Assessor's existing assessment summary:\n${text("summaryComments")}`,
    "",
    "Write the assessment summary from these answers.",
  ].join("\n\n");
}

// Demo mode without an API key: the same summary worked out from simple rules.
export function summarizeOffline(a) {
  const rows = a.recommendations || [];
  const inherent = highestLevel(rows.map((r) => r.inherent)) || level(a.inherentRisk) || "Medium";
  const residual = highestLevel(rows.map((r) => r.residual));
  const open = rows.filter((r) => r.strategy !== "Accept" && r.residual !== "Very Low" && r.residual !== "Low").length;
  const flags = [a.nercImpact === "Yes" && "NERC CIP applies", a.aiCapability === "Yes" && "it has AI capability"].filter(Boolean);
  const type = a.assessmentType ? ` (${a.assessmentType.replace(/^(?!AI|SaaS)./, (c) => c.toLowerCase())})` : "";
  return {
    risk_level: inherent,
    summary: `${a.solution || "The solution"}${type} was assessed${a.population ? ` for ${a.population}` : ""} with ${rows.length} recommendation${rows.length === 1 ? "" : "s"}. `
      + `The solution risk level is ${inherent}${residual ? `, and ${residual} once the treatment plans are in place` : ""}. `
      + (flags.length ? `Note that ${flags.join(" and ")}. ` : "")
      + (open ? `${open} recommendation${open === 1 ? " still needs" : "s still need"} a treatment plan that brings the residual risk down to Low or Very Low.` : rows.length ? "Every recommendation has a response that brings the residual risk to Low or Very Low, or is accepted." : "No recommendations have been recorded yet."),
    rationale: "Worked out from simple rules (no AI): the highest inherent risk level in the recommendations table sets the solution risk level.",
  };
}

// ---------- PDF report ----------
// A print-ready copy of the summary report (printed to PDF with the browser's "Save as PDF").
// Blank text sections are left out so the report reads as a finished document.
export function reportHtml(a, { esc, org = "", logo = "", id = "", generated = new Date() }) {
  const has = (v) => (Array.isArray(v) ? v.length > 0 : typeof v === "string" ? v.trim() !== "" : v != null);
  const para = (t) => esc(t).split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
  const lines = (t) => String(t || "").split("\n").map((l) => l.replace(/^\s*[-•·*]\s*/, "").trim()).filter(Boolean);
  const cell = (t) => esc(t || "").replace(/\n/g, "<br>");
  const badge = (v) => (v ? `<span class="pr-badge ${levelCls(v)}">${esc(v)}</span>` : '<span class="pr-muted">–</span>');
  const yn = (v) => (v === "Yes" ? '<span class="pr-pill yes">Yes</span>' : v === "No" ? '<span class="pr-pill no">No</span>' : v ? `<span class="pr-pill">${esc(v)}</span>` : '<span class="pr-muted">–</span>');
  const date = (d) => (d ? new Date(`${d}T00:00:00`).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : "");
  const fact = (label, v) => `<div class="pr-fact"><div class="pr-label">${label}</div><div>${v || '<span class="pr-muted">–</span>'}</div></div>`;
  const sec = (title, inner) => (inner ? `<section class="pr-section"><h2>${esc(title)}</h2>${inner}</section>` : "");
  const status = a.status === "Final" ? "Final" : "Draft";
  const rows = a.recommendations || [], handoff = a.handoff || [];

  return `<article class="pr-doc">
    <header class="pr-cover">
      <div class="pr-cover-top"><span class="pr-brand">${logo}<span>${esc(org || "Posture.ai")}</span></span><span>Adhoc Risk Assessment Summary Report · ${esc(id)}</span></div>
      <div class="pr-eyebrow">Adhoc Risk Assessment Summary Report – ${status.toUpperCase()}</div>
      <h1>${esc(a.solution || "Untitled request")}</h1>
      <div class="pr-cover-meta">${[a.assessmentType, date(a.assessmentDate)].filter(Boolean).map(esc).join(" · ")}</div>
      <div class="pr-verdict">
        <div class="pr-verdict-item"><small>Solution risk level</small>${badge(a.inherentRisk)}</div>
        <div class="pr-verdict-item"><small>NERC CIP</small><strong>${esc(a.nercImpact || "–")}</strong></div>
        <div class="pr-verdict-item"><small>AI capability</small><strong>${esc(a.aiCapability || "–")}</strong></div>
      </div>
    </header>

    <section class="pr-section">
      <div class="pr-facts">
        ${fact("Request name", esc(a.solution))}${fact("Requestor", esc(a.requestor))}${fact("Population", esc(a.population))}
        ${fact("Version", esc(a.version))}${fact("License type", esc(a.licenseType))}${fact("Solution type", esc(a.assessmentType))}
        ${fact("Solution risk level", badge(a.inherentRisk))}${fact("NERC CIP", yn(a.nercImpact))}${fact("AI capability", yn(a.aiCapability))}
        ${fact("Assessment date", esc(date(a.assessmentDate)))}${fact("Cybersecurity reviewer", esc(a.reviewer))}${fact("Risk owner", esc(a.riskOwner))}
      </div>
    </section>

    ${SECTIONS.map(([key, title]) => sec(title, !has(a[key]) ? "" : key === "topRisks" ? `<ul>${lines(a[key]).map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : para(a[key]))).join("")}
    ${sec("Recommendations / actions", rows.length ? `<table class="pr-table"><thead><tr><th class="pr-narrow">ID</th><th>Risk domain</th><th>Recommendations / actions</th>
        <th class="pr-narrow">Inherent risk level</th><th class="pr-narrow">Risk response strategy</th><th>Business inputs / treatment plan details</th><th class="pr-narrow">Residual risk level</th></tr></thead>
      <tbody>${rows.map((r, i) => `<tr><td><span class="pr-id">${rowId(i)}</span></td><td>${esc(r.domain || "")}</td><td>${cell(r.recommendation)}</td><td>${badge(r.inherent)}</td>
        <td>${esc(r.strategy || "")}</td><td>${cell(r.treatment)}${r.registerId ? `<div class="pr-muted">Risk register: ${esc(r.registerId)}</div>` : ""}</td><td>${badge(r.residual)}</td></tr>`).join("")}</tbody></table>` : "")}
    ${sec("Next steps / implementation hand-off", handoff.length ? `<div class="pr-callout"><p>${esc(HANDOFF_NOTE)}</p><p>${esc(HANDOFF_ASK)}</p></div>
      <table class="pr-table"><thead><tr><th class="pr-narrow">Sr. no.</th><th>Category</th><th>Support team</th><th>Point of contact</th><th>Actions required</th></tr></thead>
      <tbody>${handoff.map((h, i) => `<tr><td>${i + 1}</td><td>${esc(h.category || "")}</td><td>${esc(h.team || "")}</td><td>${esc(h.contact || "")}</td><td>${cell(h.actions)}</td></tr>`).join("")}</tbody></table>` : "")}
    <footer class="pr-foot">${esc(org ? `${org} · ` : "")}Confidential · ${esc(id)} · Generated ${esc(generated.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }))} with Posture.ai</footer>
  </article>`;
}

export function blankAssessment() {
  return { template: 2, status: "Draft", assessmentDate: new Date().toISOString().slice(0, 10), recommendations: [], handoff: defaultHandoff() };
}

const getPath = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
function setPath(obj, path, value) {
  const keys = path.split(".");
  let o = obj;
  for (const k of keys.slice(0, -1)) o = o[k] ??= {};
  o[keys.at(-1)] = value;
}

export function initAssessments({ $, $$, escapeHtml: esc, toast, initial, persist, canEdit, ownerNames, scope, addRegisterRisk, onChange, commenter, getAI, afterAI, getOrgName = () => "", getLogo = () => null }) {
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
    const st = $("#assessment-status-filter").value, lv = $("#assessment-level-filter").value;
    const base = scope(list);
    const rows = base.map(upgradeAssessment)
      .filter((a) => !q || JSON.stringify(a).toLowerCase().includes(q))
      .filter((a) => !st || a.status === st)
      .filter((a) => !lv || a.inherentRisk === lv)
      .sort((a, b) => String(b.assessmentDate || "").localeCompare(String(a.assessmentDate || "")) || b.id.localeCompare(a.id));
    $("#assessment-table tbody").innerHTML = rows.map((a) => `<tr class="${dialog.open && editingId === a.id ? "selected" : ""}">
        <td>${esc(a.id)}</td>
        <td><button type="button" class="link row-name" data-assessment="${esc(a.id)}">${esc(a.solution || "(untitled)")}</button><div class="muted small">${esc(a.assessmentType)}</div></td>
        <td>${esc(a.requestor)}</td>
        <td>${a.inherentRisk ? `<span class="badge ${levelCls(a.inherentRisk)}">${esc(a.inherentRisk)}</span>` : ""}</td>
        <td>${esc(a.nercImpact)}</td>
        <td>${esc(a.aiCapability)}</td>
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
  $("#assessment-level-filter").addEventListener("change", render);

  // ---------- editor fields ----------
  const val = (path) => getPath(draft, path) ?? "";
  // A value that isn't one of the choices (from an older assessment) stays selectable.
  const opts = (choices, current, blank = "–") => `<option value="">${blank}</option>${[...choices, ...(current && !choices.includes(current) ? [current] : [])]
    .map((c) => `<option value="${esc(c)}" ${c === current ? "selected" : ""}>${esc(c)}</option>`).join("")}`;
  const text = (path, label, { extra = "", list: suggestions = "", placeholder = "" } = {}) => `<label ${extra}>${label} <input data-path="${path}" value="${esc(val(path))}" maxlength="500"
    ${suggestions ? `list="${suggestions}"` : ""} placeholder="${esc(placeholder)}" /></label>`;
  const date = (path, label) => `<label>${label} <input type="date" data-path="${path}" value="${esc(val(path))}" /></label>`;
  const area = (path, label, placeholder = "", rows = 4) => `<label class="full">${label} <textarea data-path="${path}" rows="${rows}" placeholder="${esc(placeholder)}">${esc(val(path))}</textarea></label>`;
  const select = (path, label, choices) => `<label>${label} <select data-path="${path}">${opts(choices, val(path))}</select></label>`;
  // Owner fields: a pick list of the directory and members (free text until there's anyone to pick).
  const owner = (path, label) => {
    const names = ownerNames(), v = val(path);
    if (!names.length) return text(path, label);
    return `<label>${label} <select data-path="${path}" data-owner>${opts(names, v)}</select></label>`;
  };
  const datalist = (id, choices) => `<datalist id="${id}">${choices.map((c) => `<option value="${esc(c)}"></option>`).join("")}</datalist>`;
  const section = (title, inner) => `<details class="form-section-details assess-section" open><summary>${title}</summary>${inner}</details>`;
  const rowsBlock = (kind, title, fields, addLabel) => `<div class="assess-rows">${(draft[kind] || []).map((r, i) => `
      <div class="assess-row"><div class="assess-row-head"><strong>${title(r, i)}</strong>${extraRowHead(kind, r, i)}
        <button type="button" class="link danger edit-only" data-remove="${kind}.${i}" aria-label="Remove">✕</button></div>
        <div class="form-grid">${fields(i, r)}</div></div>`).join("") || '<p class="muted small">None yet.</p>'}
      <button type="button" class="small edit-only" data-add="${kind}">+ ${addLabel}</button></div>`;
  const extraRowHead = (kind, r, i) => {
    if (kind !== "recommendations") return "";
    return ` <span data-row-level="${i}"></span>
      ${r.registerId ? `<span class="tag">In register: ${esc(r.registerId)}</span>` : `<button type="button" class="small edit-only" data-to-register="${i}">Send to risk register</button>`}`;
  };

  function renderBody() {
    body.innerHTML = [
      datalist("assess-solution-types", SOLUTION_TYPES), datalist("assess-license-types", LICENSE_TYPES), datalist("assess-risk-domains", RISK_DOMAINS),
      section("Report details", `<div class="form-grid">
        <label class="full">Request name <input data-path="solution" value="${esc(val("solution"))}" required maxlength="200" placeholder="The software or technology requested, e.g. 7-Zip, a custom Excel macro, a browser add-in" /></label>
        ${owner("requestor", "Requestor")}
        ${select("status", "Report status", STATUSES)}
        ${text("population", "Population", { placeholder: "e.g. 250 users" })}
        ${text("version", "Version")}
        ${text("licenseType", "License type", { list: "assess-license-types" })}
        ${text("assessmentType", "Solution type", { list: "assess-solution-types", placeholder: "e.g. Custom program – macros" })}
        ${select("inherentRisk", "Solution risk level / score", LEVELS)}
        ${select("nercImpact", "NERC CIP", YNU)}
        ${select("aiCapability", "AI capability", YN)}
        ${date("assessmentDate", "Assessment date")}
        ${owner("reviewer", "Cybersecurity reviewer")}
        ${owner("riskOwner", "Risk owner")}
        <p class="full small muted" id="assess-hint"></p>
      </div>`),
      ...SECTIONS.map(([key, title, hint]) => section(title, `<p class="muted small">${esc(hint)}</p>
        ${key === "summaryComments" ? `<div class="ai-fill-bar edit-only"><button type="button" class="small" id="btn-assess-ai">✨ Fill with AI</button>
          <span class="small muted">Writes this summary from the other sections. Review the result before saving.</span></div>
          <div id="assess-ai-panel" class="ai-panel hidden"></div>` : ""}
        <div class="form-grid">${area(key, "Notes", "", key === "topRisks" ? 6 : 5)}</div>`)),
      section("Recommendations / actions", `<p class="muted small">The goal is to turn each risk towards Very Low. Fill in the risk response strategy and the business inputs / treatment plan details for every row.</p>
        ${rowsBlock("recommendations", (r, i) => rowId(i), (i) => `
        ${text(`recommendations.${i}.domain`, "Risk domain", { list: "assess-risk-domains" })}
        ${select(`recommendations.${i}.inherent`, "Inherent risk level", LEVELS)}
        ${area(`recommendations.${i}.recommendation`, "Recommendations / actions", "", 2)}
        ${select(`recommendations.${i}.strategy`, "Risk response strategy", STRATEGIES)}
        ${select(`recommendations.${i}.residual`, "Residual risk level", LEVELS)}
        ${area(`recommendations.${i}.treatment`, "Business inputs / treatment plan details", TREATMENT_HINT, 2)}`, "Add recommendation")}`),
      section("Next steps / implementation hand-off", `<p class="small">${esc(HANDOFF_NOTE)}</p><p class="muted small">${esc(HANDOFF_ASK)}</p>
        ${rowsBlock("handoff", (r, i) => `${i + 1}. ${esc(r.category || "Next step")}`, (i) => `
        ${text(`handoff.${i}.category`, "Category")}${text(`handoff.${i}.team`, "Support team")}
        ${text(`handoff.${i}.contact`, "Point of contact")}${text(`handoff.${i}.actions`, "Actions required")}`, "Add next step")}`),
    ].join("");
    for (const el of body.querySelectorAll(".form-grid")) el.inert = !canEdit();
    refreshDerived();
  }

  // Values shown in more than one place.
  function refreshDerived() {
    const rows = draft.recommendations || [];
    const hint = body.querySelector("#assess-hint");
    if (hint) {
      const inherent = highestLevel(rows.map((r) => r.inherent)), residual = highestLevel(rows.map((r) => r.residual));
      hint.textContent = inherent || residual ? `Highest in the recommendations table: inherent ${inherent || "–"}, residual ${residual || "–"}.`
        : "Add rows to the recommendations table to see the highest inherent and residual risk levels.";
    }
    rows.forEach((r, i) => {
      const b = body.querySelector(`[data-row-level="${i}"]`);
      if (!b) return;
      b.className = r.inherent ? `badge ${levelCls(r.inherent)}` : "";
      b.textContent = r.inherent ? `Inherent: ${r.inherent}` : "";
    });
  }

  body.addEventListener("input", (e) => {
    const path = e.target.dataset.path;
    if (!path) return;
    setPath(draft, path, e.target.value);
    refreshDerived();
  });
  // Redraws the editor (e.g. after adding a row), keeping open sections and the scroll position.
  function rerender() {
    const open = [...body.querySelectorAll("details")].map((d) => d.open);
    const y = $("#assessment-form").scrollTop;
    renderBody();
    body.querySelectorAll("details").forEach((d, i) => { d.open = open[i] ?? d.open; });
    $("#assessment-form").scrollTop = y;
  }

  // ---------- AI: assessment summary ----------
  // The summary is written from the other sections. The solution risk level is filled in only
  // where it's blank; a different suggestion is shown for the assessor to accept.
  async function fillWithAI() {
    const btn = body.querySelector("#btn-assess-ai"), panel = body.querySelector("#assess-ai-panel");
    panel.classList.remove("hidden");
    panel.innerHTML = '<div class="spinner"></div> Reviewing the assessment…';
    btn.disabled = true;
    try {
      const ctx = await getAI();
      const r = ctx ? await ctx.ai.assessmentSummary(assessmentPrompt(draft)) : summarizeOffline(draft);
      if (ctx) afterAI?.();
      // An AI function that hasn't been updated yet answers in the earlier template's shape.
      const summary = r.summary ?? r.comments ?? "", suggested = level(r.risk_level ?? r.inherent_risk);
      if (summary) draft.summaryComments = summary;
      let differs = "";
      if (!draft.inherentRisk) draft.inherentRisk = suggested;
      else if (suggested && draft.inherentRisk !== suggested) differs = `<p class="small">Solution risk level: AI suggests <strong>${esc(suggested)}</strong> (you have ${esc(draft.inherentRisk)}) <button type="button" class="link small" data-ai-accept="${esc(suggested)}">Use AI's</button></p>`;
      rerender();
      const p = body.querySelector("#assess-ai-panel");
      p.classList.remove("hidden");
      p.innerHTML = `<div class="ai-head"><strong>${ctx ? "✨ Claude wrote the assessment summary" : "Written with offline rules"}</strong></div>
        <p class="small">${esc(r.rationale || "")}</p>${differs}
        ${ctx ? "" : '<p class="muted small">Add an Anthropic API key in Settings for a Claude-written summary.</p>'}`;
      p.scrollIntoView({ block: "nearest" });
    } catch (err) {
      panel.innerHTML = `<p class="error-text">AI couldn't write the summary: ${esc(err.message)}</p>`;
    } finally {
      const b = body.querySelector("#btn-assess-ai");
      if (b) b.disabled = false;
    }
  }

  // A register risk needs a likelihood and an impact: the pair that gives each level.
  const REGISTER_SCORE = { "Very Low": [1, 2], Low: [2, 2], Medium: [3, 3], High: [4, 4], "Very High": [5, 5] };
  body.addEventListener("click", (e) => {
    if (e.target.id === "btn-assess-ai" && canEdit()) return fillWithAI();
    if (e.target.dataset.aiAccept) {
      draft.inherentRisk = e.target.dataset.aiAccept;
      const field = body.querySelector('[data-path="inherentRisk"]');
      if (field) field.value = draft.inherentRisk;
      e.target.closest("p").remove();
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
      const r = draft.recommendations[Number(toReg)];
      if (!r.recommendation?.trim()) return toast("Add the recommendation first", true);
      const [likelihood, impact] = REGISTER_SCORE[r.inherent] || REGISTER_SCORE.Medium;
      const residual = REGISTER_SCORE[r.residual];
      const id = addRegisterRisk({
        title: `${draft.solution || "Ad-hoc assessment"}: ${r.domain || r.recommendation.trim().split("\n")[0]}`.slice(0, 200), description: r.recommendation.trim(), asset: draft.solution || "",
        category: "Other", owner: draft.riskOwner || "", likelihood, impact,
        ...(residual ? { residualLikelihood: residual[0], residualImpact: residual[1] } : {}),
        treatment: STRATEGIES.includes(r.strategy) ? r.strategy : "Mitigate", status: "Identified",
        controls: r.treatment?.trim() ? `Treatment plan: ${r.treatment.trim()}` : "",
        memo: `From ad-hoc risk assessment ${editingId || nextId()}${draft.solution ? ` – ${draft.solution}` : ""}, recommendation ${rowId(Number(toReg))}.`,
        createdBy: commenter(), createdDate: new Date().toISOString().slice(0, 10), comments: [],
      });
      r.registerId = id;
      rerender();
      toast(`Added to the risk register as ${id}. Save the assessment to keep the link.`);
    }
  });

  // ---------- open / close / save ----------
  const state = () => JSON.stringify(draft);
  function open(a) {
    editingId = a?.id ?? null;
    draft = a ? upgradeAssessment(structuredClone(a)) : blankAssessment();
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
    const name = `${id} ${draft.solution || "Assessment"} – Adhoc Risk Assessment Summary Report`;
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
      return toast("Add the request name first", true);
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
