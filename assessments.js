// Ad-hoc risk assessments: a cybersecurity review of one solution or technology, following
// the assessment template – executive summary, scope and evidence, data handling, security /
// cloud / AI / OT / NERC CIP considerations, findings, recommendations, determination,
// conditions, follow-up actions, sign-off and a final summary. Findings can be sent to the
// risk register.

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

export function initAssessments({ $, $$, escapeHtml: esc, toast, initial, persist, canEdit, ownerNames, findPerson, scope, addRegisterRisk, onChange, commenter }) {
  let list = initial || [];
  let draft = null, editingId = null, snapshot = "";
  const dialog = $("#assessment-dialog");
  const body = $("#assessment-body");

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
      section("Final assessment summary", `<div class="form-grid">
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
  body.addEventListener("click", (e) => {
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
    if (!dialog.open) dialog.showModal();
    $("#assessment-form").scrollTop = 0;
    render();
  }
  const confirmDiscard = () => !dialog.open || !canEdit() || state() === snapshot || confirm("Discard your unsaved changes to this assessment?");
  function hide() {
    if (dialog.open) dialog.close();
    draft = null; editingId = null;
    render();
  }
  function close() {
    if (!confirmDiscard()) return false;
    hide();
    return true;
  }

  $("#btn-assessment-add").addEventListener("click", () => { if (confirmDiscard()) open(null); });
  $("#btn-assessment-close").addEventListener("click", close);
  $("#btn-assessment-cancel").addEventListener("click", close);
  dialog.addEventListener("cancel", (e) => { e.preventDefault(); close(); });
  document.addEventListener("click", (e) => {
    const id = e.target.closest("[data-assessment]")?.dataset.assessment;
    if (id && confirmDiscard()) open(list.find((a) => a.id === id));
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
