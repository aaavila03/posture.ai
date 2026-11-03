// Threat risk assessments: describe one asset, answer the security controls that apply, assess
// the threats and likelihood of each control gap, then rate the business impact, which completes
// the risk scores. The controls, threats and scales are in tra-library.js.

import { LIBRARY_VERSION, IMPACT_LEVELS, IMPACT_ROWS, LIKELIHOODS, TREATMENTS, COMPLIANCE, ASSET_TYPES, TRIGGERS, AUTH_METHODS,
  THREATS, THREAT_CATEGORIES, CONTROLS } from "./tra-library.js";

export const TRA_STATUSES = ["In progress", "On hold", "Completed"];
const LETTERS = IMPACT_LEVELS.map(([letter]) => letter);
const LEVEL_NAME = Object.fromEntries(IMPACT_LEVELS.map(([letter, name]) => [letter, name]));
const IMPACT_VALUE = Object.fromEntries(IMPACT_LEVELS.map(([letter, , value]) => [letter, value]));
const LIKELIHOOD_VALUE = Object.fromEntries(LIKELIHOODS.map(([name, value]) => [name, value]));
const THREAT_BY_ID = new Map(THREATS.map((t) => [t.id, t]));
const RISK_LEVELS = ["Very High", "High", "Moderate", "Low", "Very Low"];
const STEPS = ["Asset profile", "Controls", "Risk scoring", "Impact", "Summary"];

const worst = (letters) => LETTERS.find((l) => letters.includes(l)) ?? null;

// The worst answer in each column sets confidentiality, integrity and availability; the worst
// of those three sets the overall rating. Not applicable and blank answers don't count.
export function impactRating(impact = {}) {
  const column = (key) => worst(IMPACT_ROWS.map((r) => impact[r.id]?.[key]));
  const c = column("c"), i = column("i"), a = column("a");
  return { c, i, a, overall: worst([c, i, a]) };
}

function triggerFires(on, profile) {
  if (on === "general") return true;
  if (AUTH_METHODS.some(([key]) => key === on)) return !!profile.auth?.[on];
  const trigger = TRIGGERS.find((t) => t.key === on);
  if (!trigger || (trigger.onlyFor && !profile.assetTypes?.includes(trigger.onlyFor))) return false;
  return profile[on] === trigger.when;
}

// The controls that apply to an asset's profile. Each control appears once, however many of its rules fire.
export function selectControls(a) {
  const profile = a.profile || {};
  if (!profile.assetTypes?.length) return [];
  return CONTROLS.filter((c) => c.assets.some((t) => profile.assetTypes.includes(t)) && c.rules.some((r) => triggerFires(r, profile)));
}

// A completed assessment keeps the controls it was completed with, so later library changes don't alter it.
export const controlsFor = (a) => (a.status === "Completed" && a.frozenControls ? a.frozenControls : selectControls(a));

export const isGap = (a, control) => ["No", "Partially"].includes(a.answers?.[control.id]?.status);

export function riskLevel(score) {
  if (score >= 80) return "Very High";
  if (score >= 50) return "High";
  if (score >= 16) return "Moderate";
  if (score >= 4) return "Low";
  if (score >= 1) return "Very Low";
  return "";
}

// Impact is fixed by the asset's overall rating: treating a risk only changes its likelihood.
export function scoreRisk(overall, likelihood) {
  const score = (IMPACT_VALUE[overall] || 0) * (LIKELIHOOD_VALUE[likelihood] || 0);
  return { score, level: riskLevel(score) };
}

const levelCls = (level) => ({ "Very High": "critical", High: "high", Moderate: "medium", Low: "low", "Very Low": "very-low" }[level] || "");
const highest = (levels) => RISK_LEVELS.find((l) => levels.includes(l)) || "";
const average = (values) => values.reduce((sum, v) => sum + v, 0) / values.length;

export function summarize(a) {
  const rating = impactRating(a.impact);
  const controls = controlsFor(a);
  const gaps = controls.filter((c) => isGap(a, c)).map((control) => {
    const detail = a.gapDetails?.[control.id] || {};
    return { control, detail, managed: scoreRisk(rating.overall, detail.likelihood), residual: scoreRisk(rating.overall, detail.residualLikelihood) };
  });
  const count = (list, pick, value) => list.filter((x) => pick(x) === value).length;
  const sections = [...new Set(controls.map((c) => c.section))].map((section) => ({
    section,
    controls: count(controls, (c) => c.section, section),
    gaps: gaps.filter((g) => g.control.section === section).length,
  }));
  // A threat's score is the average of the gaps naming it; a category's is the average of its scored threats.
  const threatScores = new Map();
  for (const g of gaps) {
    if (!g.managed.score) continue;
    for (const id of g.detail.threats || []) {
      if (THREAT_BY_ID.has(id)) threatScores.set(id, [...(threatScores.get(id) || []), g.managed.score]);
    }
  }
  const categories = THREAT_CATEGORIES.map((category) => {
    const scores = THREATS.filter((t) => t.category === category && threatScores.has(t.id)).map((t) => average(threatScores.get(t.id)));
    const score = scores.length ? average(scores) : 0;
    return { category, score, level: riskLevel(score) };
  });
  const byLevel = (key) => Object.fromEntries(RISK_LEVELS.map((l) => [l, gaps.filter((g) => g[key].level === l).length]));
  return {
    rating, controls, gaps, sections, categories,
    answered: controls.filter((c) => a.answers?.[c.id]?.status).length,
    assessed: gaps.filter((g) => g.detail.likelihood).length,
    managedLevels: byLevel("managed"), residualLevels: byLevel("residual"),
    treatments: Object.fromEntries(TREATMENTS.map((t) => [t, gaps.filter((g) => g.detail.treatment === t).length])),
    highestManaged: highest(gaps.map((g) => g.managed.level)),
    highestResidual: highest(gaps.map((g) => g.residual.level)),
  };
}

export function blankThreatAssessment() {
  return { status: "In progress", assessmentDate: new Date().toISOString().slice(0, 10), libraryVersion: LIBRARY_VERSION,
    impact: {}, profile: { assetTypes: [], auth: {} }, answers: {}, gapDetails: {} };
}

// What's stored when saving: completing freezes the controls in use, and reopening releases them.
export function prepareForSave(a) {
  const out = { ...a };
  if (out.status !== "Completed") { delete out.frozenControls; out.libraryVersion = LIBRARY_VERSION; }
  else if (!out.frozenControls) { out.frozenControls = selectControls(out); out.libraryVersion = LIBRARY_VERSION; }
  return out;
}

// ---------- answers from someone without app access ----------
const OUTSIDE_TEXT = ["vendor", "database", "deployment", "cloudModel", "location", "ssoMethod", "notes"];
const short = (value, max = 2000) => (typeof value === "string" ? value.slice(0, max) : "");

// Keeps only what the outside form may set: known questions, controls and answers. Owners,
// status, impact ratings and gaps can't be set this way.
export function cleanOutsideResponse(response) {
  const r = response && typeof response === "object" ? response : {};
  const p = r.profile && typeof r.profile === "object" ? r.profile : {};
  const profile = {
    assetTypes: (Array.isArray(p.assetTypes) ? p.assetTypes : []).filter((t) => ASSET_TYPES.some(([k]) => k === t)),
    auth: Object.fromEntries(AUTH_METHODS.filter(([k]) => p.auth?.[k] === true).map(([k]) => [k, true])),
  };
  for (const t of TRIGGERS) if (["Yes", "No"].includes(p[t.key])) profile[t.key] = p[t.key];
  for (const k of OUTSIDE_TEXT) if (short(p[k])) profile[k] = short(p[k]);
  const answers = {};
  for (const c of CONTROLS) {
    const a = r.answers?.[c.id];
    if (!COMPLIANCE.includes(a?.status)) continue;
    answers[c.id] = { status: a.status };
    if (short(a.evidence)) answers[c.id].evidence = short(a.evidence);
    if (short(a.compensating)) answers[c.id].compensating = short(a.compensating);
  }
  const clean = { profile, answers };
  if (short(r.description, 5000)) clean.description = short(r.description, 5000);
  if (short(r.department, 500)) clean.department = short(r.department, 500);
  return clean;
}

const STRONG = ["Yes", "Not applicable"], WEAK = ["No", "Partially"];

// An assessment with the response applied. Outside answers can add asset types and sign-in
// methods but never remove them, so they can't quietly shrink the list of controls that way.
export function applyOutsideResponse(a, response) {
  const r = cleanOutsideResponse(response);
  const out = structuredClone(a);
  for (const key of ["description", "department"]) if (r[key] !== undefined) out[key] = r[key];
  const { assetTypes, auth, ...rest } = r.profile;
  const current = out.profile || {};
  out.profile = { ...current, ...rest, assetTypes: [...new Set([...(current.assetTypes || []), ...assetTypes])], auth: { ...current.auth, ...auth } };
  out.answers = { ...out.answers };
  for (const [id, answer] of Object.entries(r.answers)) out.answers[id] = { ...out.answers[id], ...answer };
  return out;
}

// What applying a response would change, for the analyst to check first. Flagged rows make the
// asset look safer than before: a gap marked as met, or exposure answered away.
export function outsideChanges(a, response) {
  const r = cleanOutsideResponse(response);
  const next = applyOutsideResponse(a, response);
  const rows = [];
  const add = (label, from, to, flag = false) => { if ((from || "") !== (to || "")) rows.push({ label, from: from || "", to: to || "", flag }); };
  add("Description", a.description, next.description);
  add("Business department", a.department, next.department);
  const names = (list, source) => (list || []).map((k) => source.find(([key]) => key === k)?.[1] || k).join(", ");
  add("Asset type", names(a.profile?.assetTypes, ASSET_TYPES), names(next.profile.assetTypes, ASSET_TYPES));
  const authOn = (p) => AUTH_METHODS.filter(([k]) => p?.auth?.[k]).map(([, label]) => label).join(", ");
  add("Sign-in methods", authOn(a.profile), authOn(next.profile));
  for (const t of TRIGGERS) add(t.label, a.profile?.[t.key], next.profile[t.key], a.profile?.[t.key] === t.when && next.profile[t.key] !== t.when);
  for (const k of OUTSIDE_TEXT) add(k === "ssoMethod" ? "Central sign-in method" : `Other details: ${k}`, a.profile?.[k], next.profile[k]);
  for (const id of Object.keys(r.answers)) {
    const was = a.answers?.[id] || {}, now = next.answers[id];
    const title = `${id}: ${CONTROLS.find((c) => c.id === id).text}`;
    add(title, was.status, now.status, WEAK.includes(was.status) && STRONG.includes(now.status));
    add(`${id} evidence`, was.evidence, now.evidence);
    add(`${id} compensating controls`, was.compensating, now.compensating);
  }
  const after = new Set(selectControls(next).map((c) => c.id));
  const removed = selectControls(a).filter((c) => !after.has(c.id));
  return { rows, removed, flagged: rows.filter((x) => x.flag).length, answered: Object.keys(r.answers).length };
}

const getPath = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
function setPath(obj, path, value) {
  const keys = path.split(".");
  let o = obj;
  for (const k of keys.slice(0, -1)) o = o[k] ??= {};
  o[keys.at(-1)] = value;
}

export function initThreatAssessments({ $, escapeHtml: esc, toast, initial, persist, canEdit, isViewer, ownerNames, outside, onChange }) {
  let list = initial || [];
  let draft = null, editingId = null, snapshot = "", step = 0, controlFilter = "";
  const dialog = $("#tra-dialog");
  const body = $("#tra-body");
  const splitView = window.matchMedia("(min-width: 1100px)");

  const nextId = () => `T-${String(list.reduce((m, a) => Math.max(m, Number(String(a.id).replace(/\D/g, "")) || 0), 0) + 1).padStart(3, "0")}`;
  const save = () => { persist(list); onChange?.(); };
  const badge = (level) => (level ? `<span class="badge ${levelCls(level)}">${esc(level)}</span>` : '<span class="muted">–</span>');
  const letterBadge = (letter) => (letter ? badge(LEVEL_NAME[letter]) : '<span class="muted">–</span>');

  // ---------- list ----------
  function render() {
    const q = $("#tra-search").value.toLowerCase();
    const st = $("#tra-status-filter").value, rate = $("#tra-rating-filter").value;
    const rows = list.map((a) => ({ a, s: summarize(a) }))
      .filter(({ a }) => !q || JSON.stringify(a).toLowerCase().includes(q))
      .filter(({ a }) => !st || a.status === st)
      .filter(({ s }) => !rate || s.rating.overall === rate)
      .sort((x, y) => String(y.a.assessmentDate || "").localeCompare(String(x.a.assessmentDate || "")) || y.a.id.localeCompare(x.a.id));
    $("#tra-table tbody").innerHTML = rows.map(({ a, s }) => `<tr class="${dialog.open && editingId === a.id ? "selected" : ""}">
        <td>${esc(a.id)}</td>
        <td><button type="button" class="link row-name" data-tra="${esc(a.id)}">${esc(a.assetName || "(untitled)")}</button><div class="muted small">${esc(a.assetOwner)}</div></td>
        <td>${letterBadge(s.rating.overall)}</td>
        <td>${s.gaps.length} of ${s.controls.length}</td>
        <td>${badge(s.highestManaged)}</td>
        <td>${badge(s.highestResidual)}</td>
        <td>${esc(a.status)}</td>
        <td class="nowrap">${esc(a.assessmentDate)}</td>
        <td><button class="small" data-tra="${esc(a.id)}">${canEdit() ? "Edit" : "View"}</button></td>
      </tr>`).join("");
    $("#empty-tra").classList.toggle("hidden", rows.length > 0);
    $("#empty-tra").textContent = list.length ? "No threat risk assessments match."
      : isViewer() ? "No threat risk assessments list you as the asset or risk owner. They appear here once you're named on one and your email is in the people directory."
      : "No threat risk assessments yet. Click “+ New assessment” to start one.";
    $("#tra-count").textContent = rows.length === list.length ? `${list.length} assessment${list.length === 1 ? "" : "s"}` : `Showing ${rows.length} of ${list.length} assessments`;
  }
  $("#tra-search").addEventListener("input", render);
  $("#tra-status-filter").addEventListener("change", render);
  $("#tra-rating-filter").addEventListener("change", render);

  // ---------- editor fields ----------
  const val = (path) => getPath(draft, path) ?? "";
  const opts = (choices, current, blank = "–") => `<option value="">${blank}</option>${choices.map((c) => {
    const [v, label] = Array.isArray(c) ? c : [c, c];
    return `<option value="${esc(v)}" ${String(v) === String(current) ? "selected" : ""}>${esc(label)}</option>`;
  }).join("")}`;
  const text = (path, label, extra = "") => `<label ${extra}>${label} <input data-path="${path}" value="${esc(val(path))}" maxlength="500" /></label>`;
  const area = (path, label, placeholder = "", rows = 3) => `<label class="full">${label} <textarea data-path="${path}" rows="${rows}" maxlength="5000" placeholder="${esc(placeholder)}">${esc(val(path))}</textarea></label>`;
  const select = (path, label, choices, extra = "") => `<label ${extra}>${label} <select data-path="${path}">${opts(choices, val(path))}</select></label>`;
  const owner = (path, label) => {
    const names = ownerNames(), v = val(path);
    if (!names.length) return text(path, label);
    const choices = names.map((n) => [n, n]);
    if (v && !names.includes(v)) choices.push([v, `${v} (not in directory)`]);
    return `<label>${label} <select data-path="${path}">${opts(choices, v)}</select></label>`;
  };
  const yesNo = (path, label) => `<div class="assess-q tra-yn"><span>${esc(label)}</span><select data-path="${path}" aria-label="${esc(label)}">${opts(["Yes", "No"], val(path))}</select></div>`;

  // ---------- step 1: asset profile ----------
  function profileStep() {
    const checks = (group, items, on) => `<fieldset class="checks">${items.map(([key, label]) => `<label><input type="checkbox" data-${group}="${key}" ${on(key) ? "checked" : ""} /> ${esc(label)}</label>`).join("")}</fieldset>`;
    return `<div class="form-grid">
        <label class="full">Asset name <input data-path="assetName" value="${esc(val("assetName"))}" required maxlength="200" placeholder="e.g. Customer billing system" /></label>
        ${owner("assetOwner", "Asset owner")}${owner("riskOwner", "Risk owner")}
        ${owner("analyst", "Risk analyst")}${text("department", "Business department")}
        <label>Assessment date <input type="date" data-path="assessmentDate" value="${esc(val("assessmentDate"))}" /></label>
        ${select("status", "Status", TRA_STATUSES)}
        ${area("description", "Description", "What the asset does and what it depends on")}
      </div>
      <h3 class="tra-h">Asset type</h3>
      <p class="muted small">Choose everything this asset includes. The controls come from these choices and the answers below.</p>
      ${checks("asset", ASSET_TYPES, (k) => draft.profile.assetTypes?.includes(k))}
      <h3 class="tra-h">Exposure</h3>
      <div class="assess-qs">${TRIGGERS.map((t) => yesNo(`profile.${t.key}`, t.label)).join("")}</div>
      <h3 class="tra-h">Sign-in methods</h3>
      ${checks("auth", AUTH_METHODS, (k) => draft.profile.auth?.[k])}
      <h3 class="tra-h">Other details</h3>
      <div class="form-grid">
        ${text("profile.vendor", "Vendor")}${text("profile.database", "Database")}
        ${select("profile.deployment", "Cloud deployment", ["Public", "Private", "Hybrid", "Community"])}
        ${select("profile.cloudModel", "Cloud model", ["SaaS", "PaaS", "IaaS"])}
        ${text("profile.location", "Data location")}${text("profile.ssoMethod", "Central sign-in method")}
        ${area("profile.notes", "Notes")}
      </div>
      <p class="small" id="tra-profile-count"></p>`;
  }

  // ---------- step 2: controls ----------
  function controlsStep() {
    const controls = controlsFor(draft);
    if (!controls.length) {
      return `<p class="muted">No controls yet. Choose an asset type in step 1.</p>`;
    }
    const shown = controls.filter((c) => {
      if (controlFilter === "open") return !draft.answers[c.id]?.status;
      if (controlFilter === "gaps") return isGap(draft, c);
      return true;
    });
    const sections = [...new Set(shown.map((c) => c.section))];
    const row = (c) => {
      const status = val(`answers.${c.id}.status`);
      return `<div class="tra-control" data-control="${esc(c.id)}">
        <div class="tra-control-head"><div><span class="tag">${esc(c.id)}</span> ${esc(c.text)} <span class="muted small">NIST ${esc(c.nist)}</span></div>
          <select data-path="answers.${c.id}.status" aria-label="Compliance with ${esc(c.id)}">${opts(COMPLIANCE, status)}</select></div>
        <input class="tra-evidence ${status ? "" : "hidden"}" data-path="answers.${c.id}.evidence" value="${esc(val(`answers.${c.id}.evidence`))}" maxlength="2000" placeholder="How do you comply? Add evidence or details" aria-label="Evidence" />
        <input class="tra-compensating ${status === "No" || status === "Partially" ? "" : "hidden"}" data-path="answers.${c.id}.compensating" value="${esc(val(`answers.${c.id}.compensating`))}" maxlength="2000" placeholder="Compensating controls, if any" aria-label="Compensating controls" />
      </div>`;
    };
    return `<p class="muted small">Answer each control. Every No or Partially becomes a gap to assess in step 3.</p>
      <div class="tra-filter"><label>Show <select id="tra-control-filter">
        <option value="" ${controlFilter === "" ? "selected" : ""}>All controls</option>
        <option value="open" ${controlFilter === "open" ? "selected" : ""}>Not answered</option>
        <option value="gaps" ${controlFilter === "gaps" ? "selected" : ""}>Gaps only</option>
      </select></label></div>
      ${sections.map((s, i) => `<details class="form-section-details assess-section" ${i === 0 ? "open" : ""}><summary>${esc(s)} <span class="muted small" data-section-count="${esc(s)}"></span></summary>${shown.filter((c) => c.section === s).map(row).join("")}</details>`).join("") || '<p class="muted">Nothing to show.</p>'}`;
  }

  // ---------- step 3: risk scoring ----------
  function scoringStep() {
    const s = summarize(draft);
    if (!s.gaps.length) return `<p class="muted">No gaps yet. Answer the controls in step 2; every No or Partially appears here.</p>`;
    const likelihoods = LIKELIHOODS.map(([name, , pct]) => [name, `${name} (${pct})`]);
    const card = ({ control: c, detail, managed, residual }) => `<div class="assess-row tra-gap">
        <div class="assess-row-head"><span class="tag">${esc(c.id)}</span><strong>${esc(c.section)}</strong></div>
        <p class="small tra-gap-text">${esc(c.gap)}</p>
        <div class="small muted">Threats</div>
        <fieldset class="checks">${c.threats.filter((id) => THREAT_BY_ID.has(id)).map((id) => {
          const t = THREAT_BY_ID.get(id);
          return `<label title="${esc(t.description)}"><input type="checkbox" data-threat="${esc(c.id)}:${esc(id)}" ${(detail.threats || []).includes(id) ? "checked" : ""} /> ${esc(t.name)}</label>`;
        }).join("")}</fieldset>
        <div class="form-grid">
          ${select(`gapDetails.${c.id}.likelihood`, "Likelihood", likelihoods)}
          <div class="tra-score"><span class="small muted">Managed risk</span><span data-score="${esc(c.id)}:likelihood">${scoreHtml(managed, detail.likelihood)}</span></div>
          ${area(`gapDetails.${c.id}.comment`, "Comment", "", 2)}
          ${select(`gapDetails.${c.id}.treatment`, "Treatment", TREATMENTS)}
          ${owner(`gapDetails.${c.id}.owner`, "Action owner")}
          ${area(`gapDetails.${c.id}.action`, "Details of the action", "", 2)}
          ${select(`gapDetails.${c.id}.residualLikelihood`, "Likelihood after treatment", likelihoods)}
          <div class="tra-score"><span class="small muted">Residual risk</span><span data-score="${esc(c.id)}:residualLikelihood">${scoreHtml(residual, detail.residualLikelihood)}</span></div>
        </div>
      </div>`;
    return `<details class="form-section-details assess-section"><summary>How scoring works</summary>
        <p class="small">Risk score = impact × likelihood. Both use the scale 1, 2, 5, 8, 10, and impact comes from the overall rating you set in step 4, so scores appear once that step is done. Treating a risk changes only its likelihood.</p>
        <p class="small">Very High 80–100 · High 50–79 · Moderate 16–49 · Low 4–15 · Very Low 1–2.</p>
      </details>
      <div class="assess-rows">${s.gaps.map(card).join("")}</div>`;
  }
  const scoreHtml = ({ score, level }, likelihood) => (score ? `${badge(level)} <span class="small muted">${score}</span>`
    : `<span class="muted small">${likelihood ? "Scored once impact is rated in step 4" : "Choose a likelihood"}</span>`);

  // ---------- step 4: impact ----------
  function impactStep() {
    const rowHtml = (r) => {
      const choices = [...r.levels.map((text, i) => [LETTERS[i], `${LETTERS[i]} – ${text}`]), ["NA", "Not applicable"]];
      const cell = (key, name) => `<select data-path="impact.${r.id}.${key}" aria-label="${esc(r.label)}: ${name}">${opts(choices, val(`impact.${r.id}.${key}`))}</select>`;
      return `<div class="tra-impact-row"><div>${esc(r.label)}<div class="muted small">${esc(r.measure)}</div></div>${cell("c", "confidentiality")}${cell("i", "integrity")}${cell("a", "availability")}</div>`;
    };
    const groups = [...new Set(IMPACT_ROWS.map((r) => r.group))];
    return `<h3 class="tra-h">Worst-case business impact</h3>
      <p class="muted small">For each row, choose the worst realistic result if the asset's information were disclosed (confidentiality), wrong or manipulated (integrity), or unavailable (availability).</p>
      <div class="tra-impact-row head"><span>Impact</span><span>Confidentiality</span><span>Integrity</span><span>Availability</span></div>
      ${groups.map((g) => `<div class="tra-group">${esc(g)}</div>${IMPACT_ROWS.filter((r) => r.group === g).map(rowHtml).join("")}`).join("")}
      <div class="risk-results tra-rating" id="tra-rating"></div>
      <p class="muted small" id="tra-impact-note"></p>`;
  }

  // ---------- step 5: summary ----------
  function summaryStep() {
    const s = summarize(draft);
    const tile = (label, inner) => `<div class="risk-result"><div class="small muted">${label}</div><div>${inner}</div></div>`;
    const table = (head, rows) => `<table class="tra-summary-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`;
    const levels = (counts) => RISK_LEVELS.map((l) => `<div class="tra-count">${badge(l)} <strong>${counts[l]}</strong></div>`).join("");
    const unassessed = s.gaps.length - s.assessed, unanswered = s.controls.length - s.answered;
    const todo = [unanswered && `${unanswered} control${unanswered === 1 ? "" : "s"} not answered`, unassessed && `${unassessed} gap${unassessed === 1 ? "" : "s"} without a likelihood`, !s.rating.overall && "business impact not rated"].filter(Boolean);
    return `${draft.status === "Completed" && draft.frozenControls ? `<p class="small muted">Completed with control library ${esc(draft.libraryVersion)}. Change the status to work on it again.</p>` : ""}
      ${todo.length ? `<p class="small tra-todo">Still to do: ${esc(todo.join(", "))}.</p>` : ""}
      <h3 class="tra-h">Impact</h3>
      <div class="risk-results tra-tiles">
        ${tile("Confidentiality", letterBadge(s.rating.c))}${tile("Integrity", letterBadge(s.rating.i))}${tile("Availability", letterBadge(s.rating.a))}${tile("Overall", letterBadge(s.rating.overall))}
      </div>
      <h3 class="tra-h">Risks</h3>
      <div class="risk-results tra-tiles">
        ${tile("Controls answered", `${s.answered} of ${s.controls.length}`)}${tile("Control gaps", s.gaps.length)}${tile("Highest managed risk", badge(s.highestManaged))}${tile("Highest residual risk", badge(s.highestResidual))}
      </div>
      <div class="tra-two">
        <div><div class="small muted">Managed risk</div>${levels(s.managedLevels)}</div>
        <div><div class="small muted">Residual risk</div>${levels(s.residualLevels)}</div>
        <div><div class="small muted">Treatment</div>${TREATMENTS.map((t) => `<div class="tra-count">${t} <strong>${s.treatments[t]}</strong></div>`).join("")}</div>
      </div>
      <h3 class="tra-h">Risk by threat category</h3>
      ${table(["Category", "Average score", "Level"], s.categories.map((c) => `<tr><td>${esc(c.category)}</td><td>${c.score ? Math.round(c.score) : "–"}</td><td>${badge(c.level)}</td></tr>`))}
      <h3 class="tra-h">Gaps by section</h3>
      ${table(["Section", "Controls", "Gaps"], s.sections.map((x) => `<tr><td>${esc(x.section)}</td><td>${x.controls}</td><td>${x.gaps}</td></tr>`))}
      <div class="form-grid tra-notes">${area("summaryNotes", "Summary notes", "", 4)}</div>`;
  }

  // ---------- drawing ----------
  const STEP_HTML = [profileStep, controlsStep, scoringStep, impactStep, summaryStep];
  function renderStep() {
    body.innerHTML = STEP_HTML[step]();
    for (const el of body.querySelectorAll(".form-grid, .assess-qs, fieldset.checks, .tra-impact-row, .tra-control")) el.inert = !canEdit();
    refreshDerived();
  }
  function refreshDerived() {
    const s = summarize(draft);
    const notes = [draft.profile.assetTypes?.length ? `${s.controls.length} controls` : "", s.controls.length ? `${s.answered} of ${s.controls.length}` : "",
      s.gaps.length ? `${s.assessed} of ${s.gaps.length}` : "", s.rating.overall ? LEVEL_NAME[s.rating.overall] : "", ""];
    $("#tra-steps").innerHTML = STEPS.map((name, i) => `<button type="button" class="tra-step ${i === step ? "active" : ""}" data-step="${i}" ${i === step ? 'aria-current="step"' : ""}>
        <span class="tra-step-num">${i + 1}</span><span>${name}<span class="tra-step-note">${esc(notes[i])}</span></span></button>`).join("");
    $("#btn-tra-prev").disabled = step === 0;
    $("#btn-tra-next").disabled = step === STEPS.length - 1;
    const rating = body.querySelector("#tra-rating");
    if (rating) {
      const tile = (label, letter) => `<div class="risk-result"><div class="small muted">${label}</div><div>${letterBadge(letter)}</div></div>`;
      rating.innerHTML = tile("Confidentiality", s.rating.c) + tile("Integrity", s.rating.i) + tile("Availability", s.rating.a) + tile("Overall business impact", s.rating.overall);
    }
    const count = body.querySelector("#tra-profile-count");
    if (count) {
      count.textContent = draft.profile.assetTypes?.length ? `${s.controls.length} controls apply to this asset.` : "Choose an asset type to see which controls apply.";
    }
    const impactNote = body.querySelector("#tra-impact-note");
    if (impactNote) impactNote.textContent = s.gaps.length ? `This rating scores the ${s.gaps.length} control gap${s.gaps.length === 1 ? "" : "s"} from step 3.` : "";
    for (const el of body.querySelectorAll("[data-section-count]")) {
      const section = s.controls.filter((c) => c.section === el.dataset.sectionCount);
      el.textContent = `${section.filter((c) => draft.answers[c.id]?.status).length} of ${section.length} answered`;
    }
  }
  function goTo(next) {
    step = next;
    renderStep();
    $("#tra-form").scrollTop = 0;
  }

  body.addEventListener("input", (e) => {
    const path = e.target.dataset.path;
    if (!path) return;
    setPath(draft, path, e.target.value);
    const answer = path.match(/^answers\.([\w-]+)\.status$/);
    if (answer) {
      const row = e.target.closest(".tra-control");
      row.querySelector(".tra-evidence").classList.toggle("hidden", !e.target.value);
      row.querySelector(".tra-compensating").classList.toggle("hidden", !["No", "Partially"].includes(e.target.value));
    }
    const likelihood = path.match(/^gapDetails\.([\w-]+)\.(likelihood|residualLikelihood)$/);
    if (likelihood) {
      const cell = body.querySelector(`[data-score="${likelihood[1]}:${likelihood[2]}"]`);
      cell.innerHTML = scoreHtml(scoreRisk(impactRating(draft.impact).overall, e.target.value), e.target.value);
    }
    refreshDerived();
  });
  body.addEventListener("change", (e) => {
    const { asset, auth, threat: threatPick } = e.target.dataset;
    if (asset) draft.profile.assetTypes = [...body.querySelectorAll("[data-asset]:checked")].map((c) => c.dataset.asset);
    if (auth) (draft.profile.auth ||= {})[auth] = e.target.checked;
    if (threatPick) {
      const [controlId, threatId] = threatPick.split(":");
      const detail = draft.gapDetails[controlId] ||= {};
      detail.threats = (detail.threats || []).filter((id) => id !== threatId);
      if (e.target.checked) detail.threats.push(threatId);
    }
    if (e.target.id === "tra-control-filter") { controlFilter = e.target.value; renderStep(); return; }
    if (asset || auth || threatPick) refreshDerived();
    if (e.target.dataset.path === "status") renderOutside();
  });
  $("#tra-steps").addEventListener("click", (e) => {
    const target = e.target.closest("[data-step]");
    if (target) goTo(Number(target.dataset.step));
  });
  $("#btn-tra-prev").addEventListener("click", () => goTo(step - 1));
  $("#btn-tra-next").addEventListener("click", () => goTo(step + 1));

  // ---------- input from someone without app access ----------
  const outsideBar = $("#tra-outside");
  let outsideState = null, freshLink = "", reviewing = false;
  const when = (iso) => (iso ? new Date(iso).toLocaleDateString() : "");
  function reviewHtml() {
    const { rows, removed, flagged } = outsideChanges(draft, outsideState.response);
    return `<div class="tra-review">
      ${flagged ? `<p class="small tra-todo"><strong>${flagged} change${flagged === 1 ? " makes" : "s make"} this asset look safer.</strong> Check the highlighted rows against evidence before applying.</p>` : ""}
      ${removed.length ? `<p class="small tra-todo">These answers remove ${removed.length} control${removed.length === 1 ? "" : "s"} from the assessment, including ${esc(removed.slice(0, 3).map((c) => c.id).join(", "))}.</p>` : ""}
      ${rows.length ? `<table class="tra-summary-table"><thead><tr><th>Item</th><th>Current</th><th>Submitted</th></tr></thead><tbody>
        ${rows.map((x) => `<tr class="${x.flag ? "tra-flag" : ""}"><td>${x.flag ? "⚠ " : ""}${esc(x.label)}</td><td>${esc(x.from) || '<span class="muted">–</span>'}</td><td>${esc(x.to) || '<span class="muted">–</span>'}</td></tr>`).join("")}
      </tbody></table>` : '<p class="small muted">These answers don\'t change anything.</p>'}
      <p class="tra-review-actions"><button type="button" class="small primary" id="btn-tra-apply">Apply these changes</button> <button type="button" class="small" id="btn-tra-review-close">Close</button></p>
    </div>`;
  }
  function renderOutside() {
    outsideBar.classList.toggle("hidden", !outside || !canEdit() || !draft);
    if (!outside || !draft) return;
    const intro = "<strong>Steps 1 and 2 from someone without app access.</strong>";
    if (!editingId) { outsideBar.innerHTML = `${intro} <span class="muted">Save this assessment first to create a link.</span>`; return; }
    const s = outsideState;
    if (!s) { outsideBar.innerHTML = `${intro} <span class="muted">Loading…</span>`; return; }
    const completed = draft.status === "Completed";
    const who = esc(s.response?.contributor?.name || "Someone");
    const email = s.response?.contributor?.email ? ` (${esc(s.response.contributor.email)})` : "";
    const applied = s.submittedAt && draft.outsideApplied?.at === s.submittedAt;
    const reply = !s.submittedAt ? "" : `<p class="small">${applied ? "Applied the" : "Not yet applied: the"} answers entered as ${who}${email} on ${esc(when(s.submittedAt))}. The name isn't verified.
        ${applied ? "" : completed ? '<span class="muted">Change the status from Completed to review them.</span>' : '<button type="button" class="small primary" id="btn-tra-review">Review changes</button>'}</p>
        ${reviewing && !applied && !completed ? reviewHtml() : ""}`;
    const started = s.draftUpdatedAt ? `<p class="small muted">${esc(s.draftBy || "Someone")} has started. Last saved ${esc(when(s.draftUpdatedAt))}, not submitted yet.</p>` : "";
    outsideBar.innerHTML = `<p class="small">${intro} ${s.expiresAt ? `A link is active until ${esc(when(s.expiresAt))}${s.shareExisting ? " and shows existing answers" : ""}.` : "There's no active link."}
        ${s.expiresAt ? '<button type="button" class="small" id="btn-tra-link-off">Turn off link</button>' : ""}</p>
      ${completed ? "" : `<p class="small tra-link-new"><label class="tra-share"><input type="checkbox" id="tra-link-share" /> Show existing answers on the form</label>
        <button type="button" class="small" id="btn-tra-link">${s.expiresAt ? "Create new link" : "Create link"}</button></p>`}
      ${freshLink ? `<div class="tra-link-row"><input id="tra-link-url" readonly value="${esc(freshLink)}" aria-label="Link to share" /><button type="button" class="small" id="btn-tra-link-copy">Copy</button></div>
        <p class="small muted">This is the only time this link is shown. It works for 14 days or until answers are submitted, and anyone who has it can use it, so share it only with the right person.</p>` : ""}
      ${started}${reply}`;
  }
  async function loadOutside() {
    if (!outside || !canEdit() || !editingId) return renderOutside();
    const id = editingId;
    try {
      const s = await outside.get(id);
      if (editingId === id) outsideState = s;
    } catch (err) {
      if (editingId === id) outsideBar.innerHTML = `<p class="small error-text">Couldn't load the link details: ${esc(err.message)}</p>`;
      return;
    }
    if (editingId === id) renderOutside();
  }
  outsideBar.addEventListener("click", async (e) => {
    const id = e.target.id;
    try {
      if (id === "btn-tra-link") {
        if (outsideState?.expiresAt && !confirm("Create a new link? The current link will stop working, and any answers not yet submitted are discarded.")) return;
        const url = new URL("tra-form.html", location.href);
        url.search = new URLSearchParams({ t: await outside.create(editingId, $("#tra-link-share").checked) }).toString();
        freshLink = url.href;
        await loadOutside();
      } else if (id === "btn-tra-link-off") {
        if (!confirm("Turn off this link? It will stop working straight away, and any answers not yet submitted are discarded.")) return;
        await outside.revoke(editingId);
        freshLink = "";
        await loadOutside();
      } else if (id === "btn-tra-link-copy") {
        await navigator.clipboard.writeText(freshLink);
        toast("Link copied");
      } else if (id === "btn-tra-review" || id === "btn-tra-review-close") {
        reviewing = id === "btn-tra-review";
        renderOutside();
      } else if (id === "btn-tra-apply") {
        const { flagged, answered } = outsideChanges(draft, outsideState.response);
        if (flagged && !confirm(`${flagged} change${flagged === 1 ? " makes" : "s make"} this asset look safer. Apply anyway?`)) return;
        const by = short(outsideState.response?.contributor?.name, 200);
        draft = { ...applyOutsideResponse(draft, outsideState.response), outsideApplied: { at: outsideState.submittedAt, by } };
        step = 0;
        reviewing = false;
        renderStep();
        renderOutside();
        toast(`Applied ${answered} control answer${answered === 1 ? "" : "s"}. Check them, then save.`);
      }
    } catch (err) {
      toast(err.message, true);
    }
  });

  // ---------- open / close / save ----------
  const state = () => JSON.stringify(draft);
  function open(a) {
    editingId = a?.id ?? null;
    draft = a ? { ...blankThreatAssessment(), ...structuredClone(a) } : blankThreatAssessment();
    draft.profile = { assetTypes: [], auth: {}, ...draft.profile };
    step = 0;
    controlFilter = "";
    $("#tra-title").textContent = a ? `${a.id} · ${a.assetName || "Assessment"}` : "New threat risk assessment";
    $("#btn-tra-delete").classList.toggle("hidden", !a);
    outsideState = null;
    freshLink = "";
    reviewing = false;
    renderStep();
    snapshot = state();
    renderOutside();
    loadOutside();
    if (splitView.matches) {
      document.documentElement.style.setProperty("--topbar-h", `${$(".topbar").offsetHeight}px`);
      document.body.classList.add("tra-split");
      if (!dialog.open) dialog.show();
    } else if (!dialog.open) {
      dialog.showModal();
    }
    $("#tra-form").scrollTop = 0;
    render();
  }
  const confirmDiscard = () => !dialog.open || !canEdit() || state() === snapshot || confirm("Discard your unsaved changes to this assessment?");
  function hide() {
    if (dialog.open) dialog.close();
    document.body.classList.remove("tra-split");
    draft = null; editingId = null;
    render();
  }
  function close() {
    if (!confirmDiscard()) return false;
    hide();
    return true;
  }

  $("#btn-tra-add").addEventListener("click", () => { if (confirmDiscard()) open(null); });
  $("#btn-tra-close").addEventListener("click", close);
  $("#btn-tra-cancel").addEventListener("click", close);
  dialog.addEventListener("cancel", (e) => { e.preventDefault(); close(); });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && dialog.open && document.body.classList.contains("tra-split")) close();
  });
  document.addEventListener("click", (e) => {
    const id = e.target.closest("[data-tra]")?.dataset.tra;
    if (!id || (dialog.open && editingId === id)) return;
    if (confirmDiscard()) open(list.find((a) => a.id === id));
  });
  $("#btn-tra-delete").addEventListener("click", () => {
    if (!editingId || !confirm(`Delete ${editingId}? This can't be undone.`)) return;
    list = list.filter((a) => a.id !== editingId);
    hide();
    save();
    toast("Assessment deleted");
  });
  $("#tra-form").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!canEdit()) return;
    if (!draft.assetName?.trim()) {
      goTo(0);
      return toast("Add the asset name first", true);
    }
    if (draft.status === "Completed") {
      const s = summarize(draft);
      if ((s.answered < s.controls.length || s.assessed < s.gaps.length || !s.controls.length || !s.rating.overall)
        && !confirm("Some steps aren't finished. Mark this assessment Completed anyway?")) return;
    }
    const now = new Date().toISOString();
    const saved = prepareForSave(draft);
    if (editingId) list = list.map((a) => (a.id === editingId ? { ...saved, id: editingId, updated: now } : a));
    else list.push({ ...saved, id: nextId(), created: now });
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
      for (const a of items) list.push({ ...a, id: /^T-\d{3,6}$/.test(a.id) && !list.some((x) => x.id === a.id) ? a.id : nextId() });
      save(); render();
    },
  };
}
