// Threat risk assessments: rate the business impact of one asset, describe it, answer the
// security controls that apply, then score each control gap. The controls, threats and scales
// are in tra-library.js.

import { LIBRARY_VERSION, IMPACT_LEVELS, IMPACT_ROWS, LIKELIHOODS, TREATMENTS, COMPLIANCE, ASSET_TYPES, TRIGGERS, AUTH_METHODS,
  THREATS, THREAT_CATEGORIES, CONTROLS } from "./tra-library.js";

export const TRA_STATUSES = ["In progress", "On hold", "Completed"];
const LETTERS = IMPACT_LEVELS.map(([letter]) => letter);
const LEVEL_NAME = Object.fromEntries(IMPACT_LEVELS.map(([letter, name]) => [letter, name]));
const IMPACT_VALUE = Object.fromEntries(IMPACT_LEVELS.map(([letter, , value]) => [letter, value]));
const LIKELIHOOD_VALUE = Object.fromEntries(LIKELIHOODS.map(([name, value]) => [name, value]));
const THREAT_BY_ID = new Map(THREATS.map((t) => [t.id, t]));
const RISK_LEVELS = ["Very High", "High", "Moderate", "Low", "Very Low"];
const STEPS = ["Impact", "Asset profile", "Controls", "Risk scoring", "Summary"];

const worst = (letters) => LETTERS.find((l) => letters.includes(l)) ?? null;

// The worst answer in each column sets confidentiality, integrity and availability; the worst
// of those three sets the overall rating. Not applicable and blank answers don't count.
export function impactRating(impact = {}) {
  const column = (key) => worst(IMPACT_ROWS.map((r) => impact[r.id]?.[key]));
  const c = column("c"), i = column("i"), a = column("a");
  return { c, i, a, overall: worst([c, i, a]) };
}

const tierApplies = (tier, overall) => tier === "L" || (tier === "M" && "ABC".includes(overall)) || (tier === "H" && "AB".includes(overall));

function triggerFires(on, profile) {
  if (on === "general") return true;
  if (AUTH_METHODS.some(([key]) => key === on)) return !!profile.auth?.[on];
  const trigger = TRIGGERS.find((t) => t.key === on);
  if (!trigger || (trigger.onlyFor && !profile.assetTypes?.includes(trigger.onlyFor))) return false;
  return profile[on] === trigger.when;
}

// The controls that apply to an assessment's impact rating and asset profile. Each control
// appears once, however many of its rules fire.
export function selectControls(a) {
  const { overall } = impactRating(a.impact);
  const profile = a.profile || {};
  if (!overall || !profile.assetTypes?.length) return [];
  return CONTROLS.filter((c) => c.assets.some((t) => profile.assetTypes.includes(t))
    && c.rules.some((r) => tierApplies(r.tier, overall) && triggerFires(r.on, profile)));
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
    scored: gaps.filter((g) => g.managed.score).length,
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

const getPath = (obj, path) => path.split(".").reduce((o, k) => (o == null ? undefined : o[k]), obj);
function setPath(obj, path, value) {
  const keys = path.split(".");
  let o = obj;
  for (const k of keys.slice(0, -1)) o = o[k] ??= {};
  o[keys.at(-1)] = value;
}

export function initThreatAssessments({ $, escapeHtml: esc, toast, initial, persist, canEdit, ownerNames, onChange }) {
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
    $("#empty-tra").textContent = list.length ? "No threat risk assessments match." : "No threat risk assessments yet. Click “+ New assessment” to start one.";
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

  // ---------- step 1: impact ----------
  function impactStep() {
    const rowHtml = (r) => {
      const choices = [...r.levels.map((text, i) => [LETTERS[i], `${LETTERS[i]} – ${text}`]), ["NA", "Not applicable"]];
      const cell = (key, name) => `<select data-path="impact.${r.id}.${key}" aria-label="${esc(r.label)}: ${name}">${opts(choices, val(`impact.${r.id}.${key}`))}</select>`;
      return `<div class="tra-impact-row"><div>${esc(r.label)}<div class="muted small">${esc(r.measure)}</div></div>${cell("c", "confidentiality")}${cell("i", "integrity")}${cell("a", "availability")}</div>`;
    };
    const groups = [...new Set(IMPACT_ROWS.map((r) => r.group))];
    return `<div class="form-grid">
        <label class="full">Asset name <input data-path="assetName" value="${esc(val("assetName"))}" required maxlength="200" placeholder="e.g. Customer billing system" /></label>
        ${owner("assetOwner", "Asset owner")}${owner("riskOwner", "Risk owner")}
        ${owner("analyst", "Risk analyst")}${text("department", "Business department")}
        <label>Assessment date <input type="date" data-path="assessmentDate" value="${esc(val("assessmentDate"))}" /></label>
        ${select("status", "Status", TRA_STATUSES)}
        ${area("description", "Description", "What the asset does and what it depends on")}
      </div>
      <h3 class="tra-h">Worst-case business impact</h3>
      <p class="muted small">For each row, choose the worst realistic result if the asset's information were disclosed (confidentiality), wrong or manipulated (integrity), or unavailable (availability).</p>
      <div class="tra-impact-row head"><span>Impact</span><span>Confidentiality</span><span>Integrity</span><span>Availability</span></div>
      ${groups.map((g) => `<div class="tra-group">${esc(g)}</div>${IMPACT_ROWS.filter((r) => r.group === g).map(rowHtml).join("")}`).join("")}
      <div class="risk-results tra-rating" id="tra-rating"></div>`;
  }

  // ---------- step 2: asset profile ----------
  function profileStep() {
    const checks = (group, items, on) => `<fieldset class="checks">${items.map(([key, label]) => `<label><input type="checkbox" data-${group}="${key}" ${on(key) ? "checked" : ""} /> ${esc(label)}</label>`).join("")}</fieldset>`;
    return `<h3 class="tra-h">Asset type</h3>
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

  // ---------- step 3: controls ----------
  function controlsStep() {
    const controls = controlsFor(draft);
    if (!controls.length) {
      return `<p class="muted">No controls yet. Rate the business impact in step 1 and choose an asset type in step 2.</p>`;
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
    return `<p class="muted small">Answer each control. Every No or Partially becomes a gap to score in step 4.</p>
      <div class="tra-filter"><label>Show <select id="tra-control-filter">
        <option value="" ${controlFilter === "" ? "selected" : ""}>All controls</option>
        <option value="open" ${controlFilter === "open" ? "selected" : ""}>Not answered</option>
        <option value="gaps" ${controlFilter === "gaps" ? "selected" : ""}>Gaps only</option>
      </select></label></div>
      ${sections.map((s, i) => `<details class="form-section-details assess-section" ${i === 0 ? "open" : ""}><summary>${esc(s)} <span class="muted small" data-section-count="${esc(s)}"></span></summary>${shown.filter((c) => c.section === s).map(row).join("")}</details>`).join("") || '<p class="muted">Nothing to show.</p>'}`;
  }

  // ---------- step 4: risk scoring ----------
  function scoringStep() {
    const s = summarize(draft);
    if (!s.gaps.length) return `<p class="muted">No gaps yet. Answer the controls in step 3; every No or Partially appears here.</p>`;
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
          <div class="tra-score"><span class="small muted">Managed risk</span><span data-score="${esc(c.id)}:likelihood">${scoreHtml(managed)}</span></div>
          ${area(`gapDetails.${c.id}.comment`, "Comment", "", 2)}
          ${select(`gapDetails.${c.id}.treatment`, "Treatment", TREATMENTS)}
          ${owner(`gapDetails.${c.id}.owner`, "Action owner")}
          ${area(`gapDetails.${c.id}.action`, "Details of the action", "", 2)}
          ${select(`gapDetails.${c.id}.residualLikelihood`, "Likelihood after treatment", likelihoods)}
          <div class="tra-score"><span class="small muted">Residual risk</span><span data-score="${esc(c.id)}:residualLikelihood">${scoreHtml(residual)}</span></div>
        </div>
      </div>`;
    return `<details class="form-section-details assess-section"><summary>How scoring works</summary>
        <p class="small">Risk score = impact × likelihood. Both use the scale 1, 2, 5, 8, 10, and impact comes from the overall rating in step 1. Treating a risk changes only its likelihood.</p>
        <p class="small">Very High 80–100 · High 50–79 · Moderate 16–49 · Low 4–15 · Very Low 1–2.</p>
      </details>
      <div class="assess-rows">${s.gaps.map(card).join("")}</div>`;
  }
  const scoreHtml = ({ score, level }) => (score ? `${badge(level)} <span class="small muted">${score}</span>` : '<span class="muted small">Choose a likelihood</span>');

  // ---------- step 5: summary ----------
  function summaryStep() {
    const s = summarize(draft);
    const tile = (label, inner) => `<div class="risk-result"><div class="small muted">${label}</div><div>${inner}</div></div>`;
    const table = (head, rows) => `<table class="tra-summary-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`;
    const levels = (counts) => RISK_LEVELS.map((l) => `<div class="tra-count">${badge(l)} <strong>${counts[l]}</strong></div>`).join("");
    const unscored = s.gaps.length - s.scored, unanswered = s.controls.length - s.answered;
    const todo = [unanswered && `${unanswered} control${unanswered === 1 ? "" : "s"} not answered`, unscored && `${unscored} gap${unscored === 1 ? "" : "s"} not scored`].filter(Boolean);
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
  const STEP_HTML = [impactStep, profileStep, controlsStep, scoringStep, summaryStep];
  function renderStep() {
    body.innerHTML = STEP_HTML[step]();
    for (const el of body.querySelectorAll(".form-grid, .assess-qs, fieldset.checks, .tra-impact-row, .tra-control")) el.inert = !canEdit();
    refreshDerived();
  }
  function refreshDerived() {
    const s = summarize(draft);
    const notes = [s.rating.overall ? LEVEL_NAME[s.rating.overall] : "", draft.profile.assetTypes?.length ? `${s.controls.length} controls` : "",
      s.controls.length ? `${s.answered} of ${s.controls.length}` : "", s.gaps.length ? `${s.scored} of ${s.gaps.length}` : "", ""];
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
      count.textContent = !s.rating.overall ? "Rate the business impact in step 1 to see which controls apply."
        : !draft.profile.assetTypes?.length ? "Choose an asset type to see which controls apply."
        : `${s.controls.length} controls apply at ${LEVEL_NAME[s.rating.overall]} impact.`;
    }
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
      cell.innerHTML = scoreHtml(scoreRisk(impactRating(draft.impact).overall, e.target.value));
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
  });
  $("#tra-steps").addEventListener("click", (e) => {
    const target = e.target.closest("[data-step]");
    if (target) goTo(Number(target.dataset.step));
  });
  $("#btn-tra-prev").addEventListener("click", () => goTo(step - 1));
  $("#btn-tra-next").addEventListener("click", () => goTo(step + 1));

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
    renderStep();
    snapshot = state();
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
      if ((s.answered < s.controls.length || s.scored < s.gaps.length || !s.controls.length)
        && !confirm("Some controls or gaps aren't finished. Mark this assessment Completed anyway?")) return;
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
