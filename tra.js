// Threat posture assessments: describe one asset, answer the security controls that apply, assess
// the threats and likelihood of each control gap, then rate the business impact, which completes
// the risk scores. The controls, threats and scales are in tra-library.js.
//
// The workspace chooses a NIST framework (CSF 2.0 or SP 800-53). It sets how controls are
// grouped and which reference each one shows. Answers are stored by control ID, so they carry
// over when the framework changes.

import { tableDate } from "./dates.js";
import { levelBadge } from "./levels.js";
import { standardsPromptText } from "./standards.js";
import { logoImg } from "./logo.js";
import { LIBRARY_VERSION, IMPACT_LEVELS, IMPACT_ROWS, LIKELIHOODS, TREATMENTS, COMPLIANCE, ASSET_TYPES, TRIGGERS, AUTH_METHODS,
  THREATS, THREAT_CATEGORIES, CONTROLS, FRAMEWORKS, CSF_FUNCTIONS, CSF_CATEGORIES, SP80053_FAMILIES } from "./tra-library.js";

export const TRA_STATUSES = ["In progress", "On hold", "Completed"];
const LETTERS = IMPACT_LEVELS.map(([letter]) => letter);
const LEVEL_NAME = Object.fromEntries(IMPACT_LEVELS.map(([letter, name]) => [letter, name]));
const IMPACT_VALUE = Object.fromEntries(IMPACT_LEVELS.map(([letter, , value]) => [letter, value]));
const LIKELIHOOD_VALUE = Object.fromEntries(LIKELIHOODS.map(([name, value]) => [name, value]));
const THREAT_BY_ID = new Map(THREATS.map((t) => [t.id, t]));
const RISK_LEVELS = ["Very High", "High", "Moderate", "Low", "Very Low"];
const STEPS = ["Impact", "Asset profile", "Controls", "Risk scoring", "Summary"];

// ---------- frameworks ----------
// Used to show assessments while a workspace hasn't chosen yet. New assessments wait for a choice.
export const DEFAULT_FRAMEWORK = "sp80053";
export const isFramework = (key) => FRAMEWORKS.some(([k]) => k === key);
export const frameworkName = (key, short = false) => FRAMEWORKS.find(([k]) => k === key)?.[short ? 2 : 1] || "";
const GROUP_NOUN = { csf2: "category", sp80053: "control family" };
const GROUP_ORDER = { csf2: Object.keys(CSF_CATEGORIES), sp80053: Object.keys(SP80053_FAMILIES) };
const CONTROL_BY_ID = new Map(CONTROLS.map((c) => [c.id, c]));

// A completed assessment keeps the framework it was completed under; the rest follow the workspace.
export function frameworkOf(a, current) {
  if (a?.status === "Completed" && isFramework(a.framework)) return a.framework;
  return isFramework(current) ? current : DEFAULT_FRAMEWORK;
}

// A control as a framework shows it: `ref` is its reference there and `group` the CSF category
// or 800-53 family it's listed under. Controls frozen by an older library take any reference
// they're missing from the current one.
export function inFramework(control, framework) {
  const c = { ...CONTROL_BY_ID.get(control.id), ...control };
  const csf = framework === "csf2" && c.csf;
  const key = (csf ? c.csf : c.nist).split("-")[0];
  const group = csf ? `${CSF_FUNCTIONS[key.slice(0, 2)]}: ${CSF_CATEGORIES[key]} (${key})` : `${SP80053_FAMILIES[key]} (${key})`;
  return { ...c, ref: csf ? c.csf : c.nist, group, rank: GROUP_ORDER[csf ? "csf2" : "sp80053"].indexOf(key) };
}

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

// An assessment's controls as its framework shows them, in the framework's order: by group, then
// by reference, so controls sharing a reference sit together. A completed
// assessment keeps the controls it was completed with, so later library changes don't alter it.
export function controlsFor(a, framework) {
  const fw = frameworkOf(a, framework);
  const controls = a.status === "Completed" && a.frozenControls ? a.frozenControls : selectControls(a);
  return controls.map((c) => inFramework(c, fw)).sort((x, y) => x.rank - y.rank || x.ref.localeCompare(y.ref, "en", { numeric: true }));
}

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

export function summarize(a, framework) {
  const rating = impactRating(a.impact);
  const controls = controlsFor(a, framework);
  const gaps = controls.filter((c) => isGap(a, c)).map((control) => {
    const detail = a.gapDetails?.[control.id] || {};
    return { control, detail, managed: scoreRisk(rating.overall, detail.likelihood), residual: scoreRisk(rating.overall, detail.residualLikelihood) };
  });
  const count = (list, pick, value) => list.filter((x) => pick(x) === value).length;
  const sections = [...new Set(controls.map((c) => c.group))].map((section) => ({
    section,
    controls: count(controls, (c) => c.group, section),
    gaps: gaps.filter((g) => g.control.group === section).length,
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

// ---------- PDF report ----------
// A print-ready threat posture assessment report (printed to PDF with the browser's "Save as PDF"), styled like
// the other reports (the .pr-* classes in styles.css). Sections with nothing to show are left out. The AI review's
// likelihoods and comments are already in the control gaps, so only its summary is added.
const REPORT_BADGE = { "Very High": "critical", High: "high", Moderate: "medium", Low: "low", "Very Low": "low" };
export function traReportHtml(a, { esc, org = "", logo = "", id = "", framework, generated = new Date() }) {
  const fw = frameworkOf(a, framework);
  const s = summarize(a, fw);
  const has = (x) => (Array.isArray(x) ? x.length > 0 : typeof x === "string" ? x.trim() !== "" : x != null);
  const dash = '<span class="pr-muted">–</span>';
  const cell = (t) => esc(t || "").replace(/\n/g, "<br>");
  const date = (d) => (/^\d{4}-\d{2}-\d{2}/.test(d || "") ? new Date(`${d.slice(0, 10)}T00:00:00`).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : esc(d || ""));
  const badge = (level) => (level ? `<span class="pr-badge ${REPORT_BADGE[level] || "neutral"}">${esc(level)}</span>` : dash);
  const scored = ({ score, level }) => (score ? `${badge(level)} <span class="pr-muted">${score}</span>` : dash);
  const letter = (l) => (l ? badge(LEVEL_NAME[l]) : dash);
  const sec = (title, inner) => (inner ? `<section class="pr-section"><h2>${esc(title)}</h2>${inner}</section>` : "");
  const rows = (pairs) => pairs.filter(([, v]) => has(v)).map(([label, v]) => `<tr><th>${label}</th><td>${v}</td></tr>`).join("");
  const facts = (pairs) => { const body = rows(pairs); return body ? `<table class="pr-table pr-summary"><tbody>${body}</tbody></table>` : ""; };
  // A column is [heading, narrow] or [heading, false, "14%"]: a width makes the table fixed so long text wraps in its column.
  const grid = (head, body) => `<table class="pr-table"${head.some(([, , w]) => w) ? ' style="table-layout:fixed"' : ""}><thead><tr>${head.map(([h, narrow, w]) => `<th${narrow ? ' class="pr-narrow"' : ""}${w ? ` style="width:${w}"` : ""}>${h}</th>`).join("")}</tr></thead><tbody>${body.join("")}</tbody></table>`;
  const noun = GROUP_NOUN[fw];
  const profile = a.profile || {};

  // Impact: only rows that were rated.
  const rated = IMPACT_ROWS.filter((r) => ["c", "i", "a"].some((k) => a.impact?.[r.id]?.[k]));
  const impactCell = (r, key) => {
    const l = a.impact?.[r.id]?.[key];
    return l === "NA" ? '<span class="pr-muted">Not applicable</span>' : l ? `${esc(l)} – ${esc(r.levels[LETTERS.indexOf(l)] || "")}` : dash;
  };
  const impactBody = rated.length || s.rating.overall
    ? `<table class="pr-table pr-summary"><tbody>${rows([["Confidentiality", letter(s.rating.c)], ["Integrity", letter(s.rating.i)], ["Availability", letter(s.rating.a)], ["Overall business impact", letter(s.rating.overall)]])}</tbody></table>
      ${rated.length ? `<h3>Impact ratings</h3>${grid([["Impact"], ["Confidentiality"], ["Integrity"], ["Availability"]],
        rated.map((r) => `<tr><td>${esc(r.label)}<div class="pr-muted">${esc(r.measure)}</div></td><td>${impactCell(r, "c")}</td><td>${impactCell(r, "i")}</td><td>${impactCell(r, "a")}</td></tr>`))}` : ""}` : "";

  // Asset profile.
  const types = (profile.assetTypes || []).map((k) => ASSET_TYPES.find(([key]) => key === k)?.[1] || k);
  const exposure = TRIGGERS.filter((t) => profile[t.key] === "Yes" || profile[t.key] === "No").map((t) => [esc(t.label), `<span class="pr-pill ${profile[t.key] === "Yes" ? "yes" : "no"}">${profile[t.key]}</span>`]);
  const signIn = AUTH_METHODS.filter(([k]) => profile.auth?.[k]).map(([, label]) => label);
  const profileBody = facts([["Asset types", esc(types.join(", "))], ...exposure, ["Sign-in methods", esc(signIn.join(", "))], ["Vendor", esc(profile.vendor)], ["Database", esc(profile.database)],
    ["Cloud deployment", esc(profile.deployment)], ["Cloud model", esc(profile.cloudModel)], ["Data location", esc(profile.location)], ["Central sign-in method", esc(profile.ssoMethod)], ["Notes", cell(profile.notes)]]);

  // Risk summary.
  const counts = (m) => RISK_LEVELS.map((l) => `<tr><td>${badge(l)}</td><td>${m[l]}</td></tr>`);
  const riskBody = s.gaps.length
    ? `${grid([["Risk level"], ["Managed risk", true], ["Residual risk", true]], RISK_LEVELS.map((l) => `<tr><td>${badge(l)}</td><td>${s.managedLevels[l]}</td><td>${s.residualLevels[l]}</td></tr>`))}
      ${s.treatments && Object.values(s.treatments).some(Boolean) ? `<h3>Treatment</h3>${grid([["Treatment"], ["Gaps", true]], TREATMENTS.map((t) => `<tr><td>${esc(t)}</td><td>${s.treatments[t]}</td></tr>`))}` : ""}
      ${s.categories.some((c) => c.score) ? `<h3>Risk by threat category</h3>${grid([["Category"], ["Average score", true], ["Level", true]], s.categories.map((c) => `<tr><td>${esc(c.category)}</td><td>${c.score ? Math.round(c.score) : "–"}</td><td>${badge(c.level)}</td></tr>`))}` : ""}
      <h3>Gaps by ${esc(frameworkName(fw, true))} ${noun}</h3>${grid([[noun === "category" ? "Category" : "Control family"], ["Controls", true], ["Gaps", true]], s.sections.map((x) => `<tr><td>${esc(x.section)}</td><td>${x.controls}</td><td>${x.gaps}</td></tr>`))}` : "";

  // The control gaps, with how each is scored and treated.
  const gapBody = s.gaps.length
    ? grid([["Control", false, "12%"], ["Gap and threats", false, "28%"], ["Managed", false, "18%"], ["Treatment", false, "24%"], ["After treatment", false, "18%"]], s.gaps.map(({ control: c, detail, managed, residual }) => {
        const threats = (detail.threats || []).map((t) => THREAT_BY_ID.get(t)?.name).filter(Boolean);
        const action = [detail.treatment && `<strong>${esc(detail.treatment)}</strong>`, detail.owner && `Owner: ${esc(detail.owner)}`, detail.action && cell(detail.action)].filter(Boolean).join("<br>");
        return `<tr><td><span class="pr-id">${esc(c.ref)}</span><div class="pr-muted">${esc(c.group)}</div></td>
          <td>${esc(c.gap)}${threats.length ? `<div class="pr-muted">Threats: ${esc(threats.join(", "))}</div>` : ""}${detail.comment ? `<div>${cell(detail.comment)}</div>` : ""}</td>
          <td>${detail.likelihood ? `${esc(detail.likelihood)}<br>` : ""}${scored(managed)}</td><td>${action || dash}</td>
          <td>${detail.residualLikelihood ? `${esc(detail.residualLikelihood)}<br>` : ""}${scored(residual)}</td></tr>`;
      }))
    : "";

  return `<article class="pr-doc pr-tra">
    <header class="pr-cover">
      <div class="pr-cover-top"><span class="pr-brand">${logo}<span>${esc(org || "Posture.ai")}</span></span><span>Threat Posture Assessment · ${esc(id)}</span></div>
      <div class="pr-eyebrow">Threat Posture Assessment</div>
      <h1>${esc(a.assetName || "Untitled asset")}</h1>
      <div class="pr-cover-meta">${[a.status, frameworkName(fw)].filter(Boolean).map(esc).join(" · ")}</div>
      <div class="pr-verdict">
        <div class="pr-verdict-item"><small>Business impact</small>${letter(s.rating.overall)}</div>
        <div class="pr-verdict-item"><small>Highest managed risk</small>${badge(s.highestManaged)}</div>
        <div class="pr-verdict-item"><small>Highest residual risk</small>${badge(s.highestResidual)}</div>
        <div class="pr-verdict-item"><small>Control gaps</small><strong>${s.gaps.length}</strong></div>
      </div>
    </header>

    <section class="pr-section pr-exec">
      <h2>Assessment summary</h2>
      ${facts([["Asset", esc(a.assetName)], ["Assessment ID", esc(id)], ["Status", esc(a.status)], ["Assessment date", date(a.assessmentDate)], ["Asset owner", esc(a.assetOwner)], ["Risk owner", esc(a.riskOwner)],
        ["Risk analyst", esc(a.analyst)], ["Business department", esc(a.department)], ["Description", cell(a.description)], ["Framework", esc(frameworkName(fw))],
        ["Control library", esc(a.libraryVersion ? `Version ${a.libraryVersion}` : "")], ["Controls answered", `${s.answered} of ${s.controls.length}`],
        ["Control gaps scored", s.gaps.length ? `${s.assessed} of ${s.gaps.length}` : ""]])}
    </section>

    ${sec("Business impact", impactBody)}
    ${sec("Asset profile", profileBody)}
    ${sec("Risk summary", riskBody)}
    ${sec("Control gaps", gapBody)}
    ${a.aiAssessment ? sec(`AI review · ${date(a.aiAssessment.at)}`.replace(/ · $/, ""), `<div class="pr-callout"><p>${esc(a.aiAssessment.summary || "The review is complete.")}</p></div><p class="pr-muted">The likelihoods the AI chose, and its comments where it wrote them, are in the control gaps above.</p>`) : ""}
    ${sec("Summary notes", has(a.summaryNotes) ? esc(a.summaryNotes).split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("") : "")}

    <footer class="pr-foot">${esc(org ? `${org} · ` : "")}Confidential · ${esc(id)} · Generated ${esc(generated.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }))} with Posture.ai</footer>
  </article>`;
}

export function blankThreatAssessment() {
  return { status: "In progress", assessmentDate: new Date().toISOString().slice(0, 10), libraryVersion: LIBRARY_VERSION,
    impact: {}, profile: { assetTypes: [], auth: {} }, answers: {}, gapDetails: {} };
}

// What's stored when saving: completing freezes the controls and the framework in use, and
// reopening releases them.
export function prepareForSave(a, framework) {
  const out = { ...a };
  const current = () => { if (isFramework(framework)) out.framework = framework; else delete out.framework; };
  if (out.status !== "Completed") { delete out.frozenControls; out.libraryVersion = LIBRARY_VERSION; current(); }
  else if (!out.frozenControls) { out.frozenControls = selectControls(out); out.libraryVersion = LIBRARY_VERSION; current(); }
  return out;
}

// ---------- answers from someone without app access ----------
const OUTSIDE_TEXT = ["vendor", "database", "deployment", "cloudModel", "location", "ssoMethod", "notes"];
const short = (value, max = 2000) => (typeof value === "string" ? value.slice(0, max) : "");

// Worst-case impact ratings from the outside form: a letter per impact row and column, or NA.
const IMPACT_KEYS = { c: "confidentiality", i: "integrity", a: "availability" };
const IMPACT_CHOICES = [...LETTERS, "NA"];
export function cleanImpact(raw) {
  const out = {};
  if (!raw || typeof raw !== "object") return out;
  for (const row of IMPACT_ROWS) {
    const v = raw[row.id];
    if (!v || typeof v !== "object") continue;
    const cell = Object.fromEntries(Object.keys(IMPACT_KEYS).filter((k) => IMPACT_CHOICES.includes(v[k])).map((k) => [k, v[k]]));
    if (Object.keys(cell).length) out[row.id] = cell;
  }
  return out;
}

// Keeps only what the outside form may set: known questions, controls, answers and impact
// ratings. Owners, status and gaps can't be set this way.
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
  const clean = { profile, answers, impact: cleanImpact(r.impact) };
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
  out.impact = { ...out.impact };
  for (const [id, cell] of Object.entries(r.impact)) out.impact[id] = { ...out.impact[id], ...cell };
  return out;
}

// What applying a response would change, for the analyst to check first. Flagged rows make the
// asset look safer than before: a gap marked as met, or exposure answered away.
export function outsideChanges(a, response, framework) {
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
  const impactText = (row, letter) => (letter === "NA" ? "Not applicable" : letter ? `${letter} – ${row.levels[LETTERS.indexOf(letter)]}` : "");
  for (const row of IMPACT_ROWS) {
    if (!r.impact[row.id]) continue;
    for (const key of Object.keys(IMPACT_KEYS)) {
      add(`Impact: ${row.label} (${IMPACT_KEYS[key]})`, impactText(row, a.impact?.[row.id]?.[key]), impactText(row, next.impact[row.id]?.[key]));
    }
  }
  for (const id of Object.keys(r.answers)) {
    const was = a.answers?.[id] || {}, now = next.answers[id];
    const c = inFramework(CONTROL_BY_ID.get(id), frameworkOf(a, framework));
    const title = `${c.ref}: ${c.text}`;
    add(title, was.status, now.status, WEAK.includes(was.status) && STRONG.includes(now.status));
    add(`Evidence for ${title}`, was.evidence, now.evidence);
    add(`Compensating controls for ${title}`, was.compensating, now.compensating);
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

// The AI review of the gap scoring, laid out like the PDF reports and the vendor review (the .pr-* classes in
// styles.css). `review` is { at, summary, scored: [{ id, ref, text, likelihood, residual }] }. The comments the
// AI wrote are in each gap's Comment field, so they are not repeated here.
const LIKELIHOOD_BADGE = { Probable: "critical", Likely: "high", Possible: "medium", Unlikely: "low", Remote: "low" };
export function traReviewCardHtml(review, { esc }) {
  const badge = (l) => (l ? `<span class="pr-badge ${LIKELIHOOD_BADGE[l] || "neutral"}">${esc(l)}</span>` : '<span class="pr-muted">–</span>');
  const when = review.at ? ` · ${new Date(review.at).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })}` : "";
  const scored = review.scored?.length
    ? `<h3>Gaps scored</h3><table class="pr-table"><thead><tr><th class="pr-narrow">Control</th><th>Gap in the control</th><th class="pr-narrow">Likelihood</th><th class="pr-narrow">After treatment</th></tr></thead>
        <tbody>${review.scored.map((r) => `<tr><td><span class="pr-id">${esc(r.ref || r.id)}</span></td><td>${esc(r.text || "")}</td><td>${badge(r.likelihood)}</td><td>${badge(r.residual)}</td></tr>`).join("")}</tbody></table>`
    : '<p class="pr-muted">The review did not score any gaps.</p>';
  return `<div class="pr-doc pr-review">
      <h2>✨ AI review<span class="pr-muted">${esc(when)}</span></h2>
      <div class="pr-callout"><p>${esc(review.summary || "The review is complete.")}</p></div>
      ${scored}
      <p class="pr-muted">The AI's comments are in each gap's Comment field where it was blank. The review is saved with the assessment when you click Save.</p>
    </div>`;
}

// What a control gap becomes as a risk: the fields it fills in on a new risk, and `source`, which the risk keeps so it can say
// where it came from. The assessment must be saved (it needs its ID).
export function gapRisk(a, control, detail = {}) {
  const threats = (detail.threats || []).map((id) => THREAT_BY_ID.get(id)?.name).filter(Boolean);
  const text = [`Gap in ${control.ref} (${control.group}): ${control.gap}`, threats.length && `Threats: ${threats.join(", ")}.`, detail.comment].filter(Boolean).join("\n");
  return {
    fields: { title: control.gap.slice(0, 200), description: text, asset: a.assetName || "", ...(detail.action ? { memo: `Planned action: ${detail.action}` } : {}) },
    source: { type: "threat", id: a.id, control: control.id, ref: control.ref, name: a.assetName || "" },
  };
}

// The line a risk shows for its source. `found` is whether that assessment still exists.
export const sourceText = (source, found) => (source?.type === "threat"
  ? `From threat posture assessment ${source.id}${source.name ? ` (${source.name})` : ""}, control ${source.ref || source.control}${found ? "" : ". That assessment has been deleted"}.`
  : "");

export function initThreatAssessments({ $, escapeHtml: esc, toast, initial, persist, canEdit, isViewer, ownerNames, outside, onChange, getFramework, getAI, onCreateRisk, getOrgName = () => "", getLogo = () => null }) {
  let list = initial || [];
  let draft = null, editingId = null, snapshot = "", step = 0, controlFilter = "";
  const dialog = $("#tra-dialog");
  const body = $("#tra-body");
  const splitView = window.matchMedia("(min-width: 1100px)");

  const nextId = () => `T-${String(list.reduce((m, a) => Math.max(m, Number(String(a.id).replace(/\D/g, "")) || 0), 0) + 1).padStart(3, "0")}`;
  const save = () => { persist(list); onChange?.(); };
  const workspaceFramework = () => getFramework?.();
  const framework = () => frameworkOf(draft, workspaceFramework());
  const badge = (level) => (level ? levelBadge(level, { cls: levelCls(level), esc }) : '<span class="muted">–</span>');
  const letterBadge = (letter) => (letter ? badge(LEVEL_NAME[letter]) : '<span class="muted">–</span>');

  // ---------- list ----------
    function render() {
    const q = $("#tra-search").value.toLowerCase();
    const st = $("#tra-status-filter").value, rate = $("#tra-rating-filter").value;
    const rows = list.map((a) => ({ a, s: summarize(a, workspaceFramework()) }))
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
        <td class="nowrap">${esc(tableDate(a.assessmentDate))}</td>
      </tr>`).join("");
    $("#empty-tra").classList.toggle("hidden", rows.length > 0);
    $("#empty-tra").textContent = list.length ? "No threat posture assessments match."
      : isViewer() ? "No threat posture assessments list you as the asset or risk owner. They appear here once you're named on one and your email is in the people directory."
      : "No threat posture assessments yet. Click “+ New assessment” to start one.";
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
    const controls = controlsFor(draft, workspaceFramework());
    if (!controls.length) {
      return `<p class="muted">No controls yet. Choose an asset type in Asset profile.</p>`;
    }
    const shown = controls.filter((c) => {
      if (controlFilter === "open") return !draft.answers[c.id]?.status;
      if (controlFilter === "gaps") return isGap(draft, c);
      return true;
    });
    const sections = [...new Set(shown.map((c) => c.group))];
    const row = (c) => {
      const status = val(`answers.${c.id}.status`);
      return `<div class="tra-control" data-control="${esc(c.id)}">
        <div class="tra-control-head"><div><span class="tag">${esc(c.ref)}</span> ${esc(c.text)}</div>
          <select data-path="answers.${c.id}.status" aria-label="Compliance: ${esc(c.text)}">${opts(COMPLIANCE, status)}</select></div>
        <input class="tra-evidence ${status ? "" : "hidden"}" data-path="answers.${c.id}.evidence" value="${esc(val(`answers.${c.id}.evidence`))}" maxlength="2000" placeholder="How do you comply? Add evidence or details" aria-label="Evidence" />
        <input class="tra-compensating ${status === "No" || status === "Partially" ? "" : "hidden"}" data-path="answers.${c.id}.compensating" value="${esc(val(`answers.${c.id}.compensating`))}" maxlength="2000" placeholder="Compensating controls, if any" aria-label="Compensating controls" />
      </div>`;
    };
    return `<p class="muted small">Answer each control. Every No or Partially becomes a gap to assess in Risk scoring. Controls are grouped by ${esc(frameworkName(framework(), true))} ${GROUP_NOUN[framework()]}, and each shows its reference there.</p>
      <div class="tra-filter"><label>Show <select id="tra-control-filter">
        <option value="" ${controlFilter === "" ? "selected" : ""}>All controls</option>
        <option value="open" ${controlFilter === "open" ? "selected" : ""}>Not answered</option>
        <option value="gaps" ${controlFilter === "gaps" ? "selected" : ""}>Gaps only</option>
      </select></label></div>
      ${sections.map((s, i) => `<details class="form-section-details assess-section" ${i === 0 ? "open" : ""}><summary>${esc(s)} <span class="muted small" data-section-count="${esc(s)}"></span></summary>${shown.filter((c) => c.group === s).map(row).join("")}</details>`).join("") || '<p class="muted">Nothing to show.</p>'}`;
  }

  // ---------- step 3: risk scoring ----------
  function scoringStep() {
    const s = summarize(draft, workspaceFramework());
    if (!s.gaps.length) return `<p class="muted">No gaps yet. Answer the controls in Controls; every No or Partially appears here.</p>`;
    const likelihoods = LIKELIHOODS.map(([name, , pct]) => [name, `${name} (${pct})`]);
    const card = ({ control: c, detail, managed, residual }) => `<div class="assess-row tra-gap">
        <div class="assess-row-head"><span class="tag">${esc(c.ref)}</span><strong>${esc(c.group)}</strong></div>
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
        ${onCreateRisk && canEdit() ? `<div class="tra-gap-actions"><button type="button" class="small" data-create-risk="${esc(c.id)}" ${editingId ? "" : 'disabled title="Save the assessment first"'}>Create risk from this gap</button></div>` : ""}
      </div>`;
    const bar = canEdit() ? `<div class="tra-ai-bar"><button type="button" id="btn-tra-ai-review" class="small primary">✨ Review with AI</button>
        </div>` : "";
    const aiCard = `<div id="tra-ai-card" class="ai-panel${draft.aiAssessment ? "" : " hidden"}">${draft.aiAssessment ? traReviewCardHtml(draft.aiAssessment, { esc }) : ""}</div>`;
    return `${bar}${aiCard}<details class="form-section-details assess-section"><summary>How scoring works</summary>
        <p class="small">Risk score = impact × likelihood. Both use the scale 1, 2, 5, 8, 10, and impact comes from the overall rating you set in Impact, so scores appear once that step is done. Treating a risk changes only its likelihood.</p>
        <p class="small">Very High 80–100 · High 50–79 · Moderate 16–49 · Low 4–15 · Very Low 1–2.</p>
      </details>
      <div class="assess-rows">${s.gaps.map(card).join("")}</div>`;
  }
  const scoreHtml = ({ score, level }, likelihood) => (score ? `${badge(level)} <span class="small muted">${score}</span>`
    : `<span class="muted small">${likelihood ? "Scored once impact is rated in Impact" : "Choose a likelihood"}</span>`);

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
    const s = summarize(draft, workspaceFramework());
    const tile = (label, inner) => `<div class="risk-result"><div class="small muted">${label}</div><div>${inner}</div></div>`;
    const table = (head, rows) => `<table class="tra-summary-table"><thead><tr>${head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table>`;
    const levels = (counts) => RISK_LEVELS.map((l) => `<div class="tra-count">${badge(l)} <strong>${counts[l]}</strong></div>`).join("");
    const unassessed = s.gaps.length - s.assessed, unanswered = s.controls.length - s.answered;
    const todo = [unanswered && `${unanswered} control${unanswered === 1 ? "" : "s"} not answered`, unassessed && `${unassessed} gap${unassessed === 1 ? "" : "s"} without a likelihood`, !s.rating.overall && "business impact not rated"].filter(Boolean);
    return `${draft.status === "Completed" && draft.frozenControls ? `<p class="small muted">Completed with control library ${esc(draft.libraryVersion)}${isFramework(draft.framework) ? ` under ${esc(frameworkName(draft.framework))}` : ""}. Change the status to work on it again.</p>` : ""}
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
      <h3 class="tra-h">Gaps by ${esc(frameworkName(framework(), true))} ${GROUP_NOUN[framework()]}</h3>
      ${table([framework() === "csf2" ? "Category" : "Control family", "Controls", "Gaps"], s.sections.map((x) => `<tr><td>${esc(x.section)}</td><td>${x.controls}</td><td>${x.gaps}</td></tr>`))}
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
    const s = summarize(draft, workspaceFramework());
    const notes = [s.rating.overall ? LEVEL_NAME[s.rating.overall] : "", draft.profile.assetTypes?.length ? `${s.controls.length} controls` : "",
      s.controls.length ? `${s.answered} of ${s.controls.length}` : "", s.gaps.length ? `${s.assessed} of ${s.gaps.length}` : "", ""];
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
    if (impactNote) impactNote.textContent = s.gaps.length ? `This rating scores the ${s.gaps.length} control gap${s.gaps.length === 1 ? "" : "s"} listed in Risk scoring.` : "";
    for (const el of body.querySelectorAll("[data-section-count]")) {
      const section = s.controls.filter((c) => c.group === el.dataset.sectionCount);
      el.textContent = `${section.filter((c) => draft.answers[c.id]?.status).length} of ${section.length} answered`;
    }
  }
  function goTo(next) {
    step = next;
    renderStep();
    $("#tra-form").scrollTop = 0;
  }

  // The likelihoods and treatment for each gap are drafted from the asset's details and the threats
  // each gap relates to. The draft is changed here; nothing is kept until the assessment is saved.
  function reviewPrompt(s) {
    const rating = impactRating(draft.impact).overall;
    const types = (draft.profile.assetTypes || []).map((k) => ASSET_TYPES.find(([key]) => key === k)?.[1] || k);
    const exposure = TRIGGERS.filter((t) => draft.profile[t.key] === t.when).map((t) => t.label);
    const lines = [
      `Asset: ${draft.assetName || "(untitled)"}`,
      draft.description ? `Description: ${draft.description}` : "",
      `Overall business impact: ${rating ? LEVEL_NAME[rating] : "not rated yet"}`,
      `Asset types: ${types.join(", ") || "none"}`,
      `Exposure: ${exposure.join("; ") || "none recorded"}`,
      "",
      "Control gaps to score:",
    ].filter((x) => x !== "");
    for (const g of s.gaps) {
      const threats = (g.control.threats || []).map((t) => THREAT_BY_ID.get(t)?.name || t).join(", ");
      lines.push(`- id ${g.control.id} (${g.control.ref}): ${g.control.text}. Gap: ${g.control.gap}. Threats: ${threats || "none listed"}. Current likelihood: ${g.detail.likelihood || "none"}.`);
    }
    return lines.join("\n");
  }

  async function reviewWithAI() {
    const ctx = await getAI();
    if (!ctx) return toast("Add your Anthropic API key in Settings to review with AI", true);
    const s = summarize(draft, workspaceFramework());
    if (!s.gaps.length) return toast("There are no gaps to score yet", true);
    const btn = body.querySelector("#btn-tra-ai-review");
    if (btn) { btn.disabled = true; btn.textContent = "Reviewing…"; }
    try {
      const result = await ctx.ai.run("review_tpa_scoring", { prompt: reviewPrompt(s) + standardsPromptText() });
      const gapIds = new Set(s.gaps.map((g) => g.control.id));
      const levels = new Set(LIKELIHOODS.map(([name]) => name));
      let scored = 0;
      const review = { at: new Date().toISOString(), summary: result.summary || "", scored: [] };
      const gapById = new Map(s.gaps.map((g) => [g.control.id, g.control]));
      for (const r of result.reviews || []) {
        if (!gapIds.has(r.id) || !levels.has(r.likelihood) || !levels.has(r.residual_likelihood)) continue;
        const detail = draft.gapDetails[r.id] ||= {};
        detail.likelihood = r.likelihood;
        detail.residualLikelihood = r.residual_likelihood;
        // A comment already written by the analyst is kept.
        if (!detail.comment && r.comment) detail.comment = String(r.comment).slice(0, 2000);
        const control = gapById.get(r.id);
        review.scored.push({ id: r.id, ref: control?.ref, text: control?.gap, likelihood: r.likelihood, residual: r.residual_likelihood });
        scored++;
      }
      // Kept with the assessment (draft.aiAssessment), so it is saved with it and shown again when it is reopened.
      draft.aiAssessment = review;
      renderStep();
      body.querySelector("#tra-ai-card")?.scrollIntoView({ behavior: "smooth", block: "nearest" });
      toast(`Claude scored ${scored} gap${scored === 1 ? "" : "s"}. Check them, then click Save.`);
    } catch (err) {
      toast(`AI review failed: ${ctx.describe(err)}`, true);
    } finally {
      const again = body.querySelector("#btn-tra-ai-review");
      if (again) { again.disabled = false; again.textContent = "✨ Review with AI"; }
    }
  }

  body.addEventListener("click", (e) => {
    if (e.target.closest("#btn-tra-ai-review")) reviewWithAI();
    const create = e.target.closest("[data-create-risk]");
    if (create && editingId && onCreateRisk) {
      const gap = summarize(draft, framework()).gaps.find((g) => g.control.id === create.dataset.createRisk);
      if (gap) onCreateRisk(gapRisk(draft, gap.control, gap.detail));
    }
  });

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
    const { rows, removed, flagged } = outsideChanges(draft, outsideState.response, workspaceFramework());
    const removedRefs = [...new Set(removed.map((c) => inFramework(c, framework()).ref))];
    return `<div class="tra-review">
      ${flagged ? `<p class="small tra-todo"><strong>${flagged} change${flagged === 1 ? " makes" : "s make"} this asset look safer.</strong> Check the highlighted rows against evidence before applying.</p>` : ""}
      ${removed.length ? `<p class="small tra-todo">These answers remove ${removed.length} control${removed.length === 1 ? "" : "s"} from the assessment, under ${esc(removedRefs.slice(0, 3).join(", "))}${removedRefs.length > 3 ? " and others" : ""}.</p>` : ""}
      ${rows.length ? `<table class="tra-summary-table"><thead><tr><th>Item</th><th>Current</th><th>Submitted</th></tr></thead><tbody>
        ${rows.map((x) => `<tr class="${x.flag ? "tra-flag" : ""}"><td>${x.flag ? "⚠ " : ""}${esc(x.label)}</td><td>${esc(x.from) || '<span class="muted">–</span>'}</td><td>${esc(x.to) || '<span class="muted">–</span>'}</td></tr>`).join("")}
      </tbody></table>` : '<p class="small muted">These answers don\'t change anything.</p>'}
      <p class="tra-review-actions"><button type="button" class="small primary" id="btn-tra-apply">Apply these changes</button> <button type="button" class="small" id="btn-tra-review-close">Close</button></p>
    </div>`;
  }
  function renderOutside() {
    outsideBar.classList.toggle("hidden", !outside || !canEdit() || !draft);
    if (!outside || !draft) return;
    const intro = "<strong>Impact, asset profile and controls from someone without app access.</strong>";
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
      ${completed ? "" : `<p class="small tra-link-new"><label class="tra-share"><input type="checkbox" id="tra-link-share" /> Also show the description, other details and existing control answers</label>
        <button type="button" class="small" id="btn-tra-link">${s.expiresAt ? "Create new link" : "Create link"}</button></p>
        <p class="small muted">The form starts from this assessment's saved asset profile (asset type, exposure and sign-in methods), so it lists the same controls.</p>`}
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
        if (state() !== snapshot) return toast("Save your changes first, so the link lists the controls this assessment has now", true);
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
        const { flagged, answered } = outsideChanges(draft, outsideState.response, workspaceFramework());
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
    $("#tra-title").textContent = a ? `${a.id} · ${a.assetName || "Assessment"}` : "New threat posture assessment";
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

  $("#btn-tra-add").addEventListener("click", () => {
    if (!isFramework(workspaceFramework())) return toast("Choose the NIST framework for threat posture assessments first", true);
    if (confirmDiscard()) open(null);
  });
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
  // ---------- PDF export ----------
  // Prints the assessment's report on its own, reusing the Posture Snapshot print container
  // (#assessment-print in styles.css). The page title becomes the PDF's suggested file name.
  $("#btn-tra-pdf").addEventListener("click", () => {
    if (!dialog.open || !draft) return;
    if (!draft.assetName?.trim()) return toast("Add the asset name first", true);
    if (state() !== snapshot) toast("Exporting what's on screen – remember to save your changes too.");
    const id = editingId || "New assessment";
    const org = getOrgName();
    $("#assessment-print").innerHTML = traReportHtml(draft, {
      esc, org, id, framework: workspaceFramework(),
      logo: logoImg(getLogo(), "pr-logo", org) || document.querySelector(".topbar .logo-mark")?.outerHTML || "",
    });
    const title = document.title;
    document.title = `${id} ${draft.assetName} – Threat Posture Assessment Report`.replace(/[\\/:*?"<>|]/g, "-");
    document.body.classList.add("printing-assessment");
    const done = () => {
      document.body.classList.remove("printing-assessment");
      document.title = title;
      $("#assessment-print").innerHTML = "";
      window.removeEventListener("afterprint", done);
    };
    window.addEventListener("afterprint", done);
    window.print();
  });

  $("#tra-form").addEventListener("submit", (e) => {
    e.preventDefault();
    if (!canEdit()) return;
    if (!draft.assetName?.trim()) {
      goTo(0);
      return toast("Add the asset name first", true);
    }
    if (draft.status === "Completed") {
      const s = summarize(draft, workspaceFramework());
      if ((s.answered < s.controls.length || s.assessed < s.gaps.length || !s.controls.length || !s.rating.overall)
        && !confirm("Some steps aren't finished. Mark this assessment Completed anyway?")) return;
    }
    const now = new Date().toISOString();
    const saved = prepareForSave(draft, workspaceFramework());
    const isNew = !editingId;
    const id = editingId || nextId();
    if (isNew) list.push({ ...saved, id, created: now });
    else list = list.map((a) => (a.id === id ? { ...saved, id, updated: now } : a));
    // Saving keeps the assessment open so the work can carry on; Cancel or the close button closes it.
    // A new one gets its ID now, so the next save updates it rather than adding a copy.
    editingId = id;
    // What saving worked out (the framework, the library version and, once completed, the frozen controls)
    // is carried onto the open draft, so it matches the assessment when it is reopened.
    for (const key of ["framework", "libraryVersion", "frozenControls"]) {
      if (saved[key] === undefined) delete draft[key]; else draft[key] = saved[key];
    }
    snapshot = state();
    $("#tra-title").textContent = `${id} · ${draft.assetName || "Assessment"}`;
    $("#btn-tra-delete").classList.remove("hidden");
    save();
    render();
    if (isNew) { outsideState = null; renderOutside(); loadOutside(); }
    toast("Assessment saved");
  });

  return {
    render,
    all: () => list,
    close,
    open: (id) => { const a = list.find((x) => x.id === id); if (a) open(a); },
    reload(next) { list = next || []; render(); },
    replaceAll(next) { list = next; save(); render(); },
    // Imported from a backup: new IDs where they'd clash.
    addMany(items) {
      for (const a of items) list.push({ ...a, id: /^T-\d{3,6}$/.test(a.id) && !list.some((x) => x.id === a.id) ? a.id : nextId() });
      save(); render();
    },
  };
}
