// Posture.ai – AI cyber risk manager. Plain ES modules, no build step.
import { assessOffline } from "./heuristics.js";
import { initVendors, residualTier, isOverdue } from "./vendors.js";
import { reportPrompt, renderReport, reportMarkdown } from "./report.js";
import { LocalStore, CloudStore, sanitizeRecord, ID_PATTERN } from "./store.js";
import { CloudAI, LocalAI, describeError } from "./ai.js";
import { initAssessments } from "./assessments.js";
import { initThreatAssessments, isFramework, frameworkName } from "./tra.js";
import { FRAMEWORKS } from "./tra-library.js";
import { directory, setOwnerField, readPeopleFile, fullName, wouldLoop, DIRECTOR, VP } from "./people.js";
import { SUPABASE_URL } from "./config.js";
import { formatPhone, formatPhoneInputs } from "./phone.js";
import { prepareLogo, logoImg } from "./logo.js";
import { setQuestionnaire } from "./intake-questions.js";
import { initQuestionnaireEditor } from "./questionnaire-editor.js";

const SETTINGS_KEY = "riskpilot.settings";
const API_KEY_KEY = "riskpilot.apiKey";

// Clickjacking defence for hosts that can't send a frame-ancestors header.
if (window.top !== window.self) {
  document.documentElement.innerHTML = "";
  throw new Error("Posture.ai cannot be embedded in another site.");
}

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

// ---------- storage ----------
function safeGet(storage, key) {
  try { return storage.getItem(key); } catch { return null; }
}
function safeSet(storage, key, value) {
  try { value == null ? storage.removeItem(key) : storage.setItem(key, value); } catch { /* storage unavailable */ }
}

let risks = [];
let store;          // LocalStore (demo) or CloudStore (signed in)
let cloud = null;   // { client, user, org, url, anonKey } when signed in
let cloudAI = null;
let workspaceApi = null;
let assessmentsApi = null;
let threatAssessmentsApi = null;
let vendorsApi;
let settings = { model: "claude-opus-5-5", effort: "medium", remember: false, orgName: "",
  ...JSON.parse(safeGet(localStorage, SETTINGS_KEY) || "{}") };
let apiKey = safeGet(localStorage, API_KEY_KEY) || safeGet(sessionStorage, API_KEY_KEY) || "";

function saveRisks() {
  store.save("risks", risks);
  render();
}

const canEdit = () => !cloud || ["analyst", "admin", "owner"].includes(cloud.org.role);
const orgName = () => (cloud ? cloud.org.name : settings.orgName);

// ---------- scoring ----------
const score = (l, i) => Number(l) * Number(i);
function rating(s) {
  if (s >= 20) return { label: "Critical", cls: "critical" };
  if (s >= 12) return { label: "High", cls: "high" };
  if (s >= 6) return { label: "Medium", cls: "medium" };
  return { label: "Low", cls: "low" };
}
const inherent = (r) => score(r.likelihood, r.impact);
const residual = (r) => score(r.residualLikelihood || r.likelihood, r.residualImpact || r.impact);
// Named levels for the 1–5 scales, shown as e.g. "4. Likely".
const LIKELIHOOD = ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"];
const IMPACT = ["Very low", "Low", "Moderate", "High", "Very high"];
const level = (names, n) => (n >= 1 && n <= 5 ? `${n}. ${names[n - 1]}` : "–");
// Risk level for a 1–25 score, numbered like the likelihood and impact levels (e.g. "3. High").
const RISK_LEVELS = ["Low", "Medium", "High", "Critical"];
const riskLevel = (s) => `${RISK_LEVELS.indexOf(rating(s).label) + 1}. ${rating(s).label}`;

// Risk lifecycle stages. Risks saved before stages existed used "Open".
const STAGES = ["Identified", "Assessment", "In treatment", "Monitoring", "Accepted", "Closed"];
const stageOf = (r) => (r.status === "Open" || !r.status ? "Identified" : r.status);
const stageLabel = (r) => `${STAGES.indexOf(stageOf(r)) + 1 || ""}${STAGES.includes(stageOf(r)) ? ". " : ""}${stageOf(r)}`;

const REVIEW_MONTHS = { Monthly: 1, Quarterly: 3, "Semi-annually": 6, Annually: 12 };
const today = () => new Date().toISOString().slice(0, 10);
function addMonths(isoDate, months) {
  const d = new Date(`${isoDate}T00:00:00`);
  d.setMonth(d.getMonth() + months);
  return d.toISOString().slice(0, 10);
}

// Whether treatment is on track against its due date (null when there's no due date).
function slippage(r) {
  if (!r.due) return null;
  if (stageOf(r) === "Closed") return { label: "Completed", cls: "low" };
  const days = Math.floor((new Date(`${today()}T00:00:00`) - new Date(`${r.due}T00:00:00`)) / 86400000);
  if (days > 0) return { label: `Overdue by ${days} day${days === 1 ? "" : "s"}`, cls: "critical", days };
  if (r.treatmentCompletion && r.treatmentCompletion > r.due) return { label: "At risk – planned completion is after the due date", cls: "high" };
  return { label: "On time", cls: "low" };
}

function nextId() {
  const max = risks.reduce((m, r) => Math.max(m, Number(String(r.id).replace(/\D/g, "")) || 0), 0);
  return `R-${String(max + 1).padStart(3, "0")}`;
}

// ---------- helpers ----------
function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

// Minimal, safe Markdown renderer (input is escaped first).
function renderMarkdown(md) {
  const lines = escapeHtml(md).split("\n");
  let html = "", inList = null;
  const inline = (t) => t
    .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
    .replace(/\*(.+?)\*/g, "<em>$1</em>")
    .replace(/`(.+?)`/g, "<code>$1</code>");
  const closeList = () => { if (inList) { html += `</${inList}>`; inList = null; } };
  for (const line of lines) {
    let m;
    if ((m = line.match(/^(#{1,4})\s+(.*)/))) {
      closeList();
      const lvl = Math.min(m[1].length + 1, 4);
      html += `<h${lvl}>${inline(m[2])}</h${lvl}>`;
    } else if ((m = line.match(/^\s*[-*]\s+(.*)/))) {
      if (inList !== "ul") { closeList(); html += "<ul>"; inList = "ul"; }
      html += `<li>${inline(m[1])}</li>`;
    } else if ((m = line.match(/^\s*\d+\.\s+(.*)/))) {
      if (inList !== "ol") { closeList(); html += "<ol>"; inList = "ol"; }
      html += `<li>${inline(m[1])}</li>`;
    } else if (line.trim() === "") {
      closeList();
    } else {
      closeList();
      html += `<p>${inline(line)}</p>`;
    }
  }
  closeList();
  return html;
}

function toast(msg, isError = false) {
  const el = $("#toast");
  el.textContent = msg;
  el.classList.toggle("error", isError);
  el.classList.remove("hidden");
  clearTimeout(toast.t);
  toast.t = setTimeout(() => el.classList.add("hidden"), 4000);
}

function download(name, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---------- AI ----------
async function getAI() {
  if (cloud) return { ai: cloudAI, describe: describeError };
  if (!apiKey) return null;
  return { ai: new LocalAI({ apiKey, model: settings.model, effort: settings.effort }), describe: describeError };
}

// Refreshes the usage meter after an AI call in cloud mode.
const afterAI = () => workspaceApi?.refreshUsage();

function registerSummary() {
  return JSON.stringify({ risks: riskSummary(), vendors: vendorsApi.summary() }, null, 1);
}

function riskSummary() {
  return risks.map((r) => ({
    id: r.id, title: r.title, description: r.description, asset: r.asset, category: r.category,
    likelihood: Number(r.likelihood), impact: Number(r.impact), inherent: inherent(r), inherentLevel: riskLevel(inherent(r)),
    residualLikelihood: Number(r.residualLikelihood || r.likelihood), residualImpact: Number(r.residualImpact || r.impact),
    residual: residual(r), residualLevel: riskLevel(residual(r)), owner: r.owner, ownerDepartment: r.ownerDepartment, stage: stageLabel(r), treatment: r.treatment,
    controls: r.controls, due: r.due, treatmentCompletion: r.treatmentCompletion, slippage: slippage(r)?.label,
    nextReview: r.nextReview, logException: r.logException || "No", exceptionApproved: r.exceptionApproved, assetCriticality: r.assetCriticality,
    threatType: r.threatType, threat: r.threatSource, dataImpact: r.dataImpact, businessImpact: r.businessImpact,
    background: r.memo, nistControls: r.nistControls,
  }));
}

function updateAiStatus() {
  const el = $("#ai-status");
  if (cloud) {
    el.textContent = "AI: on";
    el.className = "pill ok";
    el.title = "Claude runs on the Posture.ai server";
    return;
  }
  el.textContent = apiKey ? `AI: ${settings.model}` : "AI: offline mode";
  el.className = `pill ${apiKey ? "ok" : "warn"}`;
  el.title = apiKey ? "Claude is connected" : "Add an API key in Settings for Claude-powered analysis";
}

// ---------- viewers: their own risks ----------
// Viewers start with only the risks they own (Risk owner matches their name or email) on the
// dashboard, register and Exceptions tab; the "Only risks I own" box turns it off.
const isViewer = () => cloud?.org.role === "viewer";
let mineOnly = false;
function myNames() {
  const names = [fullName(cloud?.profile), fullName(people.list.find((p) => p.email === cloud?.user?.email?.toLowerCase())), cloud?.user?.email];
  return new Set(names.filter(Boolean).map((n) => n.trim().toLowerCase()));
}
const ownedBy = (list, field) => {
  if (!mineOnly) return list;
  const mine = myNames();
  return list.filter((r) => mine.has(String(r[field] || "").trim().toLowerCase()));
};
const scopedRisks = () => ownedBy(risks, "owner");
function syncMineToggles() {
  const name = fullName(cloud?.profile) || fullName(people.list.find((p) => p.email === cloud?.user?.email?.toLowerCase()));
  for (const c of $$(".mine-check")) c.checked = mineOnly;
  for (const w of $$(".mine-who")) w.textContent = name ? `(${name})` : "(add your name in Settings → Your profile)";
}
document.addEventListener("change", (e) => {
  if (!e.target.classList.contains("mine-check")) return;
  mineOnly = e.target.checked;
  render();
});

// ---------- rendering ----------
let sortKey = "score", sortDir = -1;
// A filter set from the dashboard (a tile or a heat-map cell): { label, test }.
let quickFilter = null;

function render() {
  syncMineToggles();
  renderDashboard();
  vendorsApi.render();
  renderTable();
  assessmentsApi?.render();
  threatAssessmentsApi?.render();
  updateAiStatus();
}

function renderDashboard() {
  const active = scopedRisks().filter((r) => r.status !== "Closed");
  const crit = active.filter((r) => inherent(r) >= 20).length;
  const high = active.filter((r) => inherent(r) >= 12 && inherent(r) < 20).length;
  const avgIn = active.length ? (active.reduce((s, r) => s + inherent(r), 0) / active.length).toFixed(1) : "–";
  const avgRes = active.length ? (active.reduce((s, r) => s + residual(r), 0) / active.length).toFixed(1) : "–";
  const liveVendors = vendorsApi.all().filter((v) => v.status !== "Offboarded");
  const vendorsDue = liveVendors.filter(isOverdue).length;
  const overdue = active.filter((r) => r.due && new Date(r.due) < new Date(new Date().toDateString())).length;
  $("#kpis").innerHTML = [
    ["active", "Active risks", active.length, ""],
    ["critical", "Critical", crit, "critical"],
    ["high", "High", high, "high"],
    ["avgInherent", "Avg inherent score", avgIn, ""],
    ["avgResidual", "Avg residual score", avgRes, ""],
    ["overdue", "Overdue actions", overdue, overdue ? "high" : ""],
    ...(isViewer() ? [] : [
      ["riskyVendors", "High-risk vendors", liveVendors.filter((v) => ["High", "Critical"].includes(residualTier(v))).length, ""],
      ["vendorsDue", "Vendor reviews due", vendorsDue, vendorsDue ? "high" : ""],
    ]),
  ].map(([key, k, v, c]) => `<button type="button" class="kpi ${c}" data-kpi="${key}" title="${KPI_FILTERS[key].tip}"><div class="kpi-val">${v}</div><div class="kpi-label">${k}</div></button>`).join("");

  // Heat map: rows likelihood 5..1, columns impact 1..5
  let cells = "";
  for (let l = 5; l >= 1; l--) {
    for (let i = 1; i <= 5; i++) {
      const n = active.filter((r) => Number(r.likelihood) === l && Number(r.impact) === i).length;
      cells += `<button class="cell ${rating(l * i).cls}" data-l="${l}" data-i="${i}" title="Likelihood ${l} × Impact ${i}">${n || ""}</button>`;
    }
  }
  $("#heatmap").innerHTML = cells;

  const top = [...active].sort((a, b) => inherent(b) - inherent(a)).slice(0, 5);
  $("#top-risks").innerHTML = top.length
    ? top.map((r) => `<li><a href="#" data-edit="${escapeHtml(r.id)}">${escapeHtml(r.id)} · ${escapeHtml(r.title)}</a>
        <span class="badge ${rating(inherent(r)).cls}">${inherent(r)}</span></li>`).join("")
    : `<li class="muted">No active risks yet.</li>`;

  const tiers = ["Critical", "High", "Medium", "Low"];
  const tierCounts = tiers.map((t) => liveVendors.filter((v) => residualTier(v) === t).length);
  const maxTier = Math.max(1, ...tierCounts);
  $("#vendor-tiers").innerHTML = liveVendors.length
    ? tiers.map((t, k) => `<div class="bar-row"><span>${t}</span><div class="bar"><div class="${t.toLowerCase()}" style="width:${(tierCounts[k] / maxTier) * 100}%"></div></div><span>${tierCounts[k]}</span></div>`).join("")
    : `<p class="muted">No vendors yet.</p>`;

  const byCat = {};
  active.forEach((r) => { byCat[r.category] = (byCat[r.category] || 0) + 1; });
  const maxCat = Math.max(1, ...Object.values(byCat));
  $("#by-category").innerHTML = Object.entries(byCat).sort((a, b) => b[1] - a[1])
    .map(([c, n]) => `<div class="bar-row"><span>${escapeHtml(c)}</span><div class="bar"><div style="width:${(n / maxCat) * 100}%"></div></div><span>${n}</span></div>`)
    .join("") || `<p class="muted">–</p>`;
}

// ---------- register filters ----------
// The value each filter compares, per risk ("businessImpact" is a list: any match counts).
const RISK_FILTERS = {
  category: (r) => r.category,
  inherent: (r) => riskLevel(inherent(r)),
  residual: (r) => riskLevel(residual(r)),
  treatment: (r) => r.treatment,
  owner: (r) => r.owner,
  department: (r) => r.ownerDepartment,
  threatType: (r) => r.threatType,
  businessImpact: (r) => r.businessImpact || [],
  assetCriticality: (r) => r.assetCriticality,
  logException: (r) => r.logException || "No",
  slippage: (r) => {
    const s = slippage(r);
    return !s ? "No due date" : s.days > 0 ? "Overdue" : s.label.startsWith("At risk") ? "At risk" : s.label;
  },
  review: (r) => {
    if (!r.nextReview) return "Not scheduled";
    if (r.nextReview < today()) return "Overdue";
    return r.nextReview <= addMonths(today(), 1) ? "Next 30 days" : "Later";
  },
};
const filterSelects = () => $$("#risk-filters [data-rf]");
const activeRiskFilters = () => filterSelects().filter((s) => s.value);

function matchesRiskFilters(r) {
  return activeRiskFilters().every((s) => {
    const v = RISK_FILTERS[s.dataset.rf](r);
    return Array.isArray(v) ? v.includes(s.value) : (v || "") === s.value;
  });
}

// Owner and department choices come from the register itself.
function refreshFilterChoices() {
  for (const key of ["owner", "department"]) {
    const select = $(`#risk-filters [data-rf="${key}"]`);
    const values = [...new Set(risks.map(RISK_FILTERS[key]).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const current = select.value;
    select.innerHTML = `<option value="">All</option>${values.map((v) => `<option ${v === current ? "selected" : ""}>${escapeHtml(v)}</option>`).join("")}`;
    if (current && !values.includes(current)) select.value = "";
  }
}

function renderTable() {
  refreshFilterChoices();
  const q = $("#search").value.toLowerCase();
  const st = $("#filter-status").value;
  const base = scopedRisks();
  const rows = base
    .filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q))
    .filter((r) => !st || stageOf(r) === st)
    .filter((r) => !quickFilter || quickFilter.test(r))
    .filter(matchesRiskFilters)
    .sort((a, b) => {
      const val = (r) => sortKey === "score" ? inherent(r) : sortKey === "residual" ? residual(r)
        : sortKey === "status" ? STAGES.indexOf(stageOf(r)) : String(r[sortKey] ?? "");
      const [x, y] = [val(a), val(b)];
      return (x > y ? 1 : x < y ? -1 : 0) * sortDir;
    });

  $("#risk-table tbody").innerHTML = rows.map((r) => {
    const ri = rating(inherent(r)), rr = rating(residual(r));
    return `<tr class="${dialog.open && editingId === r.id ? "selected" : ""}">
      <td>${escapeHtml(r.id)}</td>
      <td><button type="button" class="link row-name" data-edit="${escapeHtml(r.id)}">${escapeHtml(r.title)}</button><div class="muted small">${escapeHtml(r.asset)}</div></td>
      <td>${escapeHtml(r.category)}</td>
      <td>${escapeHtml(r.owner)}</td>
      <td><span class="badge ${ri.cls}">${escapeHtml(riskLevel(inherent(r)))}</span> <span class="small">${inherent(r)}</span></td>
      <td><span class="badge ${rr.cls}">${escapeHtml(riskLevel(residual(r)))}</span> <span class="small">${residual(r)}</span></td>
      <td>${escapeHtml(stageLabel(r))}</td>
      <td class="${slippage(r)?.days > 0 ? "overdue" : ""}" ${slippage(r) ? `data-tip="${escapeHtml(slippage(r).label)}"` : ""}>${escapeHtml(r.due)}</td>
      <td><button class="small" data-edit="${escapeHtml(r.id)}">Edit</button></td>
    </tr>`;
  }).join("");
  $("#empty-register").classList.toggle("hidden", rows.length > 0);
  $("#empty-register").textContent = mineOnly && !base.length
    ? "No risks list you as the risk owner. Untick “Only risks I own” to see every risk."
    : "No risks match. Add one or load the sample data from Settings.";

  const n = activeRiskFilters().length;
  $("#btn-filters").textContent = n ? `Filters (${n})` : "Filters";
  const narrowed = n || quickFilter || $("#search").value || $("#filter-status").value;
  $("#risk-count").innerHTML = narrowed
    ? `Showing ${rows.length} of ${base.length} ${mineOnly ? "of your " : ""}risks · <button type="button" class="link" id="btn-filters-reset">Clear all filters</button>`
    : `${base.length} ${mineOnly ? "of your " : ""}risks`;

  const pill = $("#cell-filter");
  pill.classList.toggle("hidden", !quickFilter);
  if (quickFilter) pill.innerHTML = `${escapeHtml(quickFilter.label)} <button class="link" id="clear-cell" aria-label="Clear filter">✕</button>`;
  renderExceptions();
}

// ---------- exceptions ----------
// Risks marked "Log exception: Yes". It's a view of the register, not a copy, so a
// change made in either tab is the same saved record.
const isException = (r) => r.logException === "Yes";

function renderExceptions() {
  const all = scopedRisks().filter(isException);
  const q = $("#exception-search").value.toLowerCase();
  const approved = $("#exception-approved-filter").value;
  const rows = all
    .filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q))
    .filter((r) => !approved || (r.exceptionApproved || "-") === approved)
    .sort((a, b) => residual(b) - residual(a) || a.id.localeCompare(b.id));
  $("#exception-table tbody").innerHTML = rows.map((r) => {
    const rr = rating(residual(r));
    const ok = r.exceptionApproved;
    return `<tr class="${dialog.open && editingId === r.id ? "selected" : ""}">
      <td>${escapeHtml(r.id)}</td>
      <td><button type="button" class="link row-name" data-edit="${escapeHtml(r.id)}">${escapeHtml(r.title)}</button><div class="muted small">${escapeHtml(r.asset)}</div></td>
      <td>${escapeHtml(r.owner)}</td>
      <td>${ok ? `<span class="badge ${ok === "Yes" ? "low" : "high"}">${escapeHtml(ok)}</span>` : '<span class="muted">Not set</span>'}</td>
      <td><span class="badge ${rr.cls}">${escapeHtml(riskLevel(residual(r)))}</span> <span class="small">${residual(r)}</span></td>
      <td>${escapeHtml(r.treatment)}</td>
      <td class="${r.nextReview && r.nextReview < today() ? "overdue" : ""}">${escapeHtml(r.nextReview)}</td>
      <td><button class="small" data-edit="${escapeHtml(r.id)}">Edit</button></td>
    </tr>`;
  }).join("");
  $("#empty-exceptions").classList.toggle("hidden", rows.length > 0);
  $("#empty-exceptions").innerHTML = all.length
    ? "No exceptions match."
    : mineOnly ? "None of your risks have a logged exception. Untick “Only risks I own” to see every exception."
    : "No exceptions logged. Open a risk and set <strong>Log exception</strong> to Yes to add it here.";
  $("#exception-count").textContent = rows.length === all.length
    ? `${all.length} exception${all.length === 1 ? "" : "s"}`
    : `Showing ${rows.length} of ${all.length} exceptions`;
  $("#exception-tab-count").textContent = all.length || "";
}
$("#exception-search").addEventListener("input", renderExceptions);
$("#exception-approved-filter").addEventListener("change", renderExceptions);

// ---------- people directory ----------
// The organisation's hierarchy (Settings → People directory). Owner fields pick from it.
let people = directory([]);
const RISK_OWNER_FIELDS = ["owner", "assetOwner", "delegate", "buDirector", "buVp", "complianceAnalyst", "riskAnalyst", "grcManager"];
const canManagePeople = () => !cloud || ["admin", "owner"].includes(cloud.org.role);

async function loadPeople() {
  try {
    people = directory(await store.loadPeople());
  } catch (err) {
    people = directory([]);
    console.warn("People directory unavailable:", err.message);
  }
  renderPeople();
}

function renderPeople() {
  $("#people-admin").classList.toggle("hidden", !canManagePeople());
  const q = $("#people-search").value.toLowerCase();
  const rows = people.list
    .filter((p) => !q || JSON.stringify(p).toLowerCase().includes(q))
    .sort((a, b) => fullName(a).localeCompare(fullName(b)));
  const invite = !!cloud && canManagePeople();
  $("#people-body").innerHTML = rows.slice(0, 500).map((p) => {
    const m = people.manager(p);
    return `<tr>
      <td>${escapeHtml(fullName(p))}${p.title ? `<div class="small muted">${escapeHtml(p.title)}</div>` : ""}</td>
      <td>${escapeHtml(p.email)}</td>
      <td>${escapeHtml(p.department)}</td>
      <td>${m ? escapeHtml(fullName(m)) : p.manager_email ? `<span class="muted">${escapeHtml(p.manager_email)}</span>` : ""}</td>
      <td class="nowrap">${p.member ? '<span class="badge low">Member</span>'
        : invite ? `<button type="button" class="small" data-invite-person="${escapeHtml(p.email)}">Invite</button>` : '<span class="muted">No</span>'}</td>
      <td class="nowrap">${!canManagePeople() ? "" : p.fromMembers
        ? `<button type="button" class="small" data-edit-person="${escapeHtml(p.email)}">Add to directory</button>`
        : `<button type="button" class="small" data-edit-person="${escapeHtml(p.email)}">Edit</button> <button type="button" class="small danger" data-remove-person="${escapeHtml(p.email)}">Remove</button>`}</td>
    </tr>`;
  }).join("") || `<tr><td colspan="6" class="muted">${people.list.length ? "No one matches." : "No one yet. Import your organization's people from a CSV or Excel file."}</td></tr>`;
  renderOrgChart();
  const members = people.list.filter((p) => p.member).length;
  $("#people-count").textContent = `${people.list.length} people${cloud ? ` · ${members} use the app` : ""}${rows.length > 500 ? " · showing the first 500 matches" : ""}`;
}

// Org chart: everyone under their manager, starting from people with no manager in the directory.
function renderOrgChart() {
  const listed = people.list.filter((p) => !p.fromMembers);
  const reports = new Map();
  for (const p of listed) {
    const m = people.manager(p) && !people.manager(p).fromMembers ? p.manager_email : "";
    reports.set(m, [...(reports.get(m) || []), p]);
  }
  const edit = canManagePeople();
  const seen = new Set();
  const branch = (email, depth) => {
    const kids = (reports.get(email) || []).filter((p) => !seen.has(p.email)).sort((a, b) => fullName(a).localeCompare(fullName(b)));
    if (!kids.length || depth > 30) return "";
    return `<ul>${kids.map((p) => {
      seen.add(p.email);
      const name = edit ? `<button type="button" class="link" data-edit-person="${escapeHtml(p.email)}">${escapeHtml(fullName(p))}</button>` : `<strong>${escapeHtml(fullName(p))}</strong>`;
      return `<li><div class="org-node">${name}<span class="small muted">${escapeHtml([p.title, p.department].filter(Boolean).join(" · "))}</span></div>${branch(p.email, depth + 1)}</li>`;
    }).join("")}</ul>`;
  };
  $("#people-chart").innerHTML = branch("", 0) || '<p class="muted small">No one in the directory yet.</p>';
}

// The add / edit form. Editing keeps track of the original email so reports follow a change.
let editingPerson = null;
function openPersonForm(person) {
  const p = person || {};
  editingPerson = person && !person.fromMembers ? person.email : null;
  $("#person-form-title").textContent = editingPerson ? `Edit ${fullName(p)}` : person ? `Add ${fullName(p)} to the directory` : "Add person";
  for (const [id, k] of [["first", "first_name"], ["last", "last_name"], ["email", "email"], ["title", "title"], ["department", "department"], ["phone", "phone"]]) {
    $(`#person-${id}`).value = person?.fromMembers && k === "first_name" && p.first_name === p.email ? "" : k === "phone" ? formatPhone(p.phone) : p[k] || "";
  }
  // Anyone except the person and the people below them.
  const choices = people.list.filter((x) => !x.fromMembers && x.email !== p.email && !(editingPerson && wouldLoop(people.list, p.email, null, x.email)))
    .sort((a, b) => fullName(a).localeCompare(fullName(b)));
  $("#person-manager").innerHTML = `<option value="">– No manager (top of the organization)</option>`
    + choices.map((x) => `<option value="${escapeHtml(x.email)}" ${x.email === p.manager_email ? "selected" : ""}>${escapeHtml(fullName(x))}${x.title ? ` – ${escapeHtml(x.title)}` : ""}</option>`).join("");
  $("#people-departments").innerHTML = [...new Set(people.list.map((x) => x.department).filter(Boolean))].sort().map((d) => `<option value="${escapeHtml(d)}">`).join("");
  $("#person-form").classList.remove("hidden");
  $("#person-form").scrollIntoView({ block: "nearest" });
  $("#person-first").focus();
}
$("#btn-person-add").addEventListener("click", () => openPersonForm(null));
$("#btn-person-cancel").addEventListener("click", () => { $("#person-form").classList.add("hidden"); editingPerson = null; });
$("#person-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!e.target.reportValidity()) return;
  const person = {
    first_name: $("#person-first").value.trim(), last_name: $("#person-last").value.trim(), email: $("#person-email").value.trim().toLowerCase(),
    title: $("#person-title").value.trim(), department: $("#person-department").value.trim(), phone: formatPhone($("#person-phone").value),
    manager_email: $("#person-manager").value,
  };
  if (!editingPerson && people.list.some((p) => p.email === person.email && !p.fromMembers)) return toast(`${person.email} is already in the directory`, true);
  if (wouldLoop(people.list, person.email, editingPerson, person.manager_email)) return toast("A person can't report to themselves or to someone below them", true);
  try {
    await store.savePerson(person, editingPerson);
    $("#person-form").classList.add("hidden");
    editingPerson = null;
    await loadPeople();
    toast(`${fullName(person)} saved`);
    workspaceApi?.refreshAudit();
  } catch (err) { toast(err.message, true); }
});
$("#people-card").addEventListener("click", async (e) => {
  const edit = e.target.closest("[data-edit-person]")?.dataset.editPerson;
  if (edit) return openPersonForm(people.list.find((p) => p.email === edit));
  const remove = e.target.closest("[data-remove-person]")?.dataset.removePerson;
  if (remove) {
    const p = people.list.find((x) => x.email === remove);
    const reports = people.list.filter((x) => x.manager_email === remove).length;
    const up = people.manager(p);
    if (!confirm(`Remove ${fullName(p)} from the directory?${reports ? ` Their ${reports} direct report${reports === 1 ? "" : "s"} will report to ${up ? fullName(up) : "no one"}.` : ""} Owner names already saved on risks and vendors are kept.`)) return;
    try {
      await store.deletePerson(remove);
      await loadPeople();
      toast(`${fullName(p)} removed`);
      workspaceApi?.refreshAudit();
    } catch (err) { toast(err.message, true); }
    return;
  }
  const view = e.target.closest("[data-people-view]")?.dataset.peopleView;
  if (view) {
    $$("[data-people-view]").forEach((b) => b.classList.toggle("active", b.dataset.peopleView === view));
    $("#people-list").classList.toggle("hidden", view !== "list");
    $("#people-chart").classList.toggle("hidden", view !== "chart");
  }
});
$("#people-search").addEventListener("input", renderPeople);
$("#people-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  const out = $("#people-result");
  try {
    const { people: rows, errors } = await readPeopleFile(file);
    const issues = errors.length ? `<details><summary>${errors.length} row${errors.length === 1 ? "" : "s"} need attention</summary><ul>${errors.slice(0, 100).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul></details>` : "";
    if (!rows.length) { out.innerHTML = `<p class="error-text">No people imported.</p>${issues}`; return; }
    const replace = $("#people-replace").checked;
    if (replace && !confirm(`Replace the directory with the ${rows.length} people in ${file.name}? Anyone not in the file is removed.`)) return;
    const total = await store.importPeople(rows, replace);
    await loadPeople();
    out.innerHTML = `<p>Imported ${rows.length} people from <strong>${escapeHtml(file.name)}</strong>. The directory now has ${total}.</p>${issues}`;
    toast("People directory updated");
    workspaceApi?.refreshAudit();
  } catch (err) {
    out.innerHTML = `<p class="error-text">Couldn't import ${escapeHtml(file.name)}: ${escapeHtml(err.message)}</p>`;
  }
});
$("#btn-people-clear").addEventListener("click", async () => {
  if (!confirm("Remove everyone from the people directory? Owner names already saved on risks and vendors are kept.")) return;
  try {
    await store.clearPeople();
    await loadPeople();
    toast("People directory cleared");
  } catch (err) { toast(err.message, true); }
});
// Invites a directory person to the workspace as a viewer, with their details as their profile.
$("#people-body").addEventListener("click", async (e) => {
  const email = e.target.dataset.invitePerson;
  if (!email || !cloud) return;
  const p = people.list.find((x) => x.email === email);
  if (!confirm(`Invite ${fullName(p)} (${email}) to ${cloud.org.name} as a viewer? You can change their role in Members once they join.`)) return;
  const { data: invitation, error } = await cloud.client.rpc("invite_member", { org: cloud.org.id, invitee_email: email, invitee_role: "viewer" });
  if (error) return toast(error.message, true);
  await cloud.client.rpc("set_invitation_profile", { invitation, details: { first_name: p.first_name, last_name: p.last_name, title: p.title, phone: p.phone, department: p.department } });
  e.target.replaceWith(Object.assign(document.createElement("span"), { className: "muted", textContent: "Invited" }));
  toast(`Invitation created. Send ${p.first_name || email} the app link: they join once they sign up with ${email}.`);
});

// Choosing a risk owner fills in their department, BU director and BU VP from the directory.
function fillFromOwner() {
  const p = people.find(form.elements.owner.value);
  if (!p) return;
  if (p.department) form.elements.ownerDepartment.value = p.department;
  const director = people.leader(p, DIRECTOR), vp = people.leader(p, VP);
  if (director) setOwnerField(form, "buDirector", people.names, fullName(director));
  if (vp) setOwnerField(form, "buVp", people.names, fullName(vp));
}

// ---------- navigation ----------
function showView(name) {
  // Leaving a tab closes the risk or vendor that's open in it (after asking about unsaved changes).
  const current = $(".tab.active")?.dataset.view;
  if (name !== current) {
    if (dialog.open && !closeRiskEditor()) return false;
    if (vendorsApi && !vendorsApi.close()) return false;
    if (assessmentsApi && !assessmentsApi.close()) return false;
    if (threatAssessmentsApi && !threatAssessmentsApi.close()) return false;
  }
  $$(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === name));
  $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  return true;
}
$$(".tab").forEach((t) => t.addEventListener("click", () => showView(t.dataset.view)));

// ---------- register events ----------
$("#search").addEventListener("input", renderTable);
$("#filter-status").addEventListener("change", renderTable);
$("#risk-filters").addEventListener("change", renderTable);
$("#btn-filters").addEventListener("click", () => {
  const bar = $("#risk-filters");
  bar.classList.toggle("hidden");
  $("#btn-filters").setAttribute("aria-expanded", String(!bar.classList.contains("hidden")));
});
function resetAllRiskFilters() {
  clearRegisterFilters();
  quickFilter = null;
  renderTable();
}
$("#btn-filters-clear").addEventListener("click", resetAllRiskFilters);
$("#risk-count").addEventListener("click", (e) => { if (e.target.id === "btn-filters-reset") resetAllRiskFilters(); });
$$("#risk-table th[data-sort]").forEach((th) => th.addEventListener("click", () => {
  sortDir = sortKey === th.dataset.sort ? -sortDir : 1;
  sortKey = th.dataset.sort;
  renderTable();
}));
$("#heatmap").addEventListener("click", (e) => {
  const c = e.target.closest(".cell");
  if (!c) return;
  const l = Number(c.dataset.l), i = Number(c.dataset.i);
  if (!showView("register")) return;
  clearRegisterFilters();
  quickFilter = { label: `Likelihood ${l} × Impact ${i}`, test: (r) => isActive(r) && Number(r.likelihood) === l && Number(r.impact) === i };
  renderTable();
});
$("#cell-filter").addEventListener("click", (e) => {
  if (e.target.id === "clear-cell") { quickFilter = null; renderTable(); }
});

// ---------- dashboard tiles ----------
// Each tile opens the list behind its number: the same rule that counts it filters the list.
const isActive = (r) => r.status !== "Closed";
const isPastDue = (r) => r.due && new Date(r.due) < new Date(new Date().toDateString());
const KPI_FILTERS = {
  active: { tip: "Show active risks", label: "Active risks", test: isActive },
  critical: { tip: "Show critical risks", label: "Critical (inherent 20+)", test: (r) => isActive(r) && inherent(r) >= 20 },
  high: { tip: "Show high risks", label: "High (inherent 12–19)", test: (r) => isActive(r) && inherent(r) >= 12 && inherent(r) < 20 },
  avgInherent: { tip: "Show active risks by inherent score", label: "Active risks, highest inherent score first", test: isActive, sort: "score" },
  avgResidual: { tip: "Show active risks by residual score", label: "Active risks, highest residual score first", test: isActive, sort: "residual" },
  overdue: { tip: "Show overdue risks", label: "Overdue (past due date)", test: (r) => isActive(r) && isPastDue(r) },
  riskyVendors: { tip: "Show high-risk vendors", vendors: true, label: "High-risk vendors (residual High or Critical)",
    test: (v) => v.status !== "Offboarded" && ["High", "Critical"].includes(residualTier(v)) },
  vendorsDue: { tip: "Show vendors due for review", vendors: true, label: "Vendor reviews due", test: (v) => v.status !== "Offboarded" && isOverdue(v) },
};

function clearRegisterFilters() {
  $("#search").value = "";
  $("#filter-status").value = "";
  for (const s of filterSelects()) s.value = "";
}

$("#kpis").addEventListener("click", (e) => {
  const tile = e.target.closest("[data-kpi]");
  if (!tile) return;
  const f = KPI_FILTERS[tile.dataset.kpi];
  if (f.vendors) {
    if (showView("vendors")) vendorsApi.filterBy({ label: f.label, test: f.test });
    return;
  }
  if (!showView("register")) return;
  clearRegisterFilters();
  quickFilter = { label: f.label, test: f.test };
  if (f.sort) { sortKey = f.sort; sortDir = -1; }
  renderTable();
});
document.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-edit]");
  if (!btn) return;
  e.preventDefault();
  if (dialog.open && editingId === btn.dataset.edit) return;
  if (!confirmDiscardRisk()) return;
  // Dashboard links open the risk in the register; the Exceptions tab opens it in place.
  const here = $(".tab.active")?.dataset.view;
  if (here !== "register" && here !== "exceptions" && !showView("register")) return;
  openEditor(risks.find((r) => r.id === btn.dataset.edit));
});

// ---------- editor ----------
const dialog = $("#risk-dialog");
const form = $("#risk-form");
let editingId = null;
// On wide screens the risk opens beside the register (split view); on phones and
// tablets it opens as a full dialog. Same behaviour as vendors (see vendors.js).
const splitView = window.matchMedia("(min-width: 1100px)");
let riskSnapshot = "";
const riskState = () => JSON.stringify(readRiskForm());
// Comments added in this editing session plus the risk's saved log.
let riskComments = [];
const LIST_FIELDS = ["dataImpact", "businessImpact"];
const SCORE_FIELDS = ["likelihood", "impact", "residualLikelihood", "residualImpact"];
// The signed-in person's name from their profile, else their email.
const commenter = () => [cloud?.profile?.first_name, cloud?.profile?.last_name].filter(Boolean).join(" ") || cloud?.user?.email || orgName() || "You";

function readRiskForm() {
  const fd = new FormData(form);
  const data = {};
  for (const k of new Set(fd.keys())) if (!LIST_FIELDS.includes(k)) data[k] = String(fd.get(k)).trim();
  for (const k of LIST_FIELDS) data[k] = fd.getAll(k);
  for (const k of SCORE_FIELDS) data[k] = Math.min(5, Math.max(1, Number(data[k]) || 1));
  data.comments = riskComments;
  return data;
}

function renderRiskComments() {
  $("#risk-comments").innerHTML = [...riskComments].reverse().map((c) => `<li><div class="small muted">${escapeHtml(c.by)} · ${escapeHtml(new Date(c.at).toLocaleString())}</div>${escapeHtml(c.text)}</li>`).join("")
    || '<li class="muted small">No comments yet.</li>';
  $("#risk-comment-count").textContent = riskComments.length ? `(${riskComments.length})` : "";
}

function updateRiskScore() {
  const d = readRiskForm();
  // Inherent and residual risk: level and score, worked out from likelihood × impact.
  const card = (name, s, l, i) => `<div class="risk-result">
      <div class="small muted">${name} risk</div>
      <div><span class="badge ${rating(s).cls}">${escapeHtml(riskLevel(s))}</span> <strong>Score ${s}</strong> <span class="small muted">of 25</span></div>
      <div class="small muted">${escapeHtml(level(LIKELIHOOD, l))} likelihood × ${escapeHtml(level(IMPACT, i))} impact</div>
    </div>`;
  $("#risk-score").innerHTML = card("Inherent", inherent(d), d.likelihood, d.impact)
    + card("Residual", residual(d), d.residualLikelihood, d.residualImpact);
  const sl = slippage(d);
  $("#risk-slippage").innerHTML = sl ? `Slippage: <span class="badge ${sl.cls}">${escapeHtml(sl.label)}</span>` : "";
}
form.addEventListener("input", updateRiskScore);
form.addEventListener("change", updateRiskScore);
form.addEventListener("change", (e) => { if (e.target.name === "owner") fillFromOwner(); });

// Suggests the next review date from the review frequency, unless one was set by hand.
let suggestedReview = "";
form.elements.reviewFrequency.addEventListener("change", () => {
  const months = REVIEW_MONTHS[form.elements.reviewFrequency.value];
  const f = form.elements.nextReview;
  if (!months || (f.value && f.value !== suggestedReview)) return;
  f.value = suggestedReview = addMonths(today(), months);
  updateRiskScore();
});

$("#btn-risk-comment").addEventListener("click", () => {
  const box = $("#risk-comment-text");
  const text = box.value.trim();
  if (!text) return;
  riskComments = [...riskComments, { by: commenter(), at: new Date().toISOString(), text: text.slice(0, 5000) }];
  box.value = "";
  renderRiskComments();
});

function confirmDiscardRisk() {
  if (!dialog.open || riskState() === riskSnapshot) return true;
  return confirm(`Discard unsaved changes to ${form.elements.title.value.trim() || "this risk"}?`);
}

// Closes the editor and restores the full-width register; false if the user keeps it open.
function closeRiskEditor() {
  if (!confirmDiscardRisk()) return false;
  hideRiskEditor();
  return true;
}

function hideRiskEditor() {
  if (dialog.open) dialog.close();
  afterRiskClose();
}

// Also runs on the dialog's close event, which can arrive late or not at all for the side panel.
function afterRiskClose() {
  if (dialog.open || !document.body.classList.contains("risk-split") && !$("#risk-table tr.selected")) return;
  document.body.classList.remove("risk-split");
  renderTable();
}

function openEditor(risk) {
  editingId = risk?.id ?? null;
  form.reset();
  $("#ai-panel").classList.add("hidden");
  $("#dialog-title").textContent = risk ? `Edit ${risk.id}` : "New risk";
  $("#btn-delete").classList.toggle("hidden", !risk);
  for (const [k, v] of Object.entries(risk || {})) {
    if (LIST_FIELDS.includes(k)) continue;
    if (form.elements[k] && typeof v !== "object") form.elements[k].value = v ?? "";
  }
  for (const k of LIST_FIELDS) for (const c of form.querySelectorAll(`input[name="${k}"]`)) c.checked = (risk?.[k] || []).includes(c.value);
  for (const k of RISK_OWNER_FIELDS) setOwnerField(form, k, people.names, risk?.[k] || "");
  form.elements.status.value = risk ? stageOf(risk) : "Identified";
  if (!risk) {
    form.elements.createdBy.value = commenter();
    form.elements.createdDate.value = today();
  }
  riskComments = structuredClone(risk?.comments || []);
  suggestedReview = "";
  $("#risk-comment-text").value = "";
  renderRiskComments();
  updateRiskScore();
  riskSnapshot = riskState();
  if (splitView.matches) {
    document.documentElement.style.setProperty("--topbar-h", `${$(".topbar").offsetHeight}px`);
    document.body.classList.add("risk-split");
    if (!dialog.open) dialog.show();
    form.scrollTop = 0;
  } else if (!dialog.open) {
    dialog.showModal();
  }
  renderTable();
}

$("#btn-add").addEventListener("click", () => { if (confirmDiscardRisk()) openEditor(null); });
$("#btn-cancel").addEventListener("click", closeRiskEditor);
$("#btn-risk-close").addEventListener("click", closeRiskEditor);
dialog.addEventListener("close", afterRiskClose);
dialog.addEventListener("cancel", (e) => { if (!confirmDiscardRisk()) e.preventDefault(); });
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && dialog.open && document.body.classList.contains("risk-split")) closeRiskEditor();
});
$("#btn-delete").addEventListener("click", () => {
  if (!confirm(`Delete ${editingId}?`)) return;
  risks = risks.filter((r) => r.id !== editingId);
  hideRiskEditor();
  saveRisks();
});

form.addEventListener("submit", (e) => {
  e.preventDefault();
  if (!canEdit()) return;
  // A comment typed but not added is still kept.
  if ($("#risk-comment-text").value.trim()) $("#btn-risk-comment").click();
  const data = readRiskForm();
  if (editingId) {
    risks = risks.map((r) => (r.id === editingId ? { ...r, ...data, updated: new Date().toISOString() } : r));
  } else {
    risks.push({ id: nextId(), ...data, created: new Date().toISOString() });
  }
  riskSnapshot = riskState();
  hideRiskEditor();
  saveRisks();
  toast("Risk saved");
});

$("#btn-ai-assess").addEventListener("click", async () => {
  const data = readRiskForm();
  if (!data.title && !data.description) return toast("Add a title or description first", true);
  const panel = $("#ai-panel");
  const btn = $("#btn-ai-assess");
  panel.classList.remove("hidden");
  panel.innerHTML = `<div class="spinner"></div> Analysing risk…`;
  btn.disabled = true;
  try {
    const ctx = await getAI();
    const result = ctx ? await ctx.ai.assessRisk(data) : assessOffline(data);
    showAssessment(result, !ctx);
    if (ctx) afterAI();
  } catch (err) {
    const msg = describeError(err);
    panel.innerHTML = `<p class="error-text">AI assessment failed: ${escapeHtml(msg)}</p>`;
  } finally {
    btn.disabled = false;
  }
});

function showAssessment(a, offline) {
  const panel = $("#ai-panel");
  panel.innerHTML = `
    <div class="ai-head"><strong>${offline ? "Offline heuristic assessment" : "✨ Claude assessment"}</strong>
      <span class="badge ${rating(a.likelihood * a.impact).cls}">Inherent ${a.likelihood}×${a.impact} = ${a.likelihood * a.impact}</span>
      <span class="badge ${rating(a.residual_likelihood * a.residual_impact).cls}">Residual ${a.residual_likelihood * a.residual_impact}</span>
    </div>
    <p>${escapeHtml(a.rationale)}</p>
    ${a.threat_scenarios?.length ? `<h4>Threat scenarios</h4><ul>${a.threat_scenarios.map((t) => `<li>${escapeHtml(t)}</li>`).join("")}</ul>` : ""}
    <h4>Recommended controls</h4>
    <ul>${a.recommended_controls.map((c) => `<li><span class="tag">${escapeHtml(c.csf_function)}</span> <span class="tag p-${escapeHtml(c.priority).toLowerCase()}">${escapeHtml(c.priority)}</span> ${escapeHtml(c.control)}</li>`).join("")}</ul>
    ${offline ? `<p class="muted small">Add an Anthropic API key in Settings for a full Claude-powered assessment.</p>` : ""}
    <button type="button" id="btn-apply-ai" class="primary small">Apply to form</button>`;
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
  $("#btn-apply-ai").addEventListener("click", () => {
    const f = form.elements;
    f.category.value = a.category;
    f.likelihood.value = a.likelihood;
    f.impact.value = a.impact;
    f.residualLikelihood.value = a.residual_likelihood;
    f.residualImpact.value = a.residual_impact;
    f.treatment.value = a.treatment;
    const recs = a.recommended_controls.map((c) => `- [${c.csf_function}/${c.priority}] ${c.control}`).join("\n");
    f.controls.value = [f.controls.value.trim(), recs].filter(Boolean).join("\n");
    toast("Assessment applied – review and save");
  });
}

// ---------- AI analyst ----------
let lastReport = null;

// Shows a briefing: a new one built from the register now, or the saved one.
function showReport(report) {
  lastReport = report;
  $("#report").innerHTML = renderReport(report, { logo });
  const when = new Date(report.generatedAt).toLocaleString(undefined, { dateStyle: "long", timeStyle: "short" });
  $("#report-meta").textContent = `Generated ${when}${report.generatedBy ? ` by ${report.generatedBy}` : ""}. Stays here until the next briefing is generated.`;
  $("#report-meta").classList.remove("hidden");
  $("#btn-print-report").classList.remove("hidden");
  $("#btn-copy-report").classList.remove("hidden");
}

// Builds a briefing from the current register, shows it, and saves it as the latest.
async function publishReport(ai) {
  const report = { risks: riskSummary(), vendors: vendorsApi.summary(), ai, generatedAt: new Date().toISOString(),
    generatedBy: cloud?.user?.email || null, title: orgName() || "Posture.ai" };
  showReport(report);
  if (!canEdit()) return toast("Viewers can generate briefings, but only analysts and above can replace the saved one.");
  try {
    await store.saveBriefing(report);
  } catch (err) {
    toast(`Couldn't save the briefing: ${err.message}`, true);
  }
}

$("#btn-report").addEventListener("click", async () => {
  const out = $("#report");
  if (!risks.length) return toast("Your register is empty", true);
  const ctx = await getAI();
  if (!ctx) {
    await publishReport(null);
    toast("Showing the data-only briefing. Add an API key in Settings for Claude's analysis.");
    return;
  }
  const btn = $("#btn-report");
  btn.disabled = true;
  btn.innerHTML = `<span class="spinner"></span> Writing briefing…`;
  out.innerHTML = `<div class="rh-loading"><div class="spinner"></div><p>Claude is analysing ${risks.length} risks and ${vendorsApi.all().length} vendors. This usually takes under a minute.</p></div>`;
  try {
    await publishReport(await ctx.ai.briefing(reportPrompt(registerSummary())));
    afterAI();
  } catch (err) {
    out.innerHTML = `<p class="error-text">Briefing failed: ${escapeHtml(ctx.describe(err))}</p>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "✨ Generate briefing";
  }
});

$("#btn-copy-report").addEventListener("click", () => {
  if (lastReport) navigator.clipboard.writeText(reportMarkdown(lastReport)).then(() => toast("Briefing copied as text"));
});
$("#btn-print-report").addEventListener("click", () => {
  document.body.classList.add("printing-report");
  window.print();
});
window.addEventListener("afterprint", () => document.body.classList.remove("printing-report"));

// Hover tooltips for anything with a data-tip attribute (charts, chips).
const tooltip = $("#tooltip");
document.addEventListener("mouseover", (e) => {
  const el = e.target.closest("[data-tip]");
  if (!el) { tooltip.classList.add("hidden"); return; }
  tooltip.textContent = el.dataset.tip;
  tooltip.classList.remove("hidden");
});
document.addEventListener("mousemove", (e) => {
  if (tooltip.classList.contains("hidden")) return;
  const x = Math.min(e.clientX + 14, innerWidth - tooltip.offsetWidth - 8);
  const y = e.clientY + 18 + tooltip.offsetHeight > innerHeight ? e.clientY - tooltip.offsetHeight - 10 : e.clientY + 18;
  tooltip.style.transform = `translate(${x}px, ${y}px)`;
});

document.addEventListener("click", (e) => {
  if (e.target.id === "go-settings") { e.preventDefault(); showView("settings"); }
});

const chatHistory = [];
$("#chat-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const input = $("#chat-input");
  const q = input.value.trim();
  if (!q) return;
  input.value = "";
  const log = $("#chat-log");
  log.insertAdjacentHTML("beforeend", `<div class="msg user">${escapeHtml(q)}</div>`);
  const bubble = document.createElement("div");
  bubble.className = "msg assistant markdown";
  log.append(bubble);

  const ctx = await getAI();
  if (!ctx) {
    bubble.innerHTML = `Add your Anthropic API key in <a href="#" id="go-settings">Settings</a> to chat with the AI analyst.`;
    return;
  }
  chatHistory.push({ role: "user", content: q });
  bubble.innerHTML = `<div class="spinner"></div>`;
  let text = "";
  try {
    text = await ctx.ai.chat(chatHistory, registerSummary(), (d) => {
      text += d;
      bubble.innerHTML = renderMarkdown(text);
      log.scrollTop = log.scrollHeight;
    });
    bubble.innerHTML = renderMarkdown(text);
    chatHistory.push({ role: "assistant", content: text });
    afterAI();
  } catch (err) {
    chatHistory.pop();
    bubble.innerHTML = `<span class="error-text">${escapeHtml(ctx.describe(err))}</span>`;
  }
  log.scrollTop = log.scrollHeight;
});

// ---------- settings ----------
function loadSettingsForm() {
  $("#api-key").value = apiKey;
  $("#remember-key").checked = settings.remember;
  $("#model").value = settings.model;
  $("#effort").value = settings.effort;
  $("#org-name").value = settings.orgName;
}
$("#btn-save-settings").addEventListener("click", () => {
  apiKey = $("#api-key").value.trim();
  settings = { model: $("#model").value, effort: $("#effort").value, remember: $("#remember-key").checked, orgName: $("#org-name").value.trim() };
  safeSet(localStorage, SETTINGS_KEY, JSON.stringify(settings));
  safeSet(localStorage, API_KEY_KEY, settings.remember && apiKey ? apiKey : null);
  safeSet(sessionStorage, API_KEY_KEY, apiKey || null);
  updateAiStatus();
  showLogo();
  $("#settings-saved").classList.remove("hidden");
  setTimeout(() => $("#settings-saved").classList.add("hidden"), 2000);
});

// ---------- company logo ----------
let logo = null;
const canSetLogo = () => !cloud || ["admin", "owner"].includes(cloud.org.role);

// Puts the logo (or nothing) in the top bar, on the dashboard, in Settings and on the briefing.
function showLogo() {
  const name = orgName();
  const alt = name ? `${name} logo` : "Company logo";
  $("#org-brand").innerHTML = logoImg(logo, "", alt);
  $("#org-brand").classList.toggle("hidden", !logo);
  $("#dash-org").innerHTML = logo ? `<span class="org-logo-chip">${logoImg(logo, "", alt)}</span>
    <div>${name ? `<h2>${escapeHtml(name)}</h2>` : ""}<span class="muted small">Cyber risk dashboard</span></div>` : "";
  $("#dash-org").classList.toggle("hidden", !logo);
  $("#logo-preview").innerHTML = logoImg(logo, "", alt) || '<span class="muted small">No logo yet</span>';
  $("#logo-actions").classList.toggle("hidden", !canSetLogo());
  $("#btn-logo-remove").classList.toggle("hidden", !logo);
  $("#logo-note").classList.toggle("hidden", canSetLogo());
  if (lastReport) $("#report").innerHTML = renderReport(lastReport, { logo });
}

async function setLogo(next) {
  try {
    await store.saveLogo(next);
  } catch (err) {
    return toast(`Couldn't save the logo: ${err.message}`, true);
  }
  logo = next;
  showLogo();
  toast(next ? "Logo saved" : "Logo removed");
}

$("#logo-file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  e.target.value = "";
  if (!file) return;
  try {
    await setLogo(await prepareLogo(file));
  } catch (err) {
    toast(`Couldn't use that image: ${err.message}`, true);
  }
});
$("#btn-logo-remove").addEventListener("click", () => {
  if (confirm("Remove the company logo? It will no longer appear in the app or on exports.")) setLogo(null);
});

// ---------- threat risk assessment framework ----------
// The NIST framework assessments follow: chosen when the workspace is created (hosted mode) or
// before the first assessment, and changed in Settings. Null until then.
let framework = null;
const frameworkOptions = (blank) => `${blank ? `<option value="">${blank}</option>` : ""}${FRAMEWORKS.map(([key, name]) => `<option value="${key}">${escapeHtml(name)}</option>`).join("")}`;

// Shows the choice in Settings and above the assessment list, and redraws the list to match.
function showFramework() {
  const chosen = isFramework(framework), allowed = canSetLogo();
  const select = $("#tra-framework");
  select.innerHTML = frameworkOptions(chosen ? "" : "Choose a NIST framework…");
  select.value = chosen ? framework : "";
  select.disabled = !allowed;
  $("#framework-note").classList.toggle("hidden", allowed);
  const bar = $("#tra-framework-bar");
  bar.classList.toggle("hidden", chosen);
  bar.innerHTML = chosen ? "" : allowed
    ? `<p class="small"><strong>Choose the NIST framework for threat risk assessments.</strong> It sets how security controls are grouped and referenced, and you can change it later in Settings.</p>
       <p class="tra-link-new">${FRAMEWORKS.map(([key, name]) => `<button type="button" class="small primary" data-framework="${key}">${escapeHtml(name)}</button>`).join("")}</p>`
    : `<p class="small"><strong>No NIST framework has been chosen yet.</strong> An admin or owner needs to choose one in Settings before new threat risk assessments can be started.</p>`;
  $("#btn-tra-add").title = chosen ? `Controls follow ${frameworkName(framework)}` : "Choose a NIST framework first";
  threatAssessmentsApi?.render();
}

async function setFramework(next) {
  if (!isFramework(next) || next === framework) return showFramework();
  if (!threatAssessmentsApi.close()) return showFramework();
  try {
    await store.saveFramework(next);
  } catch (err) {
    showFramework();
    return toast(`Couldn't save the framework: ${err.message}`, true);
  }
  framework = next;
  showFramework();
  toast(`Threat risk assessments now follow ${frameworkName(next, true)}`);
}
$("#tra-framework").addEventListener("change", (e) => setFramework(e.target.value));
$("#tra-framework-bar").addEventListener("click", (e) => { if (e.target.dataset.framework) setFramework(e.target.dataset.framework); });

$("#btn-sample").addEventListener("click", async () => {
  if (!canEdit()) return;
  const hasData = risks.length || vendorsApi.all().length || assessmentsApi.all().length || threatAssessmentsApi.all().length;
  if (hasData && !confirm("Add the sample data to your existing data?")) return;
  const { SAMPLE_RISKS, SAMPLE_VENDORS, SAMPLE_FILES } = await import("./sample-data.js");
  // Data for every tab: risks (some with a logged exception), vendors, ad-hoc assessments and
  // a threat risk assessment. A sample file that can't be fetched is skipped.
  const [adhoc, threats] = await Promise.all(SAMPLE_FILES.map(async ([file, key, kind]) => {
    try {
      const res = await fetch(file);
      if (!res.ok) throw new Error(res.statusText);
      return ((await res.json())[key] || []).map((a) => sanitizeRecord(kind, a));
    } catch { return []; }
  }));
  for (const r of SAMPLE_RISKS) risks.push({ ...r, id: nextId(), created: new Date().toISOString() });
  vendorsApi.addMany(SAMPLE_VENDORS);
  if (adhoc.length) assessmentsApi.addMany(adhoc);
  if (threats.length) threatAssessmentsApi.addMany(threats);
  saveRisks();
  const exceptions = SAMPLE_RISKS.filter(isException).length;
  toast(`Loaded ${SAMPLE_RISKS.length} sample risks (${exceptions} with exceptions), ${SAMPLE_VENDORS.length} vendors, ${adhoc.length} ad-hoc assessments and ${threats.length} threat risk assessment${threats.length === 1 ? "" : "s"}`,
    !adhoc.length || !threats.length);
  showView("dashboard");
});
$("#btn-clear").addEventListener("click", () => {
  if (cloud && cloud.org.role !== "owner") return;
  const where = cloud ? `the ${cloud.org.name} workspace` : "this browser";
  if (!confirm(`Delete ALL risks, vendors and all assessments in ${where}? Export JSON first if you need a backup.`)) return;
  if (cloud && prompt(`Type the workspace name (${cloud.org.name}) to confirm`) !== cloud.org.name) return;
  risks = [];
  vendorsApi.replaceAll([]);
  assessmentsApi.replaceAll([]);
  threatAssessmentsApi.replaceAll([]);
  saveRisks();
});

// ---------- import / export ----------
const CSV_COLS = ["id", "title", "description", "memo", "asset", "assetCriticality", "category", "riskGroup", "threatType", "threatSource",
  "dataImpact", "businessImpact", "ticket", "vulnRef", "internalStandard", "nistControls",
  "likelihood", "impact", "inherentScore", "inherentLevel", "residualLikelihood", "residualImpact", "residualScore", "residualLevel",
  "treatment", "logException", "exceptionApproved", "controls", "estimatedCost", "remediationProject", "treatmentCompletion", "due", "slippage",
  "reviewFrequency", "nextReview", "owner", "ownerDepartment", "assetOwner", "delegate", "buDirector", "buVp",
  "complianceAnalyst", "riskAnalyst", "grcManager", "status", "createdBy", "createdDate", "submittedBy", "submittedDate",
  "treatmentBy", "treatmentDate", "approvedBy", "approvedDate", "completedBy", "completedDate",
  "oversightReview", "committeeReview", "committeeNotes", "comments"];
$("#btn-export-csv").addEventListener("click", () => {
  // A leading quote stops a spreadsheet running a value as a formula.
  const cell = (v) => `"${String(v ?? "").replace(/^[=+\-@\t\r]/, "'$&").replace(/"/g, '""')}"`;
  const value = (r, c) => c === "inherentScore" ? inherent(r) : c === "residualScore" ? residual(r)
    : c === "inherentLevel" ? riskLevel(inherent(r)) : c === "residualLevel" ? riskLevel(residual(r))
    : c === "slippage" ? slippage(r)?.label : c === "status" ? stageLabel(r)
    : c === "likelihood" || c === "residualLikelihood" ? level(LIKELIHOOD, Number(r[c]))
    : c === "impact" || c === "residualImpact" ? level(IMPACT, Number(r[c]))
    : c === "comments" ? (r.comments || []).map((m) => `${m.at} ${m.by}: ${m.text}`).join("\n")
    : Array.isArray(r[c]) ? r[c].join("; ") : r[c];
  const csv = [CSV_COLS.join(","), ...risks.map((r) => CSV_COLS.map((c) => cell(value(r, c))).join(","))].join("\n");
  download("risk-register.csv", csv, "text/csv");
});
$("#btn-export-json").addEventListener("click", () => {
  download("posture-ai-backup.json", JSON.stringify({ risks, vendors: vendorsApi.all(), assessments: assessmentsApi.all(), threatAssessments: threatAssessmentsApi.all() }, null, 2), "application/json");
});
$("#import-json").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file || !canEdit()) return;
  if (file.size > 25 * 1024 * 1024) { e.target.value = ""; return toast("That file is too large to import", true); }
  try {
    const parsed = JSON.parse(await file.text());
    // Accepts a plain array of risks (older exports) or a { risks, vendors } backup.
    const data = Array.isArray(parsed) ? parsed : parsed.risks;
    if (!Array.isArray(data)) throw new Error("Expected an array of risks or a Posture.ai backup");
    if (data.length > 5000) throw new Error("Too many records in one file");
    // Only known fields are kept and strings are length-capped (see store.js).
    const newVendors = Array.isArray(parsed.vendors) ? parsed.vendors.filter((v) => typeof v?.name === "string").map((v) => sanitizeRecord("vendors", v)) : [];
    if (newVendors.length) vendorsApi.addMany(newVendors);
    const newAssessments = Array.isArray(parsed.assessments) ? parsed.assessments.filter((a) => a && typeof a === "object").map((a) => sanitizeRecord("assessments", a)) : [];
    if (newAssessments.length) assessmentsApi.addMany(newAssessments);
    const newThreatAssessments = Array.isArray(parsed.threatAssessments) ? parsed.threatAssessments.filter((a) => a && typeof a === "object").map((a) => sanitizeRecord("threat_assessments", a)) : [];
    if (newThreatAssessments.length) threatAssessmentsApi.addMany(newThreatAssessments);
    for (const raw of data) {
      if (typeof raw?.title !== "string") continue;
      const r = sanitizeRecord("risks", raw);
      const id = ID_PATTERN.risks.test(r.id) && !risks.some((x) => x.id === r.id) ? r.id : nextId();
      risks.push({ ...r, id });
    }
    saveRisks();
    toast(`Imported ${data.length} risks${newVendors.length ? `, ${newVendors.length} vendors` : ""}${newAssessments.length ? `, ${newAssessments.length} assessments` : ""}${newThreatAssessments.length ? `, ${newThreatAssessments.length} threat risk assessments` : ""}`);
  } catch (err) {
    toast(`Import failed: ${err.message}`, true);
  }
  e.target.value = "";
});

// ---------- vendors ----------
function addRegisterRisk(risk) {
  const id = nextId();
  risks.push({ ...risk, id, created: new Date().toISOString() });
  saveRisks();
  return id;
}

// ---------- start-up ----------
formatPhoneInputs();
// Fields people can't change are locked (inert): no clicking, typing or focus,
// while the values stay readable. Collapsible section headings stay usable.
const LOCKABLE = "#risk-form .form-grid, #risk-form .comment-add, #vendor-form .form-grid, #vendor-form .edit-lock, #intake-answers-list";

async function rpcData(name, args) {
  const { data, error } = await cloud.client.rpc(name, args);
  if (error) throw error;
  return data;
}

function applyRoleUI() {
  document.body.classList.toggle("read-only", !canEdit());
  document.body.classList.toggle("viewer", isViewer());
  if (isViewer() && ["vendors", "analyst"].includes($(".tab.active")?.dataset.view)) showView("dashboard");
  for (const el of $$(LOCKABLE)) el.inert = !canEdit();
  document.body.classList.toggle("not-owner", !!cloud && cloud.org.role !== "owner");
  document.body.classList.toggle("cloud", !!cloud);
}

async function loadData() {
  const data = await store.load();
  risks = data.risks.map((r) => (r.status === "Open" ? { ...r, status: "Identified" } : r));
  return data;
}

async function boot() {
  const data = await loadData();
  await loadPeople();
  framework = await store.loadFramework().catch(() => null);
  // The workspace's version of the vendor questionnaire, used by everything that reads answers.
  let questionnaire = await store.loadQuestionnaire().catch(() => null);
  setQuestionnaire(questionnaire);
  vendorsApi = initVendors({
    $, $$, escapeHtml, toast, download, getAI, addRegisterRisk,
    initial: data.vendors,
    persist: (list) => store.save("vendors", list),
    getOrgName: orgName,
    ownerNames: () => people.names,
    onChange: renderDashboard,
    // Hosted mode: vendors' questionnaires saved online through their links.
    intakeServer: store.cloud ? {
      list: () => store.listIntakeResponses(),
      get: (ref) => store.getIntakeResponse(ref),
      documents: (ref, opts) => store.getIntakeDocuments(ref, opts),
    } : null,
    vendorLink: cloud ? {
      create: async (ref, share) => rpcData("create_vendor_link", { org: cloud.org.id, ref, share }),
      revoke: async (ref) => rpcData("revoke_vendor_link", { org: cloud.org.id, ref }),
      get: async (ref) => rpcData("get_vendor_link", { org: cloud.org.id, ref }),
    } : null,
  });
  assessmentsApi = initAssessments({
    $, $$, escapeHtml, toast, canEdit, commenter, addRegisterRisk, getAI, afterAI, getOrgName: orgName, getLogo: () => logo,
    initial: data.assessments || [],
    persist: (list) => store.save("assessments", list),
    ownerNames: () => people.names,
    findPerson: (name) => people.find(name),
    scope: (list) => ownedBy(list, "riskOwner"),
    intake: cloud ? {
      create: async (ref) => rpcData("create_assessment_intake_link", { org: cloud.org.id, ref }),
      revoke: async (ref) => rpcData("revoke_assessment_intake_link", { org: cloud.org.id, ref }),
      get: async (ref) => rpcData("get_assessment_intake", { org: cloud.org.id, ref }),
    } : null,
  });
  threatAssessmentsApi = initThreatAssessments({
    $, escapeHtml, toast, canEdit, isViewer,
    initial: data.threat_assessments || [],
    persist: (list) => store.save("threat_assessments", list),
    ownerNames: () => people.names,
    getFramework: () => framework,
    outside: cloud ? {
      create: async (ref, share) => rpcData("create_tra_link", { org: cloud.org.id, ref, share }),
      revoke: async (ref) => rpcData("revoke_tra_link", { org: cloud.org.id, ref }),
      get: async (ref) => rpcData("get_tra_outside", { org: cloud.org.id, ref }),
    } : null,
  });
  initQuestionnaireEditor({
    $, escapeHtml, toast, canChange: canSetLogo,
    current: () => questionnaire,
    save: async (next) => {
      if (!vendorsApi.close()) throw new Error("close the open vendor first");
      await store.saveQuestionnaire(next);
      questionnaire = next;
      setQuestionnaire(next);
      render();
    },
  });
  applyRoleUI();
  mineOnly = isViewer();
  loadSettingsForm();
  render();
  showFramework();
  store.loadLogo().then((saved) => { logo = saved; showLogo(); })
    .catch(() => showLogo());
  store.loadBriefing().then((saved) => { if (saved) showReport(saved); })
    .catch((err) => toast(`Couldn't load the saved briefing: ${err.message}`, true));
}

// When a save is rejected (e.g. a role change or a concurrent edit), reload the server's data.
async function onSaveError(err) {
  toast(`Couldn't save your change: ${err.message}. Reloading the latest data.`, true);
  const data = await loadData();
  vendorsApi.reload(data.vendors);
  assessmentsApi.reload(data.assessments);
  threatAssessmentsApi.reload(data.threat_assessments);
  render();
}

if (SUPABASE_URL) {
  const { startAuth, signOut, switchWorkspace } = await import("./auth.js");
  $("#local-settings").classList.add("hidden");
  $("#data-note").textContent = "Data is stored in your organisation's workspace, protected by role-based access, and every change is recorded in the audit log.";
  startAuth(async (ctx) => {
    cloud = ctx;
    store = new CloudStore({ client: ctx.client, orgId: ctx.org.id, onError: onSaveError });
    cloudAI = new CloudAI({ client: ctx.client, url: ctx.url, anonKey: ctx.anonKey, orgId: ctx.org.id });
    $("#user-menu").classList.remove("hidden");
    $("#ws-label").textContent = `${ctx.org.name} · ${ctx.org.role}`;
    $("#btn-signout").addEventListener("click", () => signOut());
    $("#btn-switch-ws").addEventListener("click", switchWorkspace);
    await boot();
    const { initWorkspace } = await import("./workspace.js");
    workspaceApi = initWorkspace({
      $, escapeHtml, toast, download, ctx, signOut,
      onRenamed: (name) => { $("#ws-label").textContent = `${name} · ${ctx.org.role}`; showLogo(); },
      onProfile: (p) => { cloud.profile = p; render(); },
    });
  });
} else {
  store = new LocalStore({ safeGet, safeSet });
  await boot();
}
