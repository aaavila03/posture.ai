// Posture.ai – AI cyber risk manager. Plain ES modules, no build step.
import { assessOffline } from "./heuristics.js";
import { LIKELIHOOD, IMPACT, STAGES, REVIEW_MONTHS, CSV_COLS, riskRowsFromCsv, riskCsvTemplate, shownCriticality } from "./risk-csv.js";
import { initVendors, residualTier, isOverdue } from "./vendors.js";
import { buildReminders, whenText, expiryStatus, REMINDER_DAYS } from "./reminders.js";
import { APPETITE_LEVELS, APPETITE_CATEGORIES, cleanAppetite, appetiteCheck, appetiteText, appetiteReason } from "./appetite.js";
import { reportPrompt, renderReport, reportMarkdown } from "./report.js";
import { LocalStore, CloudStore, sanitizeRecord, ID_PATTERN, dbErrorMessage } from "./store.js";
import { CloudAI, LocalAI, describeError } from "./ai.js";
import { initAssessments } from "./assessments.js";
import { initThreatAssessments, isFramework, frameworkName, sourceText } from "./tra.js";
import { FRAMEWORKS } from "./tra-library.js";
import { directory, setOwnerField, readPeopleFile, fullName, wouldLoop, DIRECTOR, VP } from "./people.js";
import { SUPABASE_URL } from "./config.js";
import { formatPhone, formatPhoneInputs } from "./phone.js";
import { prepareLogo, logoImg } from "./logo.js";
import { parseStandardsFile, mergeStandards, MAX_STANDARDS, setActiveStandards, standardId } from "./standards.js";
import { setQuestionnaire } from "./intake-questions.js";
import { initQuestionnaireEditor } from "./questionnaire-editor.js";
import { riskReportHtml, riskAssessmentHtml, treatmentPlanHtml } from "./risk-report.js";
import { historyHtml } from "./risk-history.js";
import { tableDate } from "./dates.js";
import { levelBadge } from "./levels.js";
import { initExceptionPanel, exceptionCellHtml, expiryLabelHtml } from "./exceptions.js";
import { evidenceHtml, evidenceProblem, evidenceType, toBase64, fromBase64, hasThumbnail, initEvidencePreview } from "./risk-evidence.js";
import { cleanRiskSections, initRiskSections, riskSectionsHtml, RISK_SETTINGS_IDS, VENDOR_SETTINGS_IDS } from "./risk-sections.js";

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
  const saved = store.save("risks", risks);
  render();
  return saved;
}

const canEdit = () => !cloud || ["analyst", "approver", "admin", "owner"].includes(cloud.org.role);
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
const level = (names, n) => (n >= 1 && n <= 5 ? `${n}. ${names[n - 1]}` : "–");
// Risk level for a 1–25 score, numbered like the likelihood and impact levels (e.g. "3. High").
const RISK_LEVELS = ["Low", "Medium", "High", "Critical"];
const riskLevel = (s) => `${RISK_LEVELS.indexOf(rating(s).label) + 1}. ${rating(s).label}`;

// Where a risk stands against the risk appetite (null when none is set or the risk is closed).
const appetiteOf = (r) => appetiteCheck(appetite, { category: r.category, residualLevel: rating(residual(r)).label, status: r.status });
const outsideAppetite = (r) => !!appetiteOf(r)?.outside;
const appetiteTip = (r) => appetiteText(appetiteOf(r), { residualLevel: rating(residual(r)).label, category: r.category });
const stageOf = (r) => (r.status === "Open" || !r.status ? "Identified" : r.status);
const stageLabel = (r) => `${STAGES.indexOf(stageOf(r)) + 1 || ""}${STAGES.includes(stageOf(r)) ? ". " : ""}${stageOf(r)}`;

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
  if (days > 0) return { label: `Overdue by ${days} day${days === 1 ? "" : "s"}`, short: "Overdue", note: `by ${days} day${days === 1 ? "" : "s"}`, cls: "critical", days };
  if (r.treatmentCompletion && r.treatmentCompletion > r.due) return { label: "At risk – planned completion is after the due date", short: "At risk", note: "planned completion is after the due date", cls: "high" };
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
    nextReview: r.nextReview, logException: r.logException || "No", exceptionApproved: r.exceptionApproved, exceptionExpiry: r.exceptionExpiry,
    appetiteLimit: appetiteOf(r)?.limit, outsideAppetite: appetiteOf(r)?.outside, assetCriticality: shownCriticality(r.assetCriticality),
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
let sortKey = "residual", sortDir = -1;
// A filter set from the dashboard (a tile or a heat-map cell): { label, test }.
let quickFilter = null;

// The sections column sits just under the top bar, whose height changes as it wraps.
const setTopbarHeight = () => document.documentElement.style.setProperty("--topbar-h", `${$(".topbar").offsetHeight}px`);
setTopbarHeight();
window.addEventListener("resize", setTopbarHeight);
// Height of the search bar of the list on screen, so its column names can stick just under it.
const syncToolbarHeight = () => {
  const bar = document.querySelector(".view.active > .toolbar");
  document.documentElement.style.setProperty("--toolbar-h", `${bar ? bar.offsetHeight : 0}px`);
};
syncToolbarHeight();
window.addEventListener("resize", syncToolbarHeight);
document.querySelectorAll("nav.sidebar .tab").forEach((tab) => tab.addEventListener("click", () => setTimeout(syncToolbarHeight, 0)));
// Each cell gets its column name from the heading, so the narrow-screen card layout can show it.
const labelCells = (table) => {
  const heads = [...table.querySelectorAll("thead th")].map((th) => th.textContent.trim());
  table.querySelectorAll("tbody tr").forEach((row) => [...row.children].forEach((cell, i) => {
    if (heads[i] && cell.dataset.label !== heads[i]) cell.dataset.label = heads[i];
  }));
};
new MutationObserver(() => document.querySelectorAll(".table-card table").forEach(labelCells))
  .observe(document.body, { childList: true, subtree: true });

function render() {
  syncMineToggles();
  renderDashboard();
  vendorsApi.render();
  renderTable();
  assessmentsApi?.render();
  threatAssessmentsApi?.render();
  updateAiStatus();
}

// The "Due soon" panel: what is overdue, due this week and due this month, one row per risk or vendor.
// A chip per group (click to show only that group), a 30-day timeline with a dot per dated item,
// and a card per item with a calendar tile for its nearest date.
// The Minimize / Maximize control is an icon-only button; its label and tooltip carry the words.
const CHEVRON = `<svg aria-hidden="true" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 15l6 -6l6 6" /></svg>`;
let dueFilter = "";
// Minimized shows only the header row (title and count chips); remembered in this browser.
const DUE_COLLAPSED_KEY = "riskpilot.collapsed.due";
let dueCollapsed = safeGet(localStorage, DUE_COLLAPSED_KEY) === "1";
const DUE_GROUPS = [["overdue", "Overdue", "critical"], ["attention", "Needs attention", "high"], ["week", "This week", "high"],
  ["month", "This month", "medium"], ["waiting", "Waiting on vendors", "low"]];
function renderDueSoon() {
  const r = buildReminders({ risks: scopedRisks(), vendors: isViewer() ? [] : vendorsApi.all(), today: today(), outsideAppetite });
  $("#dashboard-tab-count").textContent = r.urgent || "";
  const parse = (d) => new Date(`${d}T00:00:00`);
  const shortDate = (d) => parse(d).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
  const shortWhen = (days) => (days < 0 ? `${-days}d overdue` : days === 0 ? "today" : `in ${days}d`);
  const groups = DUE_GROUPS.filter(([key]) => r[key].length);
  if (dueFilter && !r[dueFilter]?.length) dueFilter = "";
  const link = (x) => (x.record === "risk" ? `data-edit="${escapeHtml(x.id)}"` : `data-open-vendor="${escapeHtml(x.id)}"`);
  const nearest = (x) => x.reasons.filter((y) => y.date).sort((p, q) => p.days - q.days)[0];

  const tile = (x, cls) => {
    const n = nearest(x);
    if (!n) return `<div class="due-tile ${cls}" aria-hidden="true"><span class="due-tile-icon">${x.bucket === "waiting" ? "⏳" : "!"}</span></div>`;
    const d = parse(n.date);
    return `<div class="due-tile ${cls}"><span class="due-tile-m">${escapeHtml(d.toLocaleDateString(undefined, { month: "short" }))}</span><span class="due-tile-d">${d.getDate()}</span></div>`;
  };
  const card = (x, cls) => {
    const n = nearest(x);
    return `<li class="due-item">
      ${tile(x, cls)}
      <div class="due-main">
        <a href="#" ${link(x)} class="due-title"><span class="due-id">${escapeHtml(x.id)}</span> ${escapeHtml(x.title)}</a>
        <div class="due-chips"><span class="due-kind">${x.record === "risk" ? "Risk" : "Vendor"}</span>${x.reasons.map((y) =>
          `<span class="due-chip"${y.date ? ` data-tip="${escapeHtml(whenText(y.days))}"` : ""}>${escapeHtml(y.date ? `${y.text} ${shortDate(y.date)}` : y.text)}</span>`).join("")}</div>
      </div>
      ${n ? `<span class="due-when ${cls}">${escapeHtml(shortWhen(n.days))}</span>` : ""}
    </li>`;
  };
  const lane = ([key, label, cls], hidden) => {
    const list = r[key], shown = list.slice(0, 5), more = list.slice(5);
    return `<section class="due-lane ${cls}" data-due="${key}"${hidden ? " hidden" : ""}><h3><span class="due-dot ${cls}"></span>${label}<span class="due-count">${list.length}</span></h3>
      <ul>${shown.map((x) => card(x, cls)).join("")}</ul>
      ${more.length ? `<details><summary>Show ${more.length} more</summary><ul>${more.map((x) => card(x, cls)).join("")}</ul></details>` : ""}</section>`;
  };

  // Timeline: the left 16% holds overdue items (up to 60 days late), then today, then the next 30 days.
  const OVERDUE_W = 16;
  const pos = (days) => (days < 0 ? OVERDUE_W * (1 - Math.min(-days, 60) / 60) : OVERDUE_W + (100 - OVERDUE_W) * Math.min(days, REMINDER_DAYS) / REMINDER_DAYS);
  const dots = groups.flatMap(([key, , cls]) => r[key].map((x) => [x, nearest(x), cls])).filter(([, n]) => n)
    .map(([x, n, cls]) => `<button type="button" class="due-pin ${cls}" style="left:${pos(n.days).toFixed(2)}%" data-pin="${escapeHtml(x.record)}:${escapeHtml(x.id)}"
      data-tip="${escapeHtml(`${x.id} · ${x.title}: ${n.text} ${shortDate(n.date)} · ${whenText(n.days)}`)}" aria-label="${escapeHtml(`Open ${x.id}: ${n.text} ${whenText(n.days)}`)}"></button>`).join("");
  const timeline = dots ? `<div class="due-timeline" aria-label="Due dates over the next ${REMINDER_DAYS} days">
      <div class="due-track"><div class="due-zone" style="width:${OVERDUE_W}%"></div><div class="due-today" style="left:${OVERDUE_W}%"><span>Today</span></div>${dots}</div>
      <div class="due-scale"><span>Overdue</span><span style="left:${pos(7)}%">+7d</span><span style="left:${pos(14)}%">+14d</span><span style="left:${pos(21)}%">+21d</span><span class="end">+${REMINDER_DAYS}d</span></div>
    </div>` : "";

  $("#due-soon").innerHTML = `<div class="due-head">
      <div><h2>Due soon</h2><p class="muted small">Overdue items and anything due in the next ${REMINDER_DAYS} days</p></div>
      ${groups.length ? `<div class="due-filters" role="group" aria-label="Show">${[["", "All", "", r.total], ...groups.map(([key, label, cls]) => [key, label, cls, r[key].length])]
        .map(([key, label, cls, n]) => `<button type="button" class="due-filter ${cls}" data-due-filter="${key}" aria-pressed="${dueFilter === key}"><b>${n}</b> ${label}</button>`).join("")}</div>` : ""}
      <button type="button" class="link card-toggle due-toggle" aria-expanded="${!dueCollapsed}" aria-controls="due-body"
        aria-label="${dueCollapsed ? "Maximize" : "Minimize"} Due soon" data-tip="${dueCollapsed ? "Maximize" : "Minimize"}">${CHEVRON}</button>
    </div><div id="due-body">`
    + (r.total ? `${timeline}<div class="due-lanes">${groups.map((g) => lane(g, dueFilter && g[0] !== dueFilter)).join("")}</div>`
      : `<div class="due-clear"><span class="due-clear-icon">✓</span><div><strong>All clear</strong><div class="muted small">Nothing is due in the next ${REMINDER_DAYS} days, and nothing is overdue.</div></div></div>`)
    + "</div>";
  // Hidden rather than left out, so the timeline dots can still find their item's link.
  $("#due-soon").classList.toggle("due-collapsed", dueCollapsed);
}
$("#due-soon").addEventListener("click", (e) => {
  const pin = e.target.closest("[data-pin]");
  if (pin) {
    const [record, id] = pin.dataset.pin.split(":");
    $(`#due-soon .due-lanes a[${record === "risk" ? "data-edit" : "data-open-vendor"}="${CSS.escape(id)}"]`)?.click();
    return;
  }
  if (e.target.closest(".due-toggle")) {
    dueCollapsed = !dueCollapsed;
    safeSet(localStorage, DUE_COLLAPSED_KEY, dueCollapsed ? "1" : null);
    renderDueSoon();
    return;
  }
  const b = e.target.closest("[data-due-filter]");
  if (!b) return;
  // A chip on the minimized card opens it, showing that group.
  if (dueCollapsed) {
    dueCollapsed = false;
    safeSet(localStorage, DUE_COLLAPSED_KEY, null);
    dueFilter = b.dataset.dueFilter;
  } else {
    dueFilter = dueFilter === b.dataset.dueFilter ? "" : b.dataset.dueFilter;
  }
  renderDueSoon();
});

function renderDashboard() {
  renderDueSoon();
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
    ...(appetite ? [["outsideAppetite", "Outside appetite", active.filter(outsideAppetite).length, active.some(outsideAppetite) ? "high" : ""]] : []),
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
        <span class="badge level ${rating(inherent(r)).cls}">${inherent(r)}</span>${outsideAppetite(r) ? ` <span class="badge high" data-tip="${escapeHtml(appetiteTip(r))}">Outside appetite</span>` : ""}</li>`).join("")
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
  appetite: (r) => { const c = appetiteOf(r); return !c ? "" : c.outside ? "Outside appetite" : "Within appetite"; },
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
  // The appetite filter only means something once an appetite is set.
  const appetiteFilter = $('[data-rf="appetite"]');
  if (!appetite) appetiteFilter.value = "";
  appetiteFilter.closest("label").classList.toggle("hidden", !appetite);
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
    const rr = rating(residual(r));
    return `<tr class="${dialog.open && editingId === r.id ? "selected" : ""}">
      <td>${escapeHtml(r.id)}</td>
      <td><button type="button" class="link row-name" data-edit="${escapeHtml(r.id)}">${escapeHtml(r.title)}</button><div class="muted small">${escapeHtml(r.asset)}</div></td>
      <td>${escapeHtml(r.category)}</td>
      <td>${escapeHtml(standardId(r.internalStandard || ""))}</td>
      <td>${escapeHtml(r.owner)}</td>
      <td>${levelBadge(rr.label, { cls: rr.cls, esc: escapeHtml })}${outsideAppetite(r) ? `<div><span class="badge high" data-tip="${escapeHtml(appetiteTip(r))}">Outside appetite</span></div>` : ""}</td>
      <td>${escapeHtml(stageOf(r))}</td>
      <td class="nowrap${slippage(r)?.days > 0 ? " overdue" : ""}" ${slippage(r) ? `data-tip="${escapeHtml(slippage(r).label)}"` : ""}>${escapeHtml(tableDate(r.due))}</td>
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
  const expiry = $("#exception-expiry-filter").value;
  const rows = all
    .filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q))
    .filter((r) => !approved || (approved === "pending" ? !!r.exceptionPending : (r.exceptionApproved || "-") === approved))
    .filter((r) => !expiry || (expiry === "none" ? !r.exceptionExpiry : expiryStatus(r.exceptionExpiry, today())?.key === expiry))
    .sort((a, b) => residual(b) - residual(a) || a.id.localeCompare(b.id));
  $("#exception-table tbody").innerHTML = rows.map((r) => {
    const rr = rating(residual(r));
    const exp = expiryStatus(r.exceptionExpiry, today());
    const expiresCell = !exp ? '<span class="muted">Not set</span>'
      : `${escapeHtml(tableDate(r.exceptionExpiry))}${exp.label ? ` ${expiryLabelHtml(exp, { esc: escapeHtml })}` : ""}`;
    return `<tr class="${dialog.open && editingId === r.id ? "selected" : ""}">
      <td>${escapeHtml(r.id)}</td>
      <td><button type="button" class="link row-name" data-edit="${escapeHtml(r.id)}">${escapeHtml(r.title)}</button><div class="muted small">${escapeHtml(r.asset)}</div></td>
      <td>${escapeHtml(r.owner)}</td>
      <td class="nowrap">${exceptionCellHtml(r, { esc: escapeHtml })}</td>
      <td>${expiresCell}</td>
      <td>${levelBadge(rr.label, { cls: rr.cls, esc: escapeHtml })}</td>
      <td>${escapeHtml(r.treatment)}</td>
      <td class="nowrap${r.nextReview && r.nextReview < today() ? " overdue" : ""}">${escapeHtml(tableDate(r.nextReview))}</td>
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
$("#exception-expiry-filter").addEventListener("change", renderExceptions);

// ---------- people directory ----------
// The organisation's hierarchy (Settings → People directory). Owner fields pick from it.
let people = directory([]);
const RISK_OWNER_FIELDS = ["owner", "assetOwner", "delegate", "buDirector", "buVp", "complianceAnalyst", "riskAnalyst", "grcManager",
  "createdBy", "submittedBy", "treatmentBy", "approvedBy", "completedBy"];
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
  outsideAppetite: { tip: "Show risks outside appetite", label: "Outside risk appetite", test: (r) => isActive(r) && outsideAppetite(r) },
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

// The Due soon panel's vendor links open the vendor in the Vendors tab.
document.addEventListener("click", (e) => {
  const link = e.target.closest("[data-open-vendor]");
  if (!link) return;
  e.preventDefault();
  if (!showView("vendors")) return;
  vendorsApi.open(link.dataset.openVendor);
});

// ---------- editor ----------
const dialog = $("#risk-dialog");
const form = $("#risk-form");
let editingId = null;
// The custom sections of the risk editor (see risk-sections.js), set when the workspace loads.
let riskSections = cleanRiskSections(null);
// The same for the vendor editor.
let vendorSections = cleanRiskSections(null);
// On wide screens the risk opens beside the register (split view); on phones and
// tablets it opens as a full dialog. Same behaviour as vendors (see vendors.js).
const splitView = window.matchMedia("(min-width: 1100px)");
let riskSnapshot = "";
const riskState = () => JSON.stringify(readRiskForm());
// Comments added in this editing session plus the risk's saved log.
let riskComments = [];
// The AI assessment last run for this risk (or the saved one); it is kept with the risk when saved.
let riskAI = null;
// Where the risk came from (a threat posture assessment's control gap), kept with the risk when saved.
let riskSource = null;
const LIST_FIELDS = ["dataImpact", "businessImpact"];
const SCORE_FIELDS = ["likelihood", "impact", "residualLikelihood", "residualImpact"];
// The signed-in person's name from their profile, else their email.
const commenter = () => [cloud?.profile?.first_name, cloud?.profile?.last_name].filter(Boolean).join(" ") || cloud?.user?.email || orgName() || "You";

function readRiskForm() {
  const fd = new FormData(form);
  const data = {}, custom = {};
  // Custom fields are named cf:<field id> and kept together as `custom` (see risk-sections.js).
  for (const k of new Set(fd.keys())) {
    if (k.startsWith("cf:")) custom[k.slice(3)] = String(fd.get(k)).trim();
    else if (!LIST_FIELDS.includes(k)) data[k] = String(fd.get(k)).trim();
  }
  data.custom = custom;
  for (const k of LIST_FIELDS) data[k] = fd.getAll(k);
  for (const k of SCORE_FIELDS) data[k] = Math.min(5, Math.max(1, Number(data[k]) || 1));
  data.comments = riskComments;
  data.aiAssessment = riskAI;
  if (riskSource) data.source = riskSource;
  return data;
}

// The scoring helpers the report and the assessment panel share, so they agree with the editor.
const reportHelpers = { inherent, residual, rating, riskLevel, level, stageLabel, slippage };

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
      <div>${levelBadge(rating(s).label, { cls: rating(s).cls, esc: escapeHtml })} <strong>Score ${s}</strong> <span class="small muted">of 25</span></div>
      <div class="small muted">${escapeHtml(level(LIKELIHOOD, l))} likelihood × ${escapeHtml(level(IMPACT, i))} impact</div>
    </div>`;
  $("#risk-score").innerHTML = card("Inherent", inherent(d), d.likelihood, d.impact)
    + card("Residual", residual(d), d.residualLikelihood, d.residualImpact);
  const check = appetiteCheck(appetite, { category: d.category, residualLevel: rating(residual(d)).label, status: d.status });
  $("#risk-appetite").innerHTML = check ? `<span class="badge ${check.outside ? "high" : "low"}">${check.outside ? "Outside appetite" : "Within appetite"}</span> ${escapeHtml(appetiteReason(check, { residualLevel: rating(residual(d)).label, category: d.category }))}.` : "";
  const sl = slippage(d);
  $("#risk-slippage").innerHTML = sl ? `Slippage: <span class="badge ${sl.cls}">${escapeHtml(sl.short || sl.label)}</span>${sl.note ? ` ${escapeHtml(sl.note)}` : ""}` : "";
}
// A PDF-style rendering of the treatment plan, shown under the text box while there is a plan.
function updatePlanPreview() {
  const box = $("#risk-plan-preview");
  const html = treatmentPlanHtml(form.elements.controls.value, escapeHtml);
  box.classList.toggle("hidden", !html);
  box.innerHTML = html ? `<h3>Treatment plan preview</h3>${html}` : "";
}
form.addEventListener("input", updateRiskScore);
form.addEventListener("input", (e) => { if (e.target.name === "controls") updatePlanPreview(); });
// The AI card leaves out what the risk already has, so redraw it when the fields it compares change
// (for example, after the plan is cleared its recommended controls come back).
const AI_COMPARED = ["controls", "category", "treatment", "likelihood", "impact", "residualLikelihood", "residualImpact"];
const refreshAssessment = (e) => { if (riskAI && AI_COMPARED.includes(e.target.name)) showAssessment(riskAI); };
form.addEventListener("input", refreshAssessment);
form.addEventListener("change", refreshAssessment);
// Adds "- [Function/Priority] Control" to the plan, the format the preview and the PDF show as a table row.
function addPlanControl() {
  const input = $("#plan-control");
  const text = input.value.trim();
  if (!text) return input.focus();
  const line = `- [${$("#plan-fn").value}/${$("#plan-pri").value}] ${text.replace(/\s+/g, " ")}`;
  const box = form.elements.controls;
  box.value = [box.value.trimEnd(), line].filter(Boolean).join("\n");
  box.dispatchEvent(new Event("input", { bubbles: true }));
  input.value = "";
  input.focus();
}
$("#btn-plan-add").addEventListener("click", addPlanControl);
$("#plan-control").addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); addPlanControl(); } });
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

// The editor's three sections (Risk Details, Assessment, Treatment & Review), one shown at a time.
let riskStep = 0;
function showRiskStep(n) {
  riskStep = Math.max(0, Math.min(2, n));
  form.querySelectorAll("[data-rstep-panel]").forEach((p) => p.classList.toggle("hidden", Number(p.dataset.rstepPanel) !== riskStep));
  form.querySelectorAll("#risk-steps [data-rstep]").forEach((b) => {
    const on = Number(b.dataset.rstep) === riskStep;
    b.classList.toggle("active", on);
    if (on) b.setAttribute("aria-current", "step"); else b.removeAttribute("aria-current");
  });
  $("#btn-risk-back").disabled = riskStep === 0;
  $("#btn-risk-next").disabled = riskStep === 2;
}
$("#risk-steps").addEventListener("click", (e) => { const b = e.target.closest("[data-rstep]"); if (b) showRiskStep(Number(b.dataset.rstep)); });
$("#btn-risk-back").addEventListener("click", () => showRiskStep(riskStep - 1));
$("#btn-risk-next").addEventListener("click", () => showRiskStep(riskStep + 1));
// The title is required but lives in the first section: bring it into view when Save is refused for it.
form.addEventListener("invalid", () => showRiskStep(0), true);

// The History section of a saved risk (hosted mode only: it reads the audit log). `after` is a save in progress, so the
// new entry is there when it loads. A reply for a risk that is no longer open is ignored.
async function showRiskHistory(id, after = null) {
  const section = $("#risk-history-section");
  const show = !!(cloud && id);
  section.classList.toggle("hidden", !show);
  if (!show) return;
  try {
    await after;
    const rows = await store.loadRiskHistory(id);
    if (editingId !== id) return;
    $("#risk-history").innerHTML = historyHtml(rows, { esc: escapeHtml });
    $("#risk-history-count").textContent = rows.length ? `(${rows.length})` : "";
  } catch (err) {
    if (editingId === id) $("#risk-history").innerHTML = `<li class="small error-text">Couldn't load the history: ${escapeHtml(err.message)}</li>`;
  }
}

// The exception panel of a risk (hosted mode): request, approve and renew exceptions (see exceptions.js). In demo mode
// the approval fields are ordinary fields. In hosted mode they are left out of the form, since only the database's
// approval functions may change them.
let exceptionPanel = null;
function showRiskException(risk, after = null) {
  for (const name of ["exceptionApproved", "exceptionExpiry"]) form.elements[name].disabled = !!cloud;
  $$(".exception-demo-only").forEach((el) => el.classList.toggle("hidden", !!cloud));
  exceptionPanel?.show(risk, after);
}
// One risk as the database has it now, after an approval changed it.
async function refreshRiskFromDb(id) {
  const fresh = await store.refreshRisk(id);
  if (!fresh) return null;
  risks = risks.map((r) => (r.id === id ? fresh : r));
  render();
  return fresh;
}

// The Evidence section of a risk (hosted mode only). A risk that isn't saved yet has no number to attach files to, so it
// asks for a save first. `after` is a save in progress. A reply for a risk that is no longer open is ignored.
let evidenceRows = [];
async function showRiskEvidence(id, after = null) {
  const section = $("#risk-evidence-section");
  section.classList.toggle("hidden", !cloud);
  if (!cloud) return;
  $("#risk-evidence-save-first").classList.toggle("hidden", !!id);
  $("#risk-evidence-add").classList.toggle("hidden", !id);
  $("#risk-evidence").classList.toggle("hidden", !id);
  if (!id) { evidenceRows = []; $("#risk-evidence-count").textContent = ""; return; }
  try {
    await after;
    const rows = await store.listEvidence(id);
    if (editingId !== id) return;
    evidenceRows = rows;
    $("#risk-evidence").innerHTML = evidenceHtml(rows, { esc: escapeHtml, canRemove: canEdit() });
    $("#risk-evidence-count").textContent = rows.length ? `(${rows.length})` : "";
    loadEvidenceThumbs(id, rows);
  } catch (err) {
    if (editingId === id) $("#risk-evidence").innerHTML = `<li class="small error-text">Couldn't load the evidence: ${escapeHtml(err.message)}</li>`;
  }
}

// Thumbnails for the images in the list, fetched one at a time after it shows (only images up to 1 MB have one).
let thumbUrls = [];
async function loadEvidenceThumbs(id, rows) {
  thumbUrls.forEach((u) => URL.revokeObjectURL(u));
  thumbUrls = [];
  for (const row of rows.filter(hasThumbnail)) {
    try {
      const file = await store.getEvidence(row.id);
      const img = $("#risk-evidence").querySelector(`[data-evidence-thumb="${CSS.escape(row.id)}"]`);
      if (editingId !== id || !img) return;
      const url = URL.createObjectURL(fromBase64(file.data, file.media_type));
      thumbUrls.push(url);
      img.src = url;
      img.hidden = false;
    } catch { /* the thumbnail is a nicety: the row still has Preview and Download */ }
  }
}

// Previews a file: an image or text in a dialog, a PDF in the browser's own viewer in a new tab (see risk-evidence.js).
const previewEvidence = initEvidencePreview({ $, toast, getFile: (id) => store.getEvidence(id) });

$("#risk-evidence-file").addEventListener("change", async (e) => {
  const input = e.target, file = input.files[0], id = editingId;
  input.value = "";
  if (!file || !id || !canEdit()) return;
  const problem = evidenceProblem({ name: file.name, size: file.size, type: file.type }, evidenceRows.map((r) => r.name));
  if (problem) return toast(problem, true);
  try {
    await store.addEvidence(id, { name: file.name, media_type: evidenceType({ name: file.name, type: file.type }), data: toBase64(await file.arrayBuffer()) });
    toast("Evidence added");
  } catch (err) {
    toast(err.message, true);
  }
  showRiskEvidence(id);
});

$("#risk-evidence").addEventListener("click", async (e) => {
  const download = e.target.closest("[data-evidence-download]"), remove = e.target.closest("[data-evidence-remove]");
  const preview = e.target.closest("[data-evidence-preview], [data-evidence-thumb]");
  const id = editingId;
  try {
    if (preview) {
      const row = evidenceRows.find((r) => r.id === (preview.dataset.evidencePreview || preview.dataset.evidenceThumb));
      if (row) await previewEvidence(row);
    } else if (download) {
      const file = await store.getEvidence(download.dataset.evidenceDownload);
      const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(fromBase64(file.data, file.media_type)), download: file.name });
      link.click();
      setTimeout(() => URL.revokeObjectURL(link.href), 10000);
    } else if (remove && canEdit()) {
      const row = evidenceRows.find((r) => r.id === remove.dataset.evidenceRemove);
      if (!confirm(`Remove ${row?.name || "this file"} from the risk? This can't be undone.`)) return;
      await store.removeEvidence(remove.dataset.evidenceRemove);
      toast("Evidence removed");
      showRiskEvidence(id);
    }
  } catch (err) {
    toast(err.message, true);
  }
});

// The source line under the title: where the risk came from, linking back while that assessment still exists.
function showRiskSource() {
  const box = $("#risk-source");
  const found = riskSource && (threatAssessmentsApi?.all() || []).some((a) => a.id === riskSource.id);
  const text = sourceText(riskSource, found);
  box.classList.toggle("hidden", !text);
  box.innerHTML = found ? `<a href="#" data-open-threat="${escapeHtml(riskSource.id)}">${escapeHtml(text.replace(/\.$/, ""))}</a>.` : escapeHtml(text);
}
$("#risk-source").addEventListener("click", (e) => {
  const link = e.target.closest("[data-open-threat]");
  if (!link) return;
  e.preventDefault();
  if (showView("threats")) threatAssessmentsApi.open(link.dataset.openThreat);
});

function openEditor(risk, prefill = null) {
  showRiskStep(0);
  editingId = risk?.id ?? null;
  form.reset();
  riskAI = risk?.aiAssessment ? structuredClone(risk.aiAssessment) : null;
  $("#ai-panel").classList.add("hidden");
  $("#dialog-title").textContent = risk ? `${risk.id} · ${risk.title || "Untitled risk"}` : "New risk";
  $("#btn-delete").classList.toggle("hidden", !risk);
  fillStandardOptions(risk?.internalStandard || "");
  for (const [k, v] of Object.entries(risk || {})) {
    if (LIST_FIELDS.includes(k)) continue;
    if (form.elements[k] && typeof v !== "object") form.elements[k].value = v ?? "";
  }
  for (const k of LIST_FIELDS) for (const c of form.querySelectorAll(`input[name="${k}"]`)) c.checked = (risk?.[k] || []).includes(c.value);
  for (const k of RISK_OWNER_FIELDS) setOwnerField(form, k, people.names, risk?.[k] || "");
  for (const [k, v] of Object.entries(prefill?.fields || {})) if (form.elements[k]) form.elements[k].value = v;
  riskSource = risk?.source || prefill?.source || null;
  showRiskSource();
  showRiskHistory(risk?.id ?? null);
  showRiskEvidence(risk?.id ?? null);
  showRiskException(risk);
  form.elements.status.value = risk ? stageOf(risk) : "Identified";
  if (!risk) {
    setOwnerField(form, "createdBy", people.names, commenter());
    form.elements.createdDate.value = today();
  }
  riskComments = structuredClone(risk?.comments || []);
  $("#risk-sections").innerHTML = riskSectionsHtml(riskSections, escapeHtml, risk?.custom || {});
  suggestedReview = "";
  $("#risk-comment-text").value = "";
  renderRiskComments();
  updateRiskScore();
  updatePlanPreview();
  if (riskAI) showAssessment(riskAI);
  // A risk prefilled from a gap isn't saved yet, so closing it asks first.
  riskSnapshot = prefill ? "" : riskState();
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
    // A new risk gets its ID now, so the next save updates it rather than adding a copy.
    editingId = nextId();
    risks.push({ id: editingId, ...data, created: new Date().toISOString() });
  }
  riskSnapshot = riskState();
  // Saving keeps the risk open, so the work can carry on; Cancel or ✕ closes it.
  $("#dialog-title").textContent = `${editingId} · ${data.title || "Untitled risk"}`;
  $("#btn-delete").classList.remove("hidden");
  const saved = saveRisks();
  showRiskHistory(editingId, saved);
  showRiskEvidence(editingId, saved);
  showRiskException(risks.find((r) => r.id === editingId), saved);
  toast("Risk saved");
});

// ---------- PDF export ----------
// Prints the risk's report on its own, reusing the Posture Snapshot print container
// (#assessment-print in styles.css). The page title becomes the PDF's suggested file name.
$("#btn-risk-pdf").addEventListener("click", () => {
  if (!dialog.open) return;
  const data = readRiskForm();
  if (!data.title?.trim()) return toast("Add a title first", true);
  if (riskState() !== riskSnapshot) toast("Exporting what's on screen – remember to save your changes too.");
  const id = editingId || "New risk";
  const org = orgName();
  $("#assessment-print").innerHTML = riskReportHtml(data, {
    esc: escapeHtml, org, id, sections: riskSections, appetite,
    helpers: reportHelpers,
    logo: logoImg(logo, "pr-logo", org) || $(".topbar .logo-mark")?.outerHTML || "",
  });
  const title = document.title;
  document.title = `${id} ${data.title} – Risk Report`.replace(/[\\/:*?"<>|]/g, "-");
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
    riskAI = { ...result, offline: !ctx, at: new Date().toISOString() };
    showAssessment(riskAI);
    panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
    if (ctx) afterAI();
  } catch (err) {
    const msg = describeError(err);
    panel.innerHTML = `<p class="error-text">AI review failed: ${escapeHtml(msg)}</p>`;
  } finally {
    btn.disabled = false;
  }
});

function showAssessment(a) {
  const panel = $("#ai-panel");
  panel.classList.remove("hidden");
  // Laid out like the risk PDF report; what the risk already says isn't repeated (see riskAssessmentHtml).
  const risk = readRiskForm();
  const when = a.at ? ` · ${new Date(a.at).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" })}` : "";
  panel.innerHTML = `
    <div class="pr-doc pr-review">
      <h2>${a.offline ? "Risk assessment (rule-based)" : "✨ AI review"}<span class="pr-muted">${escapeHtml(when)}</span></h2>
      ${riskAssessmentHtml(a, risk, { esc: escapeHtml, helpers: reportHelpers })}
      ${a.offline ? `<p class="pr-muted">Add an Anthropic API key in Settings for a full Claude-powered assessment.</p>` : ""}
      <p class="pr-muted">The assessment is saved with the risk when you click Save and is included in the PDF export.</p>
      <button type="button" id="btn-apply-ai" class="primary small">Apply to form</button>
    </div>`;
  $("#btn-apply-ai").addEventListener("click", () => {
    const f = form.elements;
    f.category.value = a.category;
    f.likelihood.value = a.likelihood;
    f.impact.value = a.impact;
    f.residualLikelihood.value = a.residual_likelihood;
    f.residualImpact.value = a.residual_impact;
    f.treatment.value = a.treatment;
    const have = f.controls.value.toLowerCase();
    const recs = a.recommended_controls.filter((c) => !have.includes(String(c.control).toLowerCase())).map((c) => `- [${c.csf_function}/${c.priority}] ${c.control}`).join("\n");
    f.controls.value = [f.controls.value.trim(), recs].filter(Boolean).join("\n");
    updateRiskScore();
    updatePlanPreview();
    showAssessment(a);
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
    toast(`Couldn't save the briefing: ${dbErrorMessage(err)}`, true);
  }
}

$("#btn-report").addEventListener("click", async () => {
  const out = $("#report");
  if (!risks.length) return toast("Your ledger is empty", true);
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
  // A collapsed briefing would print empty, so open it for the print.
  $("#briefing-panel").open = true;
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
    bubble.innerHTML = `Add your Anthropic API key in <a href="#" id="go-settings">Settings</a> to chat with the AI Risk Analyst.`;
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
    return toast(`Couldn't save the logo: ${dbErrorMessage(err)}`, true);
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

// ---------- collapsible cards ----------
// A card marked data-collapsible="<key>" gets a Minimize / Maximize button in its heading.
// The choice is remembered in this browser.
for (const card of $$("[data-collapsible]")) {
  const key = `riskpilot.collapsed.${card.dataset.collapsible}`;
  const heading = card.querySelector("h2");
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "link card-toggle";
  heading.classList.add("card-head");
  heading.append(btn);
  const set = (collapsed) => {
    card.classList.toggle("collapsed", collapsed);
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.innerHTML = CHEVRON;
    btn.setAttribute("aria-label", `${collapsed ? "Maximize" : "Minimize"} ${heading.firstChild.textContent.trim()}`);
    btn.dataset.tip = collapsed ? "Maximize" : "Minimize";
  };
  set(safeGet(localStorage, key) === "1");
  btn.addEventListener("click", () => {
    const collapsed = !card.classList.contains("collapsed");
    set(collapsed);
    safeSet(localStorage, key, collapsed ? "1" : null);
  });
}

// ---------- risk appetite ----------
// The workspace's limits (see appetite.js), set in Settings by admins and owners; null until set.
let appetite = null;
const showAppetiteCategories = () => $("#appetite-categories").classList.toggle("hidden", !$("#appetite-default").value);
function showAppetite() {
  const can = canSetLogo();
  $("#appetite-default").value = appetite?.default || "";
  $("#appetite-categories").innerHTML = APPETITE_CATEGORIES.map((c) => `<label>${escapeHtml(c)}
      <select data-appetite-category="${escapeHtml(c)}"><option value="">Same as default</option>${APPETITE_LEVELS.map((l) => `<option ${appetite?.categories[c] === l ? "selected" : ""}>${l}</option>`).join("")}</select></label>`).join("");
  showAppetiteCategories();
  for (const el of $$("#appetite-settings select, #btn-appetite-save")) el.disabled = !can;
  $("#appetite-note").classList.toggle("hidden", can);
}
$("#appetite-default").addEventListener("change", showAppetiteCategories);
$("#btn-appetite-save").addEventListener("click", async () => {
  const level = $("#appetite-default").value;
  const limits = Object.fromEntries($$("[data-appetite-category]").filter((s) => s.value).map((s) => [s.dataset.appetiteCategory, s.value]));
  const next = level ? cleanAppetite({ default: level, categories: limits }) : null;
  try {
    await store.saveRiskAppetite(next);
  } catch (err) {
    return toast(`Couldn't save the risk appetite: ${dbErrorMessage(err)}`, true);
  }
  appetite = next;
  showAppetite();
  render();
  toast(next ? "Risk appetite saved" : "Risk appetite cleared");
});

// ---------- internal standards ----------
// The company's standards, loaded from files in Settings. They fill the Internal standard
// dropdown on risks and are sent to the AI reviews.
let standards = [];
const STANDARD_FILE_LIMIT = 1024 * 1024;
function showStandards() {
  setActiveStandards(standards);
  const n = standards.length;
  $("#standards-count").textContent = n ? `${n} standard${n === 1 ? "" : "s"} loaded` : "No standards loaded yet.";
  $("#standards-list").innerHTML = standards.map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  $("#btn-standards-clear").classList.toggle("hidden", !n || !canSetLogo());
  $("#standards-file").closest("label").classList.toggle("hidden", !canSetLogo());
  $("#standards-note").classList.toggle("hidden", canSetLogo());
}
// The Internal standard dropdown: the loaded standards, plus the value a risk already has.
function fillStandardOptions(current) {
  // Each option shows the control ID; its full description is the tooltip. A value that is
  // already a full name (from an older risk) is matched to its ID.
  const entries = standards.map((s) => ({ value: standardId(s), title: s }));
  const value = current ? (entries.find((e) => e.title === current || e.value === current)?.value ?? current) : "";
  if (value && !entries.some((e) => e.value === value)) entries.push({ value, title: value });
  $("#risk-standard").innerHTML = `<option value="">–</option>${entries.map((e) => `<option value="${escapeHtml(e.value)}" title="${escapeHtml(e.title)}"${e.value === value ? " selected" : ""}>${escapeHtml(e.value)}</option>`).join("")}`;
}
async function setStandards(next) {
  try {
    await store.saveStandards(next);
  } catch (err) {
    return toast(`Couldn't save the standards: ${dbErrorMessage(err)}`, true);
  }
  standards = next;
  showStandards();
}
$("#standards-file").addEventListener("change", async (e) => {
  const files = [...e.target.files];
  e.target.value = "";
  if (!files.length || !canSetLogo()) return;
  let next = standards;
  const problems = [];
  for (const file of files) {
    if (file.size > STANDARD_FILE_LIMIT) { problems.push(`${file.name} is too large (1 MB at most)`); continue; }
    const { standards: found, errors } = parseStandardsFile(file.name, await file.text());
    problems.push(...errors);
    next = mergeStandards(next, found);
  }
  if (next.length > MAX_STANDARDS) problems.push(`only the first ${MAX_STANDARDS} standards are kept`);
  const added = next.length - standards.length;
  await setStandards(next);
  toast(`Loaded ${added > 0 ? added : 0} new standard${added === 1 ? "" : "s"}${problems.length ? `. Skipped: ${problems.join("; ")}` : ""}`, problems.length > 0);
});
$("#btn-standards-clear").addEventListener("click", () => {
  if (confirm("Remove all internal standards? Risks keep the standard they already have.")) setStandards([]);
});

// ---------- threat posture assessment framework ----------
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
    ? `<p class="small"><strong>Choose the NIST framework for threat posture assessments.</strong> It sets how security controls are grouped and referenced, and you can change it later in Settings.</p>
       <p class="tra-link-new">${FRAMEWORKS.map(([key, name]) => `<button type="button" class="small primary" data-framework="${key}">${escapeHtml(name)}</button>`).join("")}</p>`
    : `<p class="small"><strong>No NIST framework has been chosen yet.</strong> An admin or owner needs to choose one in Settings before new threat posture assessments can be started.</p>`;
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
    return toast(`Couldn't save the framework: ${dbErrorMessage(err)}`, true);
  }
  framework = next;
  showFramework();
  toast(`Threat posture assessments now follow ${frameworkName(next, true)}`);
}
$("#tra-framework").addEventListener("change", (e) => setFramework(e.target.value));
$("#tra-framework-bar").addEventListener("click", (e) => { if (e.target.dataset.framework) setFramework(e.target.dataset.framework); });

// Hide or show the section menu on wide screens. The choice is remembered in this browser.
const appShell = document.querySelector(".shell");
const sidebarBtn = $("#btn-sidebar");
function applySidebar(collapsed) {
  appShell.classList.toggle("sidebar-collapsed", collapsed);
  sidebarBtn.setAttribute("aria-expanded", String(!collapsed));
  sidebarBtn.setAttribute("aria-label", collapsed ? "Show menu" : "Hide menu");
  sidebarBtn.title = collapsed ? "Show menu" : "Hide menu";
}
sidebarBtn.addEventListener("click", () => {
  const collapsed = !appShell.classList.contains("sidebar-collapsed");
  applySidebar(collapsed);
  try { localStorage.setItem("riskpilot.sidebar", collapsed ? "hidden" : "shown"); } catch { /* storage may be blocked */ }
});
try { applySidebar(localStorage.getItem("riskpilot.sidebar") === "hidden"); } catch { applySidebar(false); }

$("#btn-sample").addEventListener("click", async () => {
  if (!canEdit()) return;
  const hasData = risks.length || vendorsApi.all().length || assessmentsApi.all().length || threatAssessmentsApi.all().length;
  if (hasData && !confirm("Add the sample data to your existing data?")) return;
  const { SAMPLE_RISKS, SAMPLE_VENDORS, SAMPLE_FILES } = await import("./sample-data.js");
  // Data for every tab: risks (some with a logged exception), vendors, ad-hoc assessments and
  // a threat posture assessment. A sample file that can't be fetched is skipped.
  const [adhoc, threats] = await Promise.all(SAMPLE_FILES.map(async ([file, key, kind]) => {
    try {
      const res = await fetch(new URL(file, import.meta.url));
      if (!res.ok) throw new Error(res.statusText);
      return ((await res.json())[key] || []).map((a) => sanitizeRecord(kind, a));
    } catch { return []; }
  }));
  // The sample people directory (a 22-person organisation), added to the existing one.
  const samplePeople = await fetch(new URL("samples/people-directory-sample.csv", import.meta.url)).then(async (res) => {
    if (!res.ok) throw new Error(res.statusText);
    const file = new File([await res.blob()], "people-directory-sample.csv", { type: "text/csv" });
    return (await readPeopleFile(file)).people;
  }).catch(() => []);
  if (samplePeople.length) {
    try { await store.importPeople(samplePeople, false); } catch { /* the directory needs an admin or owner */ }
    await loadPeople();
  }
  // The GAZT controls register, loaded as the internal standards (see standards.js).
  const sampleStandards = await fetch(new URL("samples/gazt-controls-register.csv", import.meta.url))
    .then(async (res) => {
      if (!res.ok) throw new Error(res.statusText);
      return parseStandardsFile("gazt-controls-register.csv", await res.text()).standards;
    }).catch(() => []);
  if (sampleStandards.length) {
    const next = mergeStandards(standards, sampleStandards);
    try {
      await store.saveStandards(next);
      standards = next;
      showStandards();
    } catch { /* the standards need an admin or owner */ }
  }
  // A sample appetite, unless one is already set: Medium, with a looser limit for third parties.
  if (!appetite) {
    const sampleAppetite = { default: "Medium", categories: { "Third-Party/Supply Chain": "High" } };
    try {
      await store.saveRiskAppetite(sampleAppetite);
      appetite = sampleAppetite;
      showAppetite();
    } catch { /* the appetite needs an admin or owner */ }
  }
  for (const r of SAMPLE_RISKS) risks.push({ ...r, id: nextId(), created: new Date().toISOString() });
  vendorsApi.addMany(SAMPLE_VENDORS);
  if (adhoc.length) assessmentsApi.addMany(adhoc);
  if (threats.length) threatAssessmentsApi.addMany(threats);
  saveRisks();
  const exceptions = SAMPLE_RISKS.filter(isException).length;
  toast(`Loaded ${SAMPLE_RISKS.length} sample risks (${exceptions} with exceptions), ${SAMPLE_VENDORS.length} vendors, ${adhoc.length} posture snapshots, ${threats.length} threat posture assessment${threats.length === 1 ? "" : "s"} and ${samplePeople.length} people, ${sampleStandards.length} internal standards`,
    !adhoc.length || !threats.length || !samplePeople.length);
  showView("dashboard");
});
$("#btn-clear").addEventListener("click", async () => {
  if (cloud && cloud.org.role !== "owner") return;
  const where = cloud ? `the ${cloud.org.name} workspace` : "this browser";
  if (!confirm(`Delete ALL risks, vendors and all assessments in ${where}? Export JSON first if you need a backup.`)) return;
  if (cloud && prompt(`Type the workspace name (${cloud.org.name}) to confirm`) !== cloud.org.name) return;
  risks = [];
  vendorsApi.replaceAll([]);
  assessmentsApi.replaceAll([]);
  threatAssessmentsApi.replaceAll([]);
  saveRisks();
  // The people directory and the saved briefing are data too.
  try {
    await store.clearPeople();
    await store.clearBriefing();
  } catch (err) {
    return toast(`Cleared the risks, vendors and assessments, but not everything: ${err.message}`, true);
  }
  await loadPeople();
  lastReport = null;
  $("#report").innerHTML = "";
  toast("All data deleted");
});

// ---------- import / export ----------
$("#btn-export-csv").addEventListener("click", () => {
  // A leading quote stops a spreadsheet running a value as a formula.
  const cell = (v) => `"${String(v ?? "").replace(/^[=+\-@\t\r]/, "'$&").replace(/"/g, '""')}"`;
  const value = (r, c) => c === "inherentScore" ? inherent(r) : c === "residualScore" ? residual(r)
    : c === "inherentLevel" ? riskLevel(inherent(r)) : c === "residualLevel" ? riskLevel(residual(r))
    : c === "slippage" ? slippage(r)?.label : c === "status" ? stageLabel(r)
    : c === "appetiteLimit" ? appetiteOf(r)?.limit : c === "outsideAppetite" ? (appetiteOf(r) ? (appetiteOf(r).outside ? "Yes" : "No") : "")
    : c === "likelihood" || c === "residualLikelihood" ? level(LIKELIHOOD, Number(r[c]))
    : c === "impact" || c === "residualImpact" ? level(IMPACT, Number(r[c]))
    : c === "comments" ? (r.comments || []).map((m) => `${m.at} ${m.by}: ${m.text}`).join("\n")
    : Array.isArray(r[c]) ? r[c].join("; ") : r[c];
  const custom = customFieldList();
  const header = [...CSV_COLS, ...custom.map((f) => f.label)];
  const rows = risks.map((r) => [...CSV_COLS.map((c) => value(r, c)), ...custom.map((f) => r.custom?.[f.id] ?? "")]);
  const csv = [header.map(cell).join(","), ...rows.map((row) => row.map(cell).join(","))].join("\n");
  download("risk-register.csv", csv, "text/csv");
});
// Custom fields follow the built-in columns, labelled with their section.
function customFieldList() {
  return riskSections.flatMap((sec) => sec.fields.map((f) => ({ id: f.id, label: `${sec.name}: ${f.label}` })));
}
$("#btn-csv-template").addEventListener("click", () => {
  download("risk-register-template.csv", riskCsvTemplate(customFieldList()) + "\n", "text/csv");
});
$("#import-csv").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file || !canEdit()) return;
  if (file.size > 5 * 1024 * 1024) { e.target.value = ""; return toast("That file is too large to import", true); }
  try {
    const { risks: rows, errors } = riskRowsFromCsv(await file.text(), customFieldList());
    if (rows.length > 5000) throw new Error("Too many rows in one file");
    for (const raw of rows) {
      const r = sanitizeRecord("risks", raw);
      const id = ID_PATTERN.risks.test(r.id) && !risks.some((x) => x.id === r.id) ? r.id : nextId();
      risks.push({ ...r, id, created: r.created || new Date().toISOString() });
    }
    if (rows.length) saveRisks();
    const skipped = errors.length
      ? `, ${errors.length} row${errors.length === 1 ? "" : "s"} skipped: ${errors.slice(0, 3).join(" | ")}${errors.length > 3 ? " …" : ""}`
      : "";
    toast(`Imported ${rows.length} risk${rows.length === 1 ? "" : "s"}${skipped}`, !rows.length || errors.length > 0);
  } catch (err) {
    toast(`Import failed: ${err.message}`, true);
  }
  e.target.value = "";
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
    toast(`Imported ${data.length} risks${newVendors.length ? `, ${newVendors.length} vendors` : ""}${newAssessments.length ? `, ${newAssessments.length} assessments` : ""}${newThreatAssessments.length ? `, ${newThreatAssessments.length} threat posture assessments` : ""}`);
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
  // The custom sections of the risk editor, shared by the whole workspace.
  riskSections = cleanRiskSections(await store.loadRiskSections().catch(() => null));
  initRiskSections({
    $, escapeHtml, toast, canChange: canSetLogo, ids: RISK_SETTINGS_IDS,
    current: () => riskSections,
    save: async (next) => {
      await store.saveRiskSections(next);
      riskSections = next;
    },
  });
  // The workspace's version of the vendor questionnaire, used by everything that reads answers.
  let questionnaire = await store.loadQuestionnaire().catch(() => null);
  setQuestionnaire(questionnaire);
  // The custom sections and fields of the vendor editor, shared by the whole workspace.
  vendorSections = cleanRiskSections(await store.loadVendorSections().catch(() => null));
  initRiskSections({
    $, escapeHtml, toast, canChange: canSetLogo, ids: VENDOR_SETTINGS_IDS,
    current: () => vendorSections,
    save: async (next) => {
      await store.saveVendorSections(next);
      vendorSections = next;
    },
  });
  vendorsApi = initVendors({
    $, $$, escapeHtml, toast, download, getAI,
    vendorSections: () => vendorSections,
    getLogo: () => logo,
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
  exceptionPanel = initExceptionPanel({
    $, esc: escapeHtml, toast, today,
    api: cloud ? {
      list: (id) => store.listExceptions(id),
      request: (id, req) => store.requestException(id, req),
      decide: (id, approve, note) => store.decideException(id, approve, note),
      withdraw: (id) => store.withdrawException(id),
      revoke: (id, note) => store.revokeException(id, note),
    } : null,
    getRole: () => cloud?.org.role, getUserId: () => cloud?.user.id,
    onChanged: refreshRiskFromDb,
  });
  threatAssessmentsApi = initThreatAssessments({
    $, escapeHtml, toast, canEdit, isViewer, getAI, getOrgName: orgName, getLogo: () => logo,
    initial: data.threat_assessments || [],
    persist: (list) => store.save("threat_assessments", list),
    ownerNames: () => people.names,
    getFramework: () => framework,
    // "Create risk from this gap": the register opens a new risk filled in from the gap.
    onCreateRisk: (prefill) => { if (showView("register") && confirmDiscardRisk()) openEditor(null, prefill); },
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
  store.loadRiskAppetite().then((saved) => { appetite = saved; showAppetite(); render(); })
    .catch(() => showAppetite());
  store.loadStandards().then((list) => { standards = list; showStandards(); })
    .catch(() => showStandards());
  store.loadLogo().then((saved) => { logo = saved; showLogo(); })
    .catch(() => showLogo());
  store.loadBriefing().then((saved) => { if (saved) showReport(saved); })
    .catch((err) => toast(`Couldn't load the saved briefing: ${err.message}`, true));
}

// When a save is rejected (e.g. a role change or a concurrent edit), reload the server's data.
async function onSaveError(err) {
  toast(`Couldn't save your change: ${dbErrorMessage(err)}. Reloading the latest data.`, true);
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
