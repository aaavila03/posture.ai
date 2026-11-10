// Threat risk assessment steps 1 and 2 for someone without an account, opened from a link an
// analyst created. Answers save to the link's own holding area through database functions
// (see the threat_assessment_links migration) until an analyst applies them.
import { ASSET_TYPES, TRIGGERS, AUTH_METHODS, COMPLIANCE } from "./tra-library.js";
import { cleanOutsideResponse, selectControls, controlsFor } from "./tra.js";
import { SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY } from "./config.js";
import { logoImg } from "./logo.js";

// Clickjacking defence for hosts that can't send a frame-ancestors header.
if (window.top !== window.self) {
  document.documentElement.innerHTML = "";
  throw new Error("Posture.ai cannot be embedded in another site.");
}

const $ = (sel, root = document) => root.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const token = /^[0-9a-f]{64}$/.test(new URLSearchParams(location.search).get("t") || "") ? new URLSearchParams(location.search).get("t") : "";
const form = $("#tra-outside-form");
const intro = $("#form-intro");
let state = { profile: { assetTypes: [], auth: {} }, answers: {} };
let framework = null; // the requester's NIST framework: it sets how the controls are grouped
let saveTimer = null, saving = Promise.resolve();

async function call(name, args) {
  let res;
  try {
    res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`, {
      method: "POST",
      headers: { "content-type": "application/json", apikey: SUPABASE_PUBLISHABLE_KEY },
      body: JSON.stringify(args),
    });
  } catch {
    throw new Error("Couldn't reach the server. Check your connection and try again.");
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error(body?.message || "Something went wrong. Please try again.");
  return body;
}

const yesNoOptions = (current) => `<option value="">–</option>${["Yes", "No"].map((v) => `<option ${v === current ? "selected" : ""}>${v}</option>`).join("")}`;

function renderProfile() {
  const p = state.profile;
  const check = (group, key, label, on) => `<label><input type="checkbox" data-${group}="${esc(key)}" ${on ? "checked" : ""} /> ${esc(label)}</label>`;
  const text = (key, label) => `<label>${esc(label)} <input data-profile="${key}" value="${esc(p[key])}" maxlength="500" /></label>`;
  $("#section-profile").innerHTML = `<h2>Step 1: Asset profile</h2>
    <div class="form-grid">
      <label class="full">Description <textarea id="asset-description" rows="3" maxlength="5000" placeholder="What the asset does and what it depends on">${esc(state.description)}</textarea></label>
      <label>Business department <input id="asset-department" maxlength="500" value="${esc(state.department)}" /></label>
    </div>
    <h3 class="tra-h">Asset type</h3>
    <p class="muted small">Choose everything this asset includes. The questions in step 2 come from these choices and the answers below.</p>
    <fieldset class="checks">${ASSET_TYPES.map(([k, l]) => check("asset", k, l, p.assetTypes.includes(k))).join("")}</fieldset>
    <h3 class="tra-h">Exposure</h3>
    <div class="assess-qs">${TRIGGERS.map((t) => `<div class="assess-q tra-yn"><span>${esc(t.label)}</span><select data-profile="${t.key}" aria-label="${esc(t.label)}">${yesNoOptions(p[t.key])}</select></div>`).join("")}</div>
    <h3 class="tra-h">Sign-in methods</h3>
    <fieldset class="checks">${AUTH_METHODS.map(([k, l]) => check("auth", k, l, p.auth[k])).join("")}</fieldset>
    <h3 class="tra-h">Other details</h3>
    <div class="form-grid">
      ${text("vendor", "Vendor")}${text("database", "Database")}
      <label>Cloud deployment <select data-profile="deployment"><option value="">–</option>${["Public", "Private", "Hybrid", "Community"].map((v) => `<option ${v === p.deployment ? "selected" : ""}>${v}</option>`).join("")}</select></label>
      <label>Cloud model <select data-profile="cloudModel"><option value="">–</option>${["SaaS", "PaaS", "IaaS"].map((v) => `<option ${v === p.cloudModel ? "selected" : ""}>${v}</option>`).join("")}</select></label>
      ${text("location", "Data location")}${text("ssoMethod", "Central sign-in method")}
      <label class="full">Notes <textarea data-profile="notes" rows="3" maxlength="2000">${esc(p.notes)}</textarea></label>
    </div>`;
}

function renderControls() {
  const controls = controlsFor(state, framework);
  const box = $("#section-controls");
  if (!controls.length) {
    box.innerHTML = '<h2>Step 2: Controls</h2><p class="muted">Choose an asset type in step 1 to see the controls.</p>';
    return updateProgress();
  }
  const row = (c) => {
    const a = state.answers[c.id] || {};
    return `<div class="tra-control" data-control="${esc(c.id)}">
      <div class="tra-control-head"><div><span class="tag">${esc(c.ref)}</span> ${esc(c.text)}</div>
        <select data-answer="${esc(c.id)}" aria-label="Compliance: ${esc(c.text)}"><option value="">–</option>${COMPLIANCE.map((v) => `<option ${v === a.status ? "selected" : ""}>${v}</option>`).join("")}</select></div>
      <input class="tra-evidence ${a.status ? "" : "hidden"}" data-evidence="${esc(c.id)}" value="${esc(a.evidence)}" maxlength="2000" placeholder="How do you comply? Add evidence or details" aria-label="Evidence" />
      <input class="tra-compensating ${a.status === "No" || a.status === "Partially" ? "" : "hidden"}" data-compensating="${esc(c.id)}" value="${esc(a.compensating)}" maxlength="2000" placeholder="Compensating controls, if any" aria-label="Compensating controls" />
    </div>`;
  };
  const sections = [...new Set(controls.map((c) => c.group))];
  box.innerHTML = `<h2>Step 2: Controls</h2><p class="muted small">Answer each control as it stands today. If you're not sure, leave it blank.</p>
    ${sections.map((s, i) => `<details class="form-section-details assess-section" ${i === 0 ? "open" : ""}><summary>${esc(s)}</summary>${controls.filter((c) => c.group === s).map(row).join("")}</details>`).join("")}`;
  updateProgress();
}

function updateProgress() {
  const controls = selectControls(state);
  const done = controls.filter((c) => state.answers[c.id]?.status).length;
  $("#progress-bar").style.width = `${controls.length ? Math.round((done / controls.length) * 100) : 0}%`;
  $("#progress-text").textContent = controls.length ? `${done} of ${controls.length}` : "";
}

// Keeps the open sections when the list of controls changes.
function redrawControls() {
  const open = new Set([...document.querySelectorAll("#section-controls details[open] summary")].map((s) => s.textContent));
  renderControls();
  if (open.size) for (const d of document.querySelectorAll("#section-controls details")) d.open = open.has($("summary", d).textContent);
}

const payload = () => ({ ...cleanOutsideResponse(state), contributor: { name: $("#contributor-name").value.trim(), email: $("#contributor-email").value.trim() } });

function setSaveState(text, isError = false) {
  const el = $("#save-state");
  el.textContent = text;
  el.classList.toggle("error-text", isError);
}

function scheduleSave() {
  clearTimeout(saveTimer);
  setSaveState("Saving…");
  saveTimer = setTimeout(() => {
    saving = saving.then(() => call("tra_outside_save", { token, response: payload(), submit: false }))
      .then(() => setSaveState("Saved. You can close this page and come back with the same link. You'll need to enter your name again."))
      .catch((err) => setSaveState(err.message, true));
  }, 800);
}

form.addEventListener("input", (e) => {
  const t = e.target, d = t.dataset;
  if (t.id === "asset-description") state.description = t.value;
  else if (t.id === "asset-department") state.department = t.value;
  else if (d.profile) {
    state.profile[d.profile] = t.value;
    if (TRIGGERS.some((q) => q.key === d.profile)) redrawControls();
  } else if (d.answer) {
    state.answers[d.answer] = { ...state.answers[d.answer], status: t.value };
    const row = t.closest(".tra-control");
    $(".tra-evidence", row).classList.toggle("hidden", !t.value);
    $(".tra-compensating", row).classList.toggle("hidden", !["No", "Partially"].includes(t.value));
    updateProgress();
  } else if (d.evidence) state.answers[d.evidence] = { ...state.answers[d.evidence], evidence: t.value };
  else if (d.compensating) state.answers[d.compensating] = { ...state.answers[d.compensating], compensating: t.value };
  scheduleSave();
});
form.addEventListener("change", (e) => {
  const d = e.target.dataset;
  if (d.asset) {
    state.profile.assetTypes = [...document.querySelectorAll("[data-asset]:checked")].map((c) => c.dataset.asset);
    redrawControls();
    scheduleSave();
  }
  if (d.auth) {
    state.profile.auth[d.auth] = e.target.checked;
    redrawControls();
    scheduleSave();
  }
});
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!$("#contributor-name").value.trim()) {
    $("#contributor-name").focus();
    return setSaveState("Add your name before submitting.", true);
  }
  const controls = selectControls(state);
  const open = controls.filter((c) => !state.answers[c.id]?.status).length;
  const unanswered = open ? `${open} control${open === 1 ? " isn't" : "s aren't"} answered. ` : "";
  if (!confirm(`${unanswered}You can only submit once, and this link stops working afterwards. Submit now?`)) return;
  clearTimeout(saveTimer);
  setSaveState("Submitting…");
  try {
    await saving;
    await call("tra_outside_save", { token, response: payload(), submit: true });
    form.classList.add("hidden");
    intro.textContent = "Thank you. Your answers were submitted for review. This link no longer works, so if you need to change something, ask for a new one.";
  } catch (err) {
    setSaveState(err.message, true);
  }
});

async function start() {
  if (!SUPABASE_URL || !token) {
    intro.textContent = "This page opens from a link sent to you. Please use the full link, or ask the person who sent it for a new one.";
    return;
  }
  try {
    const data = await call("tra_outside_load", { token });
    state = cleanOutsideResponse(data.response || data.seed);
    framework = data.framework;
    const brand = logoImg(data.logo, "", data.requester);
    if (brand) { $("#org-brand").innerHTML = brand; $("#org-brand").classList.remove("hidden"); }
    $("#form-title").textContent = data.assetName || "Asset security questions";
    intro.textContent = `${data.requester || "The security team"} asked you to complete these questions about this asset. Your answers save as you go and are reviewed before they're used.`;
    renderProfile();
    renderControls();
    form.classList.remove("hidden");
  } catch (err) {
    intro.textContent = err.message;
    intro.classList.add("error-text");
  }
}
start();
