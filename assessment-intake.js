// The intake questionnaire for an ad-hoc risk assessment, for someone in the business without
// an account, opened from a link an analyst created. Answers save to the link's own holding
// area through database functions (see the assessment_intake_links migration) until the
// analyst adds them to the assessment.
import { intakeSections, intakeQuestions, cleanIntakeAnswers, isAnswered, YES_NO } from "./assessment-intake-questions.js";
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
const form = $("#intake-form");
const intro = $("#form-intro");
let types = [], answers = {};
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

function render() {
  const question = (q) => {
    const given = answers[q.id] || {};
    return `<div class="intake-q" data-question="${q.id}"><label for="q-${q.id}">${esc(q.text)}</label>
      ${q.kind === "yn" ? `<div class="intake-yn"><select id="q-${q.id}" data-yn="${q.id}"><option value="">–</option>${YES_NO.map((v) => `<option ${v === given.a ? "selected" : ""}>${v}</option>`).join("")}</select>
        <input data-text="${q.id}" value="${esc(given.t)}" maxlength="4000" placeholder="Details" aria-label="Details: ${esc(q.text)}" /></div>`
      : `<textarea id="q-${q.id}" data-text="${q.id}" rows="2" maxlength="4000">${esc(given.t)}</textarea>`}</div>`;
  };
  $("#sections").innerHTML = intakeSections(types).map((s) => `<div class="card tra-form-section"><h2>${esc(s.title)}</h2>${s.questions.map(question).join("")}</div>`).join("");
  updateProgress();
}

function updateProgress() {
  const questions = intakeQuestions(types);
  const done = questions.filter((q) => isAnswered(q, answers)).length;
  $("#progress-bar").style.width = `${questions.length ? Math.round((done / questions.length) * 100) : 0}%`;
  $("#progress-text").textContent = `${done} of ${questions.length}`;
}

const payload = () => ({ answers: cleanIntakeAnswers(answers), contributor: { name: $("#contributor-name").value.trim(), email: $("#contributor-email").value.trim() } });

function setSaveState(text, isError = false) {
  const el = $("#save-state");
  el.textContent = text;
  el.classList.toggle("error-text", isError);
}

function scheduleSave() {
  clearTimeout(saveTimer);
  setSaveState("Saving…");
  saveTimer = setTimeout(() => {
    saving = saving.then(() => call("assessment_intake_save", { token, response: payload(), submit: false }))
      .then(() => setSaveState("Saved. You can close this page and come back with the same link. You'll need to enter your name again."))
      .catch((err) => setSaveState(err.message, true));
  }, 800);
}

form.addEventListener("input", (e) => {
  const d = e.target.dataset;
  if (d.yn) answers[d.yn] = { ...answers[d.yn], a: e.target.value };
  else if (d.text) answers[d.text] = { ...answers[d.text], t: e.target.value };
  updateProgress();
  scheduleSave();
});
form.addEventListener("submit", async (e) => {
  e.preventDefault();
  if (!$("#contributor-name").value.trim()) {
    $("#contributor-name").focus();
    return setSaveState("Add your name before submitting.", true);
  }
  const open = intakeQuestions(types).filter((q) => !isAnswered(q, answers)).length;
  const unanswered = open ? `${open} question${open === 1 ? " isn't" : "s aren't"} answered. ` : "";
  if (!confirm(`${unanswered}You can only submit once, and this link stops working afterwards. Submit now?`)) return;
  clearTimeout(saveTimer);
  setSaveState("Submitting…");
  try {
    await saving;
    await call("assessment_intake_save", { token, response: payload(), submit: true });
    form.classList.add("hidden");
    intro.textContent = "Thank you. Your answers were sent to the cyber risk team for review. This link no longer works, so if you need to change something, ask for a new one.";
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
    const data = await call("assessment_intake_load", { token });
    types = data.types || [];
    answers = cleanIntakeAnswers(data.response?.answers);
    const brand = logoImg(data.logo, "", data.requester);
    if (brand) { $("#org-brand").innerHTML = brand; $("#org-brand").classList.remove("hidden"); }
    $("#form-title").textContent = data.requestName || "Technology request questions";
    intro.textContent = `${data.requester || "The cyber risk team"} asked you to answer these questions about this request, so a risk analyst can assess it. Answer what you can and leave the rest blank: the analyst will follow up where needed. Your answers save as you go.`;
    render();
    form.classList.remove("hidden");
  } catch (err) {
    intro.textContent = err.message;
    intro.classList.add("error-text");
  }
}
start();
