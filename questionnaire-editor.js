// Editor for the workspace's version of the vendor intake questionnaire (Settings).
// Built-in questions can be reworded or turned off, and the workspace can add its own
// questions and sections. What it saves is the customisation described in
// intake-questions.js; the built-in set itself never changes.
import { DEFAULT_DOMAINS, CUSTOM_LIMITS, QUESTION_TYPES, cleanCustomization, buildQuestionnaire, isCustomized } from "./intake-questions.js";

const TYPE_TAG = { inverse: "Yes is a red flag", info: "Context only" };

// `current()` returns the saved customisation, `save(custom)` stores it (null for the
// built-in questionnaire) and `canChange()` says whether this user may edit it.
export function initQuestionnaireEditor({ $, escapeHtml, toast, current, save, canChange }) {
  const dialog = $("#questionnaire-dialog");
  const body = $("#questionnaire-body");
  let draft = null;     // the customisation being edited
  let saved = "";       // the draft as it was opened, to spot unsaved changes
  let open = new Set(); // sections left expanded

  const customQuestions = (section) => draft.questions.filter((q) => q.section === section);
  const snapshot = () => JSON.stringify(draft);

  // A line for the Settings card: how the questionnaire differs from the built-in one.
  function showSummary() {
    const c = cleanCustomization(current());
    const { domains, questions } = buildQuestionnaire(c);
    const optional = domains.filter((d) => d.module).reduce((n, d) => n + d.questions.length, 0);
    const reworded = Object.keys(c.text).filter((id) => !c.hidden.includes(id)).length;
    const changes = [c.hidden.length && `${c.hidden.length} turned off`, reworded && `${reworded} reworded`, c.questions.length && `${c.questions.length} of your own`].filter(Boolean);
    $("#questionnaire-summary").textContent = `${questions.length - optional} questions in ${domains.filter((d) => !d.module).length} sections`
      + `${optional ? `, plus ${optional} in optional sections` : ""}. ${changes.length ? `Changed from the built-in questionnaire: ${changes.join(", ")}.` : "This is the built-in questionnaire."}`;
    $("#btn-questionnaire-edit").classList.toggle("hidden", !canChange());
    $("#questionnaire-note").classList.toggle("hidden", canChange());
  }

  const typeSelect = (q) => `<select data-ctype="${q.id}" aria-label="How ${q.id} is scored">${Object.entries(QUESTION_TYPES)
    .map(([value, label]) => `<option value="${value}" ${value === q.type ? "selected" : ""}>${escapeHtml(label)}</option>`).join("")}</select>`;

  const customRow = (q) => `
    <div class="qe-row qe-custom">
      <div class="qe-main">
        <span class="iq-id">${q.id}</span>
        <textarea data-ctext="${q.id}" rows="2" maxlength="${CUSTOM_LIMITS.text}" placeholder="Write a question the vendor can answer Yes, No or N/A" aria-label="Question ${q.id}">${escapeHtml(q.text)}</textarea>
      </div>
      <div class="qe-meta">${typeSelect(q)} <button type="button" class="small danger" data-remove-q="${q.id}">Remove</button></div>
    </div>`;

  function builtInRow(q, off) {
    const mine = off.has(q.id);
    const byParent = !mine && q.parent && (off.has(q.parent));
    const text = draft.text[q.id] ?? q.text;
    const notes = [
      TYPE_TAG[q.type] && `<span class="tag">${TYPE_TAG[q.type]}</span>`,
      q.maps && `<span class="tag" title="The answer feeds the vendor's control score">Control score</span>`,
      q.parent && `<span class="small muted">Asked only if ${q.parent} is ${q.showIf}${byParent ? ` – off because ${q.parent} is off` : ""}</span>`,
      `<button type="button" class="small link${draft.text[q.id] ? "" : " hidden"}" data-reset-text="${q.id}">Use original wording</button>`,
    ].filter(Boolean).join(" ");
    return `
    <div class="qe-row${q.parent ? " iq-child" : ""}${mine || byParent ? " qe-off" : ""}">
      <div class="qe-main">
        <label class="qe-toggle" title="Include this question"><input type="checkbox" data-on="${q.id}" ${mine ? "" : "checked"} ${byParent ? "disabled" : ""} aria-label="Include ${q.id}" /> <span class="iq-id">${q.id}</span></label>
        <textarea data-text="${q.id}" rows="2" maxlength="${CUSTOM_LIMITS.text}" aria-label="Wording of ${q.id}" ${mine || byParent ? "disabled" : ""}>${escapeHtml(text)}</textarea>
      </div>
      <div class="qe-meta">${notes}</div>
    </div>`;
  }

  function sectionHtml({ id, title, module, questions = [], custom }) {
    const off = new Set(draft.hidden);
    const added = customQuestions(id);
    const on = questions.filter((q) => !off.has(q.id) && !(q.parent && off.has(q.parent))).length + added.length;
    const full = draft.questions.length >= CUSTOM_LIMITS.questions;
    return `
    <details class="card domain qe-section" data-section="${id}" ${open.has(id) ? "open" : ""}>
      <summary><span><span data-title-of="${id}">${escapeHtml(title || "New section")}</span>${module ? ' <span class="tag">optional section</span>' : ""}${custom ? ' <span class="tag">yours</span>' : ""}</span>
        <span class="domain-count small muted">${on ? `${on} question${on === 1 ? "" : "s"}` : "not sent"}</span></summary>
      <div class="qe-section-bar">
        ${custom
          ? `<input data-stitle="${id}" value="${escapeHtml(title)}" maxlength="${CUSTOM_LIMITS.title}" placeholder="Section title" aria-label="Section title" />
             <button type="button" class="small danger" data-remove-s="${id}">Remove section</button>`
          : `<button type="button" class="small" data-all="${id}" data-to="${on === added.length ? "on" : "off"}">${on === added.length ? "Turn all built-in questions on" : "Turn all built-in questions off"}</button>`}
      </div>
      ${questions.map((q) => builtInRow(q, off)).join("")}
      ${added.map(customRow).join("")}
      <div class="qe-row"><button type="button" class="small" data-add="${id}" ${full ? "disabled" : ""}>+ Add a question</button>
        ${full ? `<span class="small muted">You've reached the limit of ${CUSTOM_LIMITS.questions} questions of your own.</span>` : ""}</div>
    </details>`;
  }

  function render(focus) {
    body.innerHTML = [
      ...DEFAULT_DOMAINS.map(sectionHtml),
      ...draft.sections.map((s) => sectionHtml({ ...s, custom: true })),
    ].join("");
    $("#btn-questionnaire-section").disabled = draft.sections.length >= CUSTOM_LIMITS.sections;
    if (focus) body.querySelector(focus)?.focus();
  }

  const nextId = (prefix) => `${prefix}${++draft.seq}`;

  body.addEventListener("toggle", (e) => {
    const id = e.target.dataset?.section;
    if (!id) return;
    if (e.target.open) open.add(id); else open.delete(id);
  }, true);

  // Typing only updates the draft, so the field keeps its focus.
  body.addEventListener("input", (e) => {
    const d = e.target.dataset;
    if (d.text) {
      const original = DEFAULT_DOMAINS.flatMap((x) => x.questions).find((q) => q.id === d.text).text;
      if (e.target.value.trim() && e.target.value.trim() !== original) draft.text[d.text] = e.target.value;
      else delete draft.text[d.text];
      body.querySelector(`[data-reset-text="${d.text}"]`).classList.toggle("hidden", !draft.text[d.text]);
    } else if (d.ctext) {
      draft.questions.find((q) => q.id === d.ctext).text = e.target.value;
    } else if (d.stitle) {
      draft.sections.find((s) => s.id === d.stitle).title = e.target.value;
      body.querySelector(`[data-title-of="${d.stitle}"]`).textContent = e.target.value.trim() || "New section";
    }
  });

  body.addEventListener("change", (e) => {
    const d = e.target.dataset;
    if (d.on) {
      draft.hidden = e.target.checked ? draft.hidden.filter((id) => id !== d.on) : [...draft.hidden, d.on];
      render(`[data-on="${d.on}"]`);
    } else if (d.ctype) {
      draft.questions.find((q) => q.id === d.ctype).type = e.target.value;
    }
  });

  body.addEventListener("click", (e) => {
    const d = e.target.dataset;
    if (d.add) {
      if (draft.seq >= 999) return toast("This workspace has used every question number. Reword an existing question instead.", true);
      const q = { id: nextId("CQ"), section: d.add, text: "", type: "" };
      draft.questions.push(q);
      render(`[data-ctext="${q.id}"]`);
    } else if (d.removeQ) {
      draft.questions = draft.questions.filter((q) => q.id !== d.removeQ);
      render();
    } else if (d.removeS) {
      const n = customQuestions(d.removeS).length;
      if (n && !confirm(`Remove this section and its ${n} question${n === 1 ? "" : "s"}?`)) return;
      draft.sections = draft.sections.filter((s) => s.id !== d.removeS);
      draft.questions = draft.questions.filter((q) => q.section !== d.removeS);
      render();
    } else if (d.resetText) {
      delete draft.text[d.resetText];
      render(`[data-text="${d.resetText}"]`);
    } else if (d.all) {
      const ids = DEFAULT_DOMAINS.find((x) => x.id === d.all).questions.map((q) => q.id);
      draft.hidden = draft.hidden.filter((id) => !ids.includes(id));
      if (d.to === "off") draft.hidden.push(...ids);
      render(`[data-all="${d.all}"]`);
    }
  });

  $("#btn-questionnaire-section").addEventListener("click", () => {
    if (draft.seq >= 999) return toast("This workspace has used every section number.", true);
    const s = { id: nextId("CS"), title: "" };
    draft.sections.push(s);
    open.add(s.id);
    render(`[data-stitle="${s.id}"]`);
  });

  $("#btn-questionnaire-reset").addEventListener("click", () => {
    if (!confirm("Go back to the built-in questionnaire? Your reworded questions, the ones you turned off and the questions and sections you added will be removed when you save.")) return;
    draft = { ...cleanCustomization(null), seq: draft.seq };
    render();
  });

  function close() {
    if (snapshot() !== saved && !confirm("Discard your changes to the questionnaire?")) return;
    dialog.close();
  }
  $("#btn-questionnaire-close").addEventListener("click", close);
  $("#btn-questionnaire-cancel").addEventListener("click", close);
  dialog.addEventListener("cancel", (e) => { e.preventDefault(); close(); });

  $("#questionnaire-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    // Anything left blank would silently disappear, so ask for it instead.
    const blankSection = draft.sections.find((s) => !s.title.trim());
    const blank = draft.questions.find((q) => !q.text.trim());
    if (blankSection || blank) {
      open.add(blankSection ? blankSection.id : blank.section);
      render(blankSection ? `[data-stitle="${blankSection.id}"]` : `[data-ctext="${blank.id}"]`);
      return toast(blankSection ? "Give the new section a title, or remove it" : "Write the new question, or remove it", true);
    }
    const emptySection = draft.sections.find((s) => !customQuestions(s.id).length);
    if (emptySection) {
      open.add(emptySection.id);
      render(`[data-add="${emptySection.id}"]`);
      return toast(`Add a question to “${emptySection.title.trim()}”, or remove the section`, true);
    }
    const before = cleanCustomization(current());
    const next = cleanCustomization(draft);
    const kept = new Set(buildQuestionnaire(next).questions.map((q) => q.id));
    const dropped = buildQuestionnaire(before).questions.filter((q) => !kept.has(q.id)).length;
    if (dropped && !confirm(`${dropped} question${dropped === 1 ? " is" : "s are"} being removed from the questionnaire. Answers vendors have already given to ${dropped === 1 ? "it" : "them"} will no longer be shown or scored. Save?`)) return;
    const btn = $("#btn-questionnaire-save");
    btn.disabled = true;
    try {
      // Keep the numbering even when everything else is back to the built-in set.
      await save(isCustomized(next) || next.seq ? next : null);
    } catch (err) {
      return toast(`Couldn't save the questionnaire: ${err.message}`, true);
    } finally {
      btn.disabled = false;
    }
    dialog.close();
    showSummary();
    toast("Questionnaire saved. Vendors see it the next time they open their link.");
  });

  $("#btn-questionnaire-edit").addEventListener("click", () => {
    draft = cleanCustomization(current());
    saved = snapshot();
    open = new Set();
    render();
    dialog.showModal();
    body.scrollTop = 0;
  });

  showSummary();
  return { showSummary };
}
