// Sections of the risk register editor, each holding the custom fields entered on a risk. Admins
// add, rename and remove sections and fields in Settings. Other is included to start with. Values
// are stored on each risk as `custom`, keyed by field id.
export const BUILT_IN_SECTIONS = ["Risk", "Assessment", "Treatment", "Ownership", "Workflow & governance"];
export const DEFAULT_RISK_SECTIONS = [{ id: "other", name: "Other", fields: [] }];
export const RISK_SECTION_LIMITS = { sections: 20, fieldsPerSection: 30, fields: 60, name: 60, label: 60, options: 30, option: 60 };
export const FIELD_TYPES = { text: "Text", longtext: "Long text", number: "Number", yesno: "Yes / No", date: "Date", picklist: "Pick list" };

const clean = (v, max) => (typeof v === "string" ? v.replace(/\s+/g, " ").trim().slice(0, max) : "");
const validId = (id) => typeof id === "string" && /^[a-z0-9]{1,20}$/.test(id);

// One field, checked. Pick lists keep their choices; other types drop them.
function cleanField(f) {
  const label = clean(f?.label, RISK_SECTION_LIMITS.label);
  if (!validId(f?.id) || !label || !(f.type in FIELD_TYPES)) return null;
  const field = { id: f.id, label, type: f.type };
  if (f.type === "picklist") {
    const seen = new Set();
    field.options = (Array.isArray(f.options) ? f.options : [])
      .map((o) => clean(o, RISK_SECTION_LIMITS.option))
      .filter((o) => o && !seen.has(o.toLowerCase()) && seen.add(o.toLowerCase()))
      .slice(0, RISK_SECTION_LIMITS.options);
  }
  return field;
}

// A workspace's sections, checked whatever was stored or sent. Null means the default list.
export function cleanRiskSections(raw) {
  if (!Array.isArray(raw)) return structuredClone(DEFAULT_RISK_SECTIONS);
  const ids = new Set(), names = new Set(BUILT_IN_SECTIONS.map((n) => n.toLowerCase()));
  const out = [];
  let fieldCount = 0;
  for (const s of raw) {
    const id = validId(s?.id) && !ids.has(s.id) ? s.id : "";
    const name = clean(s?.name, RISK_SECTION_LIMITS.name);
    if (!id || !name || names.has(name.toLowerCase())) continue;
    ids.add(id);
    names.add(name.toLowerCase());
    const fields = [];
    for (const f of Array.isArray(s.fields) ? s.fields : []) {
      const field = cleanField(f);
      if (!field || ids.has(field.id) || fields.length >= RISK_SECTION_LIMITS.fieldsPerSection || fieldCount >= RISK_SECTION_LIMITS.fields) continue;
      ids.add(field.id);
      fields.push(field);
      fieldCount++;
    }
    out.push({ id, name, fields });
    if (out.length === RISK_SECTION_LIMITS.sections) break;
  }
  return out;
}

// A new id, short and lower-case, that doesn't clash with any id in use.
export function newId(used) {
  let id;
  do id = `f${Math.random().toString(36).slice(2, 10)}`; while (used.has(id));
  return id;
}

export const allIds = (sections) => new Set(sections.flatMap((s) => [s.id, ...s.fields.map((f) => f.id)]));

// Why a section name can't be used, or "" if it can.
export function sectionNameProblem(name, sections, ignoreId = "") {
  const c = clean(name, 1000);
  if (!c) return "Give the section a name";
  if (c.length > RISK_SECTION_LIMITS.name) return `Keep the name to ${RISK_SECTION_LIMITS.name} characters`;
  const key = c.toLowerCase();
  if (BUILT_IN_SECTIONS.some((n) => n.toLowerCase() === key)) return `“${c}” is a built-in section`;
  if (sections.some((s) => s.id !== ignoreId && s.name.toLowerCase() === key)) return `There is already a section called “${c}”`;
  return "";
}

// Why a field can't be saved as given, or "" if it can.
export function fieldProblem(field, sections, ignoreId = "") {
  const label = clean(field.label, 1000);
  if (!label) return "Give the field a name";
  if (label.length > RISK_SECTION_LIMITS.label) return `Keep the field name to ${RISK_SECTION_LIMITS.label} characters`;
  if (!(field.type in FIELD_TYPES)) return "Choose a field type";
  if (field.type === "picklist" && !(field.options?.length)) return "A pick list needs at least one choice";
  const key = label.toLowerCase();
  if (sections.some((s) => s.fields.some((f) => f.id !== ignoreId && f.label.toLowerCase() === key && f.id !== field.id))) return `There is already a field called “${label}”`;
  return "";
}

// Choices typed as "A, B, C" become a list; blank entries are dropped.
export const parseOptions = (text) => String(text ?? "").split(/[,\n]/).map((o) => clean(o, RISK_SECTION_LIMITS.option)).filter(Boolean);

// The sections as they appear in the risk editor, with the risk's values filled in.
export function riskSectionsHtml(sections, escapeHtml, values = {}) {
  const esc = escapeHtml;
  const input = (f) => {
    const name = `cf:${esc(f.id)}`, v = values[f.id] ?? "";
    if (f.type === "longtext") return `<textarea name="${name}" rows="2">${esc(v)}</textarea>`;
    if (f.type === "number") return `<input name="${name}" type="number" step="any" value="${esc(v)}" />`;
    if (f.type === "date") return `<input name="${name}" type="date" value="${/^\d{4}-\d{2}-\d{2}$/.test(v) ? v : ""}" />`;
    if (f.type === "yesno") return `<select name="${name}"><option value="">–</option>${["Yes", "No"].map((o) => `<option ${o === v ? "selected" : ""}>${o}</option>`).join("")}</select>`;
    if (f.type === "picklist") return `<select name="${name}"><option value="">–</option>${(f.options || []).map((o) => `<option ${o === v ? "selected" : ""}>${esc(o)}</option>`).join("")}</select>`;
    return `<input name="${name}" value="${esc(v)}" maxlength="2000" />`;
  };
  return sections.map((s) => `<details class="form-section-details" data-section-id="${esc(s.id)}">
      <summary>${esc(s.name)}</summary>
      ${s.fields.length
        ? `<div class="form-grid">${s.fields.map((f) => `<label${f.type === "longtext" ? ' class="full"' : ""}>${esc(f.label)}${input(f)}</label>`).join("")}</div>`
        : '<p class="muted small">No fields yet.</p>'}
    </details>`).join("");
}

// The Settings card: sections, each with its fields. Every change is saved as it's made.
// `current()` returns the saved list; `save(next)` stores it and resolves once it's saved.
export function initRiskSections({ $, escapeHtml: esc, toast, current, save, canChange }) {
  const list = $("#risk-section-list");
  const form = $("#risk-section-form");
  const input = $("#risk-section-name");
  const note = $("#risk-section-note");
  let busy = false;

  const typeOptions = (selected) => Object.entries(FIELD_TYPES).map(([k, l]) => `<option value="${k}" ${k === selected ? "selected" : ""}>${l}</option>`).join("");

  function render() {
    const allowed = canChange();
    const sections = current();
    const dis = allowed ? "" : "disabled";
    list.innerHTML = sections.map((s) => `
      <li class="rs-section">
        <div class="rs-row">
          <input value="${esc(s.name)}" maxlength="${RISK_SECTION_LIMITS.name}" data-rs-name="${esc(s.id)}" aria-label="Section name" ${dis} />
          <button type="button" class="small danger" data-rs-remove="${esc(s.id)}" ${dis}>Remove section</button>
        </div>
        <ul class="rs-fields">
          ${s.fields.map((f) => `<li class="rs-row">
            <input value="${esc(f.label)}" maxlength="${RISK_SECTION_LIMITS.label}" data-rf-label="${esc(f.id)}" aria-label="Field name" ${dis} />
            <select data-rf-type="${esc(f.id)}" aria-label="Field type" ${dis}>${typeOptions(f.type)}</select>
            ${f.type === "picklist" ? `<input value="${esc((f.options || []).join(", "))}" data-rf-options="${esc(f.id)}" aria-label="Choices" placeholder="Choices, separated by commas" ${dis} />` : ""}
            <button type="button" class="small danger" data-rf-remove="${esc(f.id)}" ${dis}>Remove</button>
          </li>`).join("") || '<li class="muted small">No fields yet.</li>'}
        </ul>
        ${allowed ? `<form class="rs-add-field inline-form" data-add-field="${esc(s.id)}">
          <input name="label" maxlength="${RISK_SECTION_LIMITS.label}" placeholder="New field, e.g. Owner approval date" aria-label="New field name" />
          <select name="type" aria-label="Field type">${typeOptions("text")}</select>
          <input name="options" placeholder="Choices for a pick list, separated by commas" aria-label="Choices" />
          <button type="submit">Add field</button>
        </form>` : ""}
      </li>`).join("") || '<li class="muted small">No sections yet.</li>';
    form.classList.toggle("hidden", !allowed);
    note.classList.toggle("hidden", allowed);
  }

  async function change(next, message) {
    if (busy) return;
    busy = true;
    try {
      await save(next);
      toast(message);
    } catch (err) {
      toast(`Couldn't save the sections: ${err.message}`, true);
    } finally {
      busy = false;
      render();
    }
  }

  const totalFields = (sections) => sections.reduce((n, s) => n + s.fields.length, 0);
  const sectionOf = (sections, id) => sections.find((s) => s.id === id);

  // Adds a section.
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const sections = current();
    const problem = sectionNameProblem(input.value, sections);
    if (problem) return toast(problem, true);
    if (sections.length >= RISK_SECTION_LIMITS.sections) return toast(`Up to ${RISK_SECTION_LIMITS.sections} sections`, true);
    const name = clean(input.value, RISK_SECTION_LIMITS.name);
    input.value = "";
    change([...sections, { id: newId(allIds(sections)), name, fields: [] }], `Added “${name}”`);
  });

  list.addEventListener("submit", (e) => {
    const sectionId = e.target.dataset.addField;
    if (!sectionId) return;
    e.preventDefault();
    const sections = current();
    const section = sectionOf(sections, sectionId);
    const fd = new FormData(e.target);
    const field = { id: newId(allIds(sections)), label: clean(fd.get("label"), 1000), type: fd.get("type"), options: parseOptions(fd.get("options")) };
    if (!section) return;
    const problem = fieldProblem(field, sections);
    if (problem) return toast(problem, true);
    if (section.fields.length >= RISK_SECTION_LIMITS.fieldsPerSection) return toast(`Up to ${RISK_SECTION_LIMITS.fieldsPerSection} fields in a section`, true);
    if (totalFields(sections) >= RISK_SECTION_LIMITS.fields) return toast(`Up to ${RISK_SECTION_LIMITS.fields} fields in all`, true);
    const added = cleanField(field);
    change(sections.map((s) => (s.id === sectionId ? { ...s, fields: [...s.fields, added] } : s)), `Added “${added.label}”`);
  });

  // Renames a section, or changes a field's name, type or choices.
  list.addEventListener("change", (e) => {
    const d = e.target.dataset;
    const sections = current();
    if (d.rsName) {
      const problem = sectionNameProblem(e.target.value, sections, d.rsName);
      if (problem) { toast(problem, true); return render(); }
      const name = clean(e.target.value, RISK_SECTION_LIMITS.name);
      return change(sections.map((s) => (s.id === d.rsName ? { ...s, name } : s)), "Section renamed");
    }
    const fieldId = d.rfLabel || d.rfType || d.rfOptions;
    if (!fieldId) return;
    const owner = sections.find((s) => s.fields.some((f) => f.id === fieldId));
    const field = owner?.fields.find((f) => f.id === fieldId);
    if (!field) return;
    const next = d.rfLabel ? { ...field, label: e.target.value }
      : d.rfType ? { ...field, type: e.target.value, options: e.target.value === "picklist" ? field.options || [] : undefined }
      : { ...field, options: parseOptions(e.target.value) };
    const problem = fieldProblem(next, sections, fieldId);
    if (problem) { toast(problem, true); return render(); }
    const saved = cleanField(next);
    change(sections.map((s) => (s === owner ? { ...s, fields: s.fields.map((f) => (f.id === fieldId ? saved : f)) } : s)), "Field saved");
  });

  list.addEventListener("click", (e) => {
    const d = e.target.dataset;
    const sections = current();
    if (d.rsRemove) {
      const s = sectionOf(sections, d.rsRemove);
      if (!confirm(`Remove the section “${s?.name}” and its ${s?.fields.length || 0} field(s)? Values already entered for them stay saved on the risks but aren't shown.`)) return;
      return change(sections.filter((x) => x.id !== d.rsRemove), "Section removed");
    }
    if (d.rfRemove) {
      const owner = sections.find((s) => s.fields.some((f) => f.id === d.rfRemove));
      const field = owner?.fields.find((f) => f.id === d.rfRemove);
      if (!field || !confirm(`Remove the field “${field.label}”? Values already entered for it stay saved on the risks but aren't shown.`)) return;
      change(sections.map((s) => (s === owner ? { ...s, fields: s.fields.filter((f) => f.id !== d.rfRemove) } : s)), "Field removed");
    }
  });

  render();
  return { render };
}
