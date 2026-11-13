// Sections of the risk register editor beyond the built-in ones. The built-in sections (Risk,
// Assessment, Treatment, Ownership and Workflow & governance) stay as they are. Admins add,
// rename and remove the others in Settings. A section holds no fields yet; fields come later.
export const BUILT_IN_SECTIONS = ["Risk", "Assessment", "Treatment", "Ownership", "Workflow & governance"];
export const DEFAULT_RISK_SECTIONS = [{ id: "other", name: "Other" }];
export const RISK_SECTION_LIMITS = { sections: 20, name: 60 };

// A workspace's sections, checked whatever was stored or sent. Null means the default list.
export function cleanRiskSections(raw) {
  if (!Array.isArray(raw)) return structuredClone(DEFAULT_RISK_SECTIONS);
  const ids = new Set(), names = new Set(BUILT_IN_SECTIONS.map((n) => n.toLowerCase()));
  const out = [];
  for (const s of raw) {
    const id = typeof s?.id === "string" && /^[a-z0-9]{1,20}$/.test(s.id) ? s.id : "";
    const name = typeof s?.name === "string" ? s.name.replace(/\s+/g, " ").trim().slice(0, RISK_SECTION_LIMITS.name) : "";
    const key = name.toLowerCase();
    if (!id || !name || ids.has(id) || names.has(key)) continue;
    ids.add(id);
    names.add(key);
    out.push({ id, name });
    if (out.length === RISK_SECTION_LIMITS.sections) break;
  }
  return out;
}

// A new section's id: short, lower-case and unlikely to clash with an existing one.
export const newSectionId = (existing) => {
  let id;
  do id = `s${Math.random().toString(36).slice(2, 10)}`; while (existing.some((s) => s.id === id));
  return id;
};

// Why a name can't be used, or "" if it can.
export function sectionNameProblem(name, sections, ignoreId = "") {
  const clean = String(name ?? "").replace(/\s+/g, " ").trim();
  if (!clean) return "Give the section a name";
  if (clean.length > RISK_SECTION_LIMITS.name) return `Keep the name to ${RISK_SECTION_LIMITS.name} characters`;
  const key = clean.toLowerCase();
  if (BUILT_IN_SECTIONS.some((n) => n.toLowerCase() === key)) return `“${clean}” is a built-in section`;
  if (sections.some((s) => s.id !== ignoreId && s.name.toLowerCase() === key)) return `There is already a section called “${clean}”`;
  return "";
}

// The custom sections as they appear in the risk editor (no fields yet, so each says so).
export function riskSectionsHtml(sections, escapeHtml) {
  return sections.map((s) => `<details class="form-section-details" data-section-id="${escapeHtml(s.id)}">
      <summary>${escapeHtml(s.name)}</summary>
      <p class="muted small">No fields yet.</p>
    </details>`).join("");
}

// The Settings card: lists the sections and lets an admin add, rename and remove them.
// `current()` returns the saved list; `save(next)` stores it and resolves once it's saved.
export function initRiskSections({ $, escapeHtml, toast, current, save, canChange }) {
  const list = $("#risk-section-list");
  const form = $("#risk-section-form");
  const input = $("#risk-section-name");
  const note = $("#risk-section-note");
  let busy = false;

  function render() {
    const allowed = canChange();
    const sections = current();
    list.innerHTML = sections.map((s) => `
      <li class="rs-row">
        <input value="${escapeHtml(s.name)}" maxlength="${RISK_SECTION_LIMITS.name}" data-rs-name="${escapeHtml(s.id)}" aria-label="Section name" ${allowed ? "" : "disabled"} />
        <button type="button" class="small danger" data-rs-remove="${escapeHtml(s.id)}" ${allowed ? "" : "disabled"}>Remove</button>
      </li>`).join("") || '<li class="muted small">No sections of your own yet.</li>';
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

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const sections = current();
    const problem = sectionNameProblem(input.value, sections);
    if (problem) return toast(problem, true);
    if (sections.length >= RISK_SECTION_LIMITS.sections) return toast(`Up to ${RISK_SECTION_LIMITS.sections} sections of your own`, true);
    const name = input.value.replace(/\s+/g, " ").trim();
    input.value = "";
    change([...sections, { id: newSectionId(sections), name }], `Added “${name}”`);
  });

  list.addEventListener("change", (e) => {
    const id = e.target.dataset.rsName;
    if (!id) return;
    const sections = current();
    const problem = sectionNameProblem(e.target.value, sections, id);
    if (problem) { toast(problem, true); return render(); }
    const name = e.target.value.replace(/\s+/g, " ").trim();
    change(sections.map((s) => (s.id === id ? { ...s, name } : s)), "Section renamed");
  });

  list.addEventListener("click", (e) => {
    const id = e.target.dataset.rsRemove;
    if (!id) return;
    const sections = current();
    const s = sections.find((x) => x.id === id);
    if (!confirm(`Remove the section “${s?.name}”? Any fields in it are removed with it.`)) return;
    change(sections.filter((x) => x.id !== id), "Section removed");
  });

  render();
  return { render };
}
