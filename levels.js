// The short level names on screen: LOW, MED, HIGH and CRIT, with the full word shown on hover and read to
// screen readers. Moderate (threat posture assessments) reads MED. Drop-down choices, sentences and PDFs keep full words.
const SHORT = { "Very Low": "LOW", Low: "LOW", Medium: "MED", Moderate: "MED", High: "HIGH", "Very High": "CRIT", Critical: "CRIT" };

// People see four levels everywhere: Low, Medium, High and Critical. Posture snapshots and threat posture
// assessments store "Very High", "Moderate" and "Very Low" (their scale's names), which stay as they are underneath;
// they read Critical, Medium and Low. This is only the wording.
export const shownLevel = (name) => ({ "Very High": "Critical", "Very Low": "Low", Moderate: "Medium" }[name] || name || "");

export const shortLevel = (name) => SHORT[name] || "";

// The label for a level. `cls` is its colour class, `esc` escapes HTML and `prefix` is text kept in front (such as a
// score). A value that isn't a level is shown as it is, at the usual label size.
export function levelBadge(name, { cls = "", esc, prefix = "" }) {
  const short = shortLevel(name);
  const full = shownLevel(name);
  const lead = prefix ? `${esc(prefix)} ` : "";
  if (!short) return `<span class="badge ${cls}">${lead}${esc(name)}</span>`;
  return `<span class="badge level ${cls}" data-tip="${esc(full)}"><span aria-hidden="true">${lead}${short}</span><span class="sr-only">${lead}${esc(full)}</span></span>`;
}
