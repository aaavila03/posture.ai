// The level names on screen: LOW, MED, HIGH and CRITICAL, with the full word shown on hover and read to
// screen readers. Moderate (threat posture assessments) reads MED. Drop-down choices, sentences and PDFs keep full words.
const SHORT = { "Very Low": "LOW", Low: "LOW", Medium: "MED", Moderate: "MED", High: "HIGH", "Very High": "CRITICAL", Critical: "CRITICAL" };

// People see four levels everywhere: Low, Medium, High and Critical. Posture snapshots and threat posture
// assessments store "Very High", "Moderate" and "Very Low" (their scale's names), which stay as they are underneath;
// they read Critical, Medium and Low. This is only the wording.
export const shownLevel = (name) => ({ "Very High": "Critical", "Very Low": "Low", Moderate: "Medium" }[name] || name || "");

export const shortLevel = (name) => SHORT[name] || "";

// The label for a level. `cls` is its colour class and `esc` escapes HTML. A value that isn't a level is shown as it is,
// at the usual label size. CRITICAL is longer than the others, so its text is a little smaller to fit the same box.
export function levelBadge(name, { cls = "", esc }) {
  const short = shortLevel(name);
  const full = shownLevel(name);
  if (!short) return `<span class="badge ${cls}">${esc(name)}</span>`;
  return `<span class="badge level ${cls}" data-tip="${esc(full)}"><span aria-hidden="true"${short.length > 6 ? ' class="long"' : ""}>${short}</span><span class="sr-only">${esc(full)}</span></span>`;
}
