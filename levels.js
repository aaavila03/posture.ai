// The short level names on screen: V.LOW, LOW, MED, HIGH and CRIT, with the full word shown on hover and read to
// screen readers. Moderate (threat posture assessments) reads MED. Drop-down choices, sentences and PDFs keep full words.
const SHORT = { "Very Low": "V.LOW", Low: "LOW", Medium: "MED", Moderate: "MED", High: "HIGH", "Very High": "CRIT", Critical: "CRIT" };

// The top level is called Critical everywhere people read it. Snapshots and threat posture assessments store it as
// "Very High" (their scale's name for it), which stays in the saved records; this is only the wording.
export const shownLevel = (name) => (name === "Very High" ? "Critical" : name || "");

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
