// The short level names on screen: V.LOW, LOW, MED, HIGH, V.HIGH and CRIT, with the full word shown on hover and read to
// screen readers. Moderate (threat posture assessments) reads MED. Drop-down choices, sentences and PDFs keep full words.
const SHORT = { "Very Low": "V.LOW", Low: "LOW", Medium: "MED", Moderate: "MED", High: "HIGH", "Very High": "V.HIGH", Critical: "CRIT" };

// Posture snapshots use five levels; older ones called the top one Critical.
export const shortLevel = (name, scale) => (scale === "five" && name === "Critical" ? SHORT["Very High"] : SHORT[name] || "");

// The label for a level. `cls` is its colour class, `esc` escapes HTML and `prefix` is text kept in front (such as a
// score). A value that isn't a level is shown as it is, at the usual label size.
export function levelBadge(name, { cls = "", scale, esc, prefix = "" }) {
  const short = shortLevel(name, scale);
  const lead = prefix ? `${esc(prefix)} ` : "";
  if (!short) return `<span class="badge ${cls}">${lead}${esc(name)}</span>`;
  return `<span class="badge level ${cls}" data-tip="${esc(name)}"><span aria-hidden="true">${lead}${short}</span><span class="sr-only">${lead}${esc(name)}</span></span>`;
}
