// Short risk level labels for the tab tables: "2. M" for Medium, with the full word shown on hover and read to screen
// readers. Risk and vendor tiers have four levels; posture snapshots and threat posture assessments have five.
const SCALES = {
  four: { Low: "1. L", Medium: "2. M", High: "3. H", Critical: "4. C" },
  five: { "Very Low": "1. VL", Low: "2. L", Medium: "3. M", Moderate: "3. M", High: "4. H", "Very High": "5. VH",
    // Older snapshots called the top level Critical.
    Critical: "5. VH" },
};

export const shortLevel = (name, scale = "four") => SCALES[scale]?.[name] || "";

// The label for a level in a table. `cls` is its colour class and `esc` escapes HTML. A value that isn't a level of the
// scale is shown as it is, at the usual label size.
export function levelBadge(name, { cls = "", scale = "four", esc }) {
  const short = shortLevel(name, scale);
  if (!short) return `<span class="badge ${cls}">${esc(name)}</span>`;
  return `<span class="badge level ${cls}" data-tip="${esc(name)}"><span aria-hidden="true">${short}</span><span class="sr-only">${esc(name)}</span></span>`;
}
