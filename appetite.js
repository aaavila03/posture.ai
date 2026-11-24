// Risk appetite: the highest residual risk level the organisation accepts, with an optional limit for each
// category. A risk whose residual level is above its limit is "outside appetite". Without an appetite set
// (null) nothing is flagged. The workspace's appetite is { default, categories: { [category]: level } }.
export const APPETITE_LEVELS = ["Low", "Medium", "High", "Critical"];

// The categories a risk can have (the Category list in the risk editor).
export const APPETITE_CATEGORIES = ["Ransomware/Malware", "Phishing/Social Engineering", "Data Breach", "Insider Threat", "Third-Party/Supply Chain",
  "Cloud Misconfiguration", "Vulnerability/Patching", "Identity & Access", "Availability/DDoS", "Compliance/Regulatory", "Other"];

const rank = (level) => APPETITE_LEVELS.indexOf(level) + 1;

// Keeps only a valid appetite: a known default level, and limits for known categories with known levels.
export function cleanAppetite(raw) {
  if (!raw || typeof raw !== "object" || !APPETITE_LEVELS.includes(raw.default)) return null;
  const categories = {};
  for (const category of APPETITE_CATEGORIES) {
    const level = raw.categories?.[category];
    if (APPETITE_LEVELS.includes(level)) categories[category] = level;
  }
  return { default: raw.default, categories };
}

// The limit for a category: its own, or the default.
export const limitFor = (appetite, category) => (appetite ? appetite.categories[category] ?? appetite.default : null);

// How a risk stands against the appetite, from its category, residual level (Low to Critical) and stage.
// null when there is no appetite or the risk is closed. `over` is how many levels it is above the limit.
export function appetiteCheck(appetite, { category, residualLevel, status }) {
  if (!appetite || status === "Closed") return null;
  const limit = limitFor(appetite, category);
  const over = Math.max(0, rank(residualLevel) - rank(limit));
  return { limit, over, outside: over > 0 };
}

// Why a risk stands where it does, without saying whether it is in or out (for beside a badge that already says so):
// "residual High is above the Medium limit for Data Breach" / "limit Medium".
export function appetiteReason(check, { residualLevel, category }) {
  if (!check) return "";
  return check.outside ? `residual ${residualLevel} is above the ${check.limit} limit for ${category || "this category"}` : `limit ${check.limit}`;
}

// The whole sentence: "Outside appetite: residual High is above the Medium limit for Data Breach." / "Within appetite (limit Medium)."
export function appetiteText(check, ctx) {
  if (!check) return "";
  return check.outside ? `Outside appetite: ${appetiteReason(check, ctx)}.` : `Within appetite (${appetiteReason(check, ctx)}).`;
}
