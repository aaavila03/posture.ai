// CSV import and template for the risk ledger. The columns match Export CSV, so a file
// exported from the ledger can be edited in a spreadsheet and imported again.
import { parseCsv } from "./people.js";

// Named levels for the 1–5 scales, shown as e.g. "4. Likely".
export const LIKELIHOOD = ["Rare", "Unlikely", "Possible", "Likely", "Almost certain"];
export const IMPACT = ["Very low", "Low", "Medium", "High", "Very high"];
// The middle step used to be called Moderate. Saved asset criticality keeps "3. Moderate"; this is how it reads, and
// shownCriticality's reverse (savedCriticality) turns an imported "3. Medium" back into the saved form.
export const shownCriticality = (value) => (value === "3. Moderate" ? "3. Medium" : value);
export const savedCriticality = (value) => (value === "3. Medium" ? "3. Moderate" : value);
// Risk lifecycle stages. Risks saved before stages existed used "Open".
export const STAGES = ["Identified", "Assessment", "In treatment", "Monitoring", "Accepted", "Closed"];
export const REVIEW_MONTHS = { Monthly: 1, Quarterly: 3, "Semi-annually": 6, Annually: 12 };

export const CSV_COLS = ["id", "title", "description", "memo", "asset", "assetCriticality", "category", "riskGroup", "threatType", "threatSource",
  "dataImpact", "businessImpact", "ticket", "vulnRef", "internalStandard", "nistControls",
  "likelihood", "impact", "inherentScore", "inherentLevel", "residualLikelihood", "residualImpact", "residualScore", "residualLevel",
  "treatment", "logException", "exceptionApproved", "exceptionExpiry", "controls", "estimatedCost", "remediationProject", "treatmentCompletion", "due", "slippage", "appetiteLimit", "outsideAppetite",
  "reviewFrequency", "nextReview", "owner", "ownerDepartment", "assetOwner", "delegate", "buDirector", "buVp",
  "complianceAnalyst", "riskAnalyst", "grcManager", "status", "createdBy", "createdDate", "submittedBy", "submittedDate",
  "treatmentBy", "treatmentDate", "approvedBy", "approvedDate", "completedBy", "completedDate",
  "oversightReview", "committeeReview", "committeeNotes", "comments"];

// Columns the app works out from other fields; they are ignored on import.
const COMPUTED = new Set(["inherentScore", "inherentLevel", "residualScore", "residualLevel", "slippage", "appetiteLimit", "outsideAppetite", "comments"]);
const SCALE_COLS = { likelihood: LIKELIHOOD, impact: IMPACT, residualLikelihood: LIKELIHOOD, residualImpact: IMPACT };
const DATE_COLS = new Set(["due", "nextReview", "exceptionExpiry", "treatmentCompletion", "createdDate", "submittedDate", "treatmentDate", "approvedDate", "completedDate"]);
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

// Cell text as the file holds it. Export puts a quote before values a spreadsheet would
// read as formulas, so that quote is removed here.
const cellValue = (s) => {
  const v = String(s ?? "").trim();
  return /^'[=+\-@\t\r]/.test(v) ? v.slice(1) : v;
};

// A level as written by the export ("3. Possible") or as a plain number or name.
function parseLevel(text, names) {
  const digit = text.match(/^([1-5])\b/);
  if (digit) return Number(digit[1]);
  // Files written before the rename say Moderate.
  const wanted = text.toLowerCase() === "moderate" && names.includes("Medium") ? "medium" : text.toLowerCase();
  const i = names.findIndex((n) => n.toLowerCase() === wanted);
  return i >= 0 ? i + 1 : null;
}

function parseStage(text) {
  const name = text.replace(/^\d+\.\s*/, "");
  return STAGES.find((s) => s.toLowerCase() === name.toLowerCase()) || null;
}

// Reads a risk CSV file. customFields lists the custom fields as { id, label }, where the
// label is the column heading used by Export CSV ("Section: Field").
// Returns { risks, errors }: the valid rows as field objects, and a message for each skipped row.
export function riskRowsFromCsv(text, customFields = []) {
  const rows = parseCsv(String(text).replace(/^﻿/, ""));
  if (!rows.length) return { risks: [], errors: ["The file is empty."] };
  const customByLabel = new Map(customFields.map((f) => [f.label, f.id]));
  const columns = rows[0].map((h) => {
    const name = h.trim();
    return { col: CSV_COLS.includes(name) ? name : null, custom: customByLabel.get(name) || null };
  });
  if (!columns.some((c) => c.col === "title")) return { risks: [], errors: ["The file needs a title column (see the template)."] };

  const risks = [];
  const errors = [];
  rows.slice(1).forEach((cells, index) => {
    const row = {};
    const problems = [];
    columns.forEach((c, j) => {
      const raw = cellValue(cells[j]);
      if (!raw || raw === "–") return; // "–" is how the export shows an empty level
      if (c.custom) { row.custom = { ...row.custom, [c.custom]: raw }; return; }
      if (!c.col || COMPUTED.has(c.col)) return;
      if (SCALE_COLS[c.col]) {
        const n = parseLevel(raw, SCALE_COLS[c.col]);
        if (n == null) problems.push(`${c.col} must be 1–5 or a level name`);
        else row[c.col] = n;
      } else if (c.col === "status") {
        const stage = parseStage(raw);
        if (!stage) problems.push(`status must be one of ${STAGES.join(", ")}`);
        else row.status = stage;
      } else if (c.col === "reviewFrequency") {
        if (!Object.hasOwn(REVIEW_MONTHS, raw)) problems.push(`reviewFrequency must be ${Object.keys(REVIEW_MONTHS).join(", ")}`);
        else row.reviewFrequency = raw;
      } else if (DATE_COLS.has(c.col)) {
        if (!ISO_DATE.test(raw) || Number.isNaN(Date.parse(`${raw}T00:00:00`))) problems.push(`${c.col} must be a date as YYYY-MM-DD`);
        else row[c.col] = raw;
      } else if (c.col === "assetCriticality") {
        row.assetCriticality = savedCriticality(raw);
      } else {
        row[c.col] = raw;
      }
    });
    if (!row.title) problems.push("title is required");
    if (problems.length) errors.push(`Row ${index + 2}: ${problems.join("; ")}`);
    else risks.push(row);
  });
  return { risks, errors };
}

// A file with only the heading row, so people can fill it in and import it.
export function riskCsvTemplate(customFields = []) {
  const cell = (v) => `"${v.replace(/"/g, '""')}"`;
  return [...CSV_COLS, ...customFields.map((f) => f.label)].map(cell).join(",");
}
