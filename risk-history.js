// A risk's change history (hosted mode): who changed it and when, with the old and new value of its key fields.
// The rows come from the database's risk_history function, which reads the audit log for that risk.

// The key fields the audit log records values for, and what they are called in the editor. Keep in step with
// key_fields in the risk_history migration.
export const HISTORY_FIELDS = {
  title: "Title", status: "Stage", category: "Category", owner: "Owner", likelihood: "Likelihood", impact: "Impact",
  residualLikelihood: "Residual likelihood", residualImpact: "Residual impact", treatment: "Treatment", due: "Treatment due",
  nextReview: "Next review", logException: "Exception logged", exceptionApproved: "Exception approved", exceptionExpiry: "Exception expires",
};

const shown = (value, esc) => (value ? `“${esc(value)}”` : "<em>blank</em>");

// One history row as a line: what happened and, for an update, each key field that changed.
export function historyEntryHtml(row, { esc, when = (at) => new Date(at).toLocaleString() }) {
  const who = row.actor_email ? esc(row.actor_email) : "system";
  const head = `<div class="small muted">${esc(when(row.at))} · ${who}</div>`;
  if (row.action === "insert") return `<li>${head}Created the risk</li>`;
  const fields = Object.entries(row.changes || {}).filter(([k]) => HISTORY_FIELDS[k]);
  if (!fields.length) return `<li>${head}Changed other details</li>`;
  return `<li>${head}<ul class="history-changes">${fields.map(([k, v]) =>
    `<li><strong>${esc(HISTORY_FIELDS[k])}</strong>: ${shown(v?.from, esc)} → ${shown(v?.to, esc)}</li>`).join("")}</ul></li>`;
}

export const historyHtml = (rows, opts) => (rows?.length ? rows.map((r) => historyEntryHtml(r, opts)).join("") : '<li class="muted small">No history yet.</li>');
