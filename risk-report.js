// The risk report printed to PDF from the Risk Ledger editor.
// A print-ready report (printed with the browser's "Save as PDF"), styled like the vendor and
// Posture Snapshot reports (the .pr-* classes in styles.css). Blank sections are left out.
// The scoring helpers come from app.js so the report always agrees with the editor.
import { LIKELIHOOD, IMPACT, shownCriticality } from "./risk-csv.js";
import { appetiteCheck } from "./appetite.js";

// The treatment plan text as the report shows it. Lines the AI added, like "- [Protect/High] Patch the VPN",
// become a Function / Priority / Control table; any other lines become a list.
export function treatmentPlanHtml(text, esc) {
  const lines = String(text || "").split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  if (!lines.length) return "";
  const controls = [], notes = [];
  for (const line of lines) {
    const m = line.match(/^[-*•]?\s*\[([^\]/]+)\/([^\]]+)\]\s*(.+)$/);
    if (m) controls.push({ fn: m[1].trim(), priority: m[2].trim(), control: m[3].trim() });
    else notes.push(line.replace(/^([-*•]|\d+[.)])\s+/, ""));
  }
  const priority = (p) => `<span class="pr-badge ${{ High: "high", Medium: "medium", Low: "low" }[p] || "neutral"}">${esc(p)}</span>`;
  const list = notes.length === 1 && lines.length === 1 && !/^([-*•]|\d+[.)])\s/.test(lines[0])
    ? `<p>${esc(notes[0])}</p>`
    : notes.length ? `<ul>${notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>` : "";
  const table = controls.length
    ? `<table class="pr-table"><thead><tr><th class="pr-narrow">Function</th><th class="pr-narrow">Priority</th><th>Control</th></tr></thead>
        <tbody>${controls.map((c) => `<tr><td>${esc(c.fn)}</td><td>${priority(c.priority)}</td><td>${esc(c.control)}</td></tr>`).join("")}</tbody></table>`
    : "";
  return list + table;
}

// The AI risk assessment, shared by the PDF report and the editor's assessment panel. It leaves out what the
// record already says: scores, category and treatment appear only where the AI differs, and recommended
// controls only if they aren't already in the treatment plan.
export function riskAssessmentHtml(ai, r, { esc, helpers }) {
  const { rating, riskLevel, level } = helpers;
  const same = (a, b) => Number(a) === Number(b);
  const resL = r.residualLikelihood || r.likelihood, resI = r.residualImpact || r.impact;
  const scoresDiffer = !same(ai.likelihood, r.likelihood) || !same(ai.impact, r.impact) || !same(ai.residual_likelihood, resL) || !same(ai.residual_impact, resI);
  const suggest = [];
  if (ai.category && ai.category !== r.category) suggest.push(`category <strong>${esc(ai.category)}</strong>`);
  if (ai.treatment && ai.treatment !== r.treatment) suggest.push(`treatment <strong>${esc(ai.treatment)}</strong>`);
  const badge = (sc) => `<span class="pr-badge ${rating(sc).cls}">${esc(riskLevel(sc))}</span>`;
  const inh = ai.likelihood * ai.impact, res = ai.residual_likelihood * ai.residual_impact;
  const have = String(r.controls || "").toLowerCase();
  const controls = (ai.recommended_controls || []).filter((c) => !have.includes(String(c.control || "").toLowerCase()));
  const priority = (p) => `<span class="pr-badge ${{ High: "high", Medium: "medium", Low: "low" }[p] || "neutral"}">${esc(p)}</span>`;
  return `
      <div class="pr-callout"><p>${esc(ai.rationale || "")}</p>${suggest.length ? `<p>The AI suggests ${suggest.join(" and ")}.</p>` : ""}</div>
      ${scoresDiffer ? `<h3>AI-suggested scores</h3><table class="pr-table"><thead><tr><th></th><th>Likelihood</th><th>Impact</th><th class="pr-narrow">Score</th><th class="pr-narrow">Level</th></tr></thead><tbody>
        <tr><td><strong>Inherent</strong></td><td>${esc(level(LIKELIHOOD, ai.likelihood))}</td><td>${esc(level(IMPACT, ai.impact))}</td><td>${inh}</td><td>${badge(inh)}</td></tr>
        <tr><td><strong>Residual</strong></td><td>${esc(level(LIKELIHOOD, ai.residual_likelihood))}</td><td>${esc(level(IMPACT, ai.residual_impact))}</td><td>${res}</td><td>${badge(res)}</td></tr></tbody></table>` : ""}
      ${ai.threat_scenarios?.length ? `<h3>Threat scenarios</h3><ul>${ai.threat_scenarios.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : ""}
      ${controls.length ? `<h3>Recommended controls</h3><table class="pr-table"><thead><tr><th class="pr-narrow">Function</th><th class="pr-narrow">Priority</th><th>Control</th></tr></thead>
        <tbody>${controls.map((c) => `<tr><td>${esc(c.csf_function)}</td><td>${priority(c.priority)}</td><td>${esc(c.control)}</td></tr>`).join("")}</tbody></table>`
        : (ai.recommended_controls?.length ? `<p class="pr-muted">All recommended controls are already in the treatment plan.</p>` : "")}`;
}

export function riskReportHtml(r, { esc, org = "", logo = "", id = "", sections = [], helpers, appetite = null, generated = new Date() }) {
  const { inherent, residual, rating, riskLevel, level, stageLabel, slippage } = helpers;
  const has = (x) => (Array.isArray(x) ? x.length > 0 : typeof x === "string" ? x.trim() !== "" : x != null);
  const dash = '<span class="pr-muted">–</span>';
  const cell = (t) => esc(t || "").replace(/\n/g, "<br>");
  const para = (t) => esc(t).split(/\n{2,}/).map((p) => `<p>${p.replace(/\n/g, "<br>")}</p>`).join("");
  const date = (d) => (/^\d{4}-\d{2}-\d{2}/.test(d || "") ? new Date(`${d.slice(0, 10)}T00:00:00`).toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }) : esc(d || ""));
  const sec = (title, inner, extra = "") => (inner ? `<section class="pr-section ${extra}"><h2>${esc(title)}</h2>${inner}</section>` : "");
  const rows = (pairs) => pairs.filter(([, val]) => has(val)).map(([label, val]) => `<tr><th>${label}</th><td>${val}</td></tr>`).join("");
  const table = (pairs) => { const body = rows(pairs); return body ? `<table class="pr-table pr-summary"><tbody>${body}</tbody></table>` : ""; };
  const badge = (s) => `<span class="pr-badge ${rating(s).cls}">${esc(riskLevel(s))}</span>`;

  const inh = inherent(r), res = residual(r);
  // Where the risk stands against the workspace's risk appetite, when one is set.
  const ap = appetite ? appetiteCheck(appetite, { category: r.category, residualLevel: rating(res).label, status: r.status }) : null;
  const rl = r.residualLikelihood || r.likelihood, ri = r.residualImpact || r.impact;
  const sl = slippage(r);
  const list = (a) => (Array.isArray(a) ? a.join(", ") : a);

  const custom = sections.map((sc) => {
    const filled = sc.fields.filter((f) => has(r.custom?.[f.id]));
    return filled.length ? sec(sc.name, table(filled.map((f) => [esc(f.label), cell(r.custom[f.id])]))) : "";
  }).join("");

  const comments = (r.comments || []).length
    ? `<table class="pr-table"><thead><tr><th class="pr-narrow">When</th><th class="pr-narrow">By</th><th>Comment</th></tr></thead><tbody>${r.comments.map((c) => `<tr><td>${esc(new Date(c.at).toLocaleString())}</td><td>${esc(c.by || "")}</td><td>${cell(c.text)}</td></tr>`).join("")}</tbody></table>`
    : "";

  const pair = (by, on) => [by, on];
  return `<article class="pr-doc pr-risk">
    <header class="pr-cover">
      <div class="pr-cover-top"><span class="pr-brand">${logo}<span>${esc(org || "Posture.ai")}</span></span><span>Risk Report · ${esc(id)}</span></div>
      <div class="pr-eyebrow">Risk Report</div>
      <h1>${esc(r.title || "Untitled risk")}</h1>
      <div class="pr-cover-meta">${[r.category, stageLabel(r)].filter(Boolean).map(esc).join(" · ")}</div>
      <div class="pr-verdict">
        <div class="pr-verdict-item"><small>Inherent risk</small>${badge(inh)}</div>
        <div class="pr-verdict-item"><small>Residual risk</small>${badge(res)}</div>
        <div class="pr-verdict-item"><small>Treatment</small><strong>${esc(r.treatment || "Not set")}</strong></div>
        <div class="pr-verdict-item"><small>Treatment due</small><strong>${r.due ? date(r.due) : "Not set"}</strong></div>
      </div>
    </header>

    <section class="pr-section pr-exec">
      <h2>Risk summary</h2>
      <table class="pr-table pr-summary"><tbody>
        ${rows([["Risk ID", esc(id)], ["Title / vulnerability", esc(r.title)], ["Category", esc(r.category)], ["Risk group", esc(r.riskGroup)], ["Stage", esc(stageLabel(r))],
          ["Asset / system", esc(r.asset)], ["Asset criticality", esc(shownCriticality(r.assetCriticality))], ["Threat type", esc(r.threatType)], ["Threat", esc(r.threatSource)],
          ["Data protection impact", esc(list(r.dataImpact) || "")], ["Business impact", esc(list(r.businessImpact) || "")],
          ["Ticket / project #", esc(r.ticket)], ["Vulnerability ref / CVE", esc(r.vulnRef)], ["Control", esc(r.internalStandard)], ["NIST CSF controls", esc(r.nistControls)],
          ["Inherent risk", `${badge(inh)} Score ${inh} of 25`], ["Residual risk", `${badge(res)} Score ${res} of 25`],
          ["Risk appetite", ap ? `<span class="pr-badge ${ap.outside ? "high" : "low"}">${ap.outside ? "Outside appetite" : "Within appetite"}</span> Limit: ${esc(ap.limit)}` : ""],
          ["Treatment", esc(r.treatment)], ["Treatment due date", r.due ? date(r.due) : ""], ["Slippage", sl ? `<span class="pr-badge ${sl.cls}">${esc(sl.short || sl.label)}</span>${sl.note ? ` ${esc(sl.note)}` : ""}` : ""],
          ["Risk owner", esc(r.owner)]])}
      </tbody></table>
    </section>

    ${sec("Risk description", `${has(r.description) ? `<h3>Threat description</h3>${para(r.description)}` : ""}${has(r.memo) ? `<h3>Background memo</h3>${para(r.memo)}` : ""}`)}

    ${sec("Assessment", `<table class="pr-table"><thead><tr><th></th><th>Likelihood</th><th>Impact</th><th class="pr-narrow">Score</th><th class="pr-narrow">Level</th></tr></thead><tbody>
      <tr><td><strong>Inherent</strong></td><td>${esc(level(LIKELIHOOD, r.likelihood))}</td><td>${esc(level(IMPACT, r.impact))}</td><td>${inh}</td><td>${badge(inh)}</td></tr>
      <tr><td><strong>Residual</strong></td><td>${esc(level(LIKELIHOOD, rl))}</td><td>${esc(level(IMPACT, ri))}</td><td>${res}</td><td>${badge(res)}</td></tr></tbody></table>
      <p class="pr-muted">Score is likelihood × impact, out of 25. Residual is the risk once the treatment is in place.</p>`)}

    ${r.aiAssessment ? sec(r.aiAssessment.offline ? "Risk assessment (rule-based)" : "AI risk assessment", riskAssessmentHtml(r.aiAssessment, r, { esc, helpers })) : ""}

    ${sec("Treatment", table([["Treatment", esc(r.treatment)], ["Estimated cost", esc(r.estimatedCost)],
      ["Remediation project", esc(r.remediationProject)], ["Estimated completion", date(r.treatmentCompletion)], ["Treatment due date", date(r.due)],
      ["Slippage", sl ? `<span class="pr-badge ${sl.cls}">${esc(sl.short || sl.label)}</span>${sl.note ? ` ${esc(sl.note)}` : ""}` : ""],
      ["Review frequency", esc(r.reviewFrequency)], ["Next review date", date(r.nextReview)],
      ["Exception logged", r.logException === "Yes" ? "Yes" : ""], ["Exception approved", esc(r.exceptionApproved)],
      ["Exception expires", r.logException === "Yes" ? date(r.exceptionExpiry) : ""]])
      + (has(r.controls) ? `<h3>Treatment plan / mitigating controls</h3>${treatmentPlanHtml(r.controls, esc)}` : ""))}

    ${sec("Ownership", table([["Risk owner", esc(r.owner)], ["Risk owner department", esc(r.ownerDepartment)], ["Asset owner", esc(r.assetOwner)], ["Risk delegate", esc(r.delegate)],
      ["BU director", esc(r.buDirector)], ["BU VP", esc(r.buVp)], ["Compliance analyst", esc(r.complianceAnalyst)], ["Risk analyst", esc(r.riskAnalyst)], ["GRC manager", esc(r.grcManager)]]))}

    ${sec("Workflow & governance", table([...[["Created", "createdBy", "createdDate"], ["Submitted", "submittedBy", "submittedDate"], ["Treatment provided", "treatmentBy", "treatmentDate"],
      ["Approved", "approvedBy", "approvedDate"], ["Completed", "completedBy", "completedDate"]].map(([label, by, on]) =>
        pair(label, [r[by] ? `by ${esc(r[by])}` : "", r[on] ? date(r[on]) : ""].filter(Boolean).join(" · "))),
      ["Oversight committee review", date(r.oversightReview)], ["Risk committee review", date(r.committeeReview)], ["Committee notes", cell(r.committeeNotes)]]))}
    ${custom}
    ${sec("Comment log", comments)}

    <footer class="pr-foot">${esc(org ? `${org} · ` : "")}Confidential · ${esc(id)} · Generated ${esc(generated.toLocaleDateString(undefined, { year: "numeric", month: "long", day: "numeric" }))} with Posture.ai</footer>
  </article>`;
}
