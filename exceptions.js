// Risk exceptions as a process (hosted mode): an analyst or above requests an exception, an approver or above who did not
// make the request approves or rejects it, and a renewal is another request. The database enforces every rule (see the
// exception approvals migration); the checks here are for clear messages and for what to show.

export const ROLE_RANK = { viewer: 1, analyst: 2, approver: 3, admin: 4, owner: 5 };
export const EXCEPTION_MAX_DAYS = 730;
const rank = (role) => ROLE_RANK[role] || 0;

export const canRequest = (role) => rank(role) >= ROLE_RANK.analyst;
export const canDecide = (role) => rank(role) >= ROLE_RANK.approver;
export const canRevoke = canDecide;

// Why a request can't be sent, or "". `today` is "YYYY-MM-DD".
export function requestProblem({ reason, expiry }, today) {
  if (!String(reason || "").trim()) return "Give a reason for the exception.";
  if (!/^\d{4}-\d{2}-\d{2}$/.test(expiry || "")) return "Choose when the exception ends.";
  if (expiry <= today) return "The end date must be in the future.";
  const limit = new Date(`${today}T00:00:00Z`);
  limit.setUTCDate(limit.getUTCDate() + EXCEPTION_MAX_DAYS);
  if (expiry > limit.toISOString().slice(0, 10)) return "An exception can last at most two years.";
  return "";
}

// Whether a pending request can be decided by this person, and why not if it can't.
export function decideProblem(request, { role, userId }) {
  if (!canDecide(role)) return "Only approvers, admins and owners can decide a request.";
  if (request.requested_by === userId) return "Someone else must decide a request you made.";
  return "";
}
export const canWithdraw = (request, { role, userId }) => request.status === "requested" && canRequest(role) && (request.requested_by === userId || rank(role) >= ROLE_RANK.admin);

// Where a risk's exception stands, from the fields the database keeps on the risk. `today` is "YYYY-MM-DD".
export function exceptionState(risk, today) {
  const approved = risk.exceptionApproved === "Yes";
  const expired = approved && risk.exceptionExpiry && risk.exceptionExpiry < today;
  const by = risk.exceptionApprovedBy ? ` by ${risk.exceptionApprovedBy}${risk.exceptionApprovedDate ? ` on ${risk.exceptionApprovedDate}` : ""}` : " (recorded before approvals were tracked)";
  if (risk.exceptionPending) {
    return { state: approved ? "renewal" : "requested", badge: "Awaiting approval", cls: "medium",
      text: `${approved ? "A renewal is" : "A request is"} waiting for approval (requested ${risk.exceptionPending}).${approved ? ` The current approval ${expired ? "ended" : "runs until"} ${risk.exceptionExpiry || "no date"}.` : ""}` };
  }
  if (expired) return { state: "expired", badge: "Expired", cls: "high", text: `Approved${by}, and it ended on ${risk.exceptionExpiry}. Request a renewal.` };
  if (approved) return { state: "approved", badge: "Approved", cls: "low", text: `Approved${by}${risk.exceptionExpiry ? `, until ${risk.exceptionExpiry}` : ", with no end date"}.` };
  if (risk.exceptionApproved === "No") return { state: "rejected", badge: "Not approved", cls: "high", text: "The exception is not approved." };
  return { state: "none", badge: "", cls: "", text: risk.logException === "Yes" ? "An exception is logged but has not been requested for approval." : "No exception." };
}

// One request, as a list item.
export function requestHtml(r, { esc, date = (at) => String(at).slice(0, 10) }) {
  const decided = r.status === "requested" ? "Waiting for a decision"
    : `${{ approved: "Approved", rejected: "Rejected", withdrawn: "Withdrawn" }[r.status]} by ${esc(r.decided_by_email || "unknown")} on ${esc(date(r.decided_at))}`;
  return `<li><div class="small muted">${r.renewal ? "Renewal" : "Request"} by ${esc(r.requested_by_email)} on ${esc(date(r.requested_at))} · until ${esc(r.proposed_expiry)}</div>
      <div>${esc(r.reason)}</div><div class="small muted">${decided}${r.decision_note ? `: ${esc(r.decision_note)}` : ""}</div></li>`;
}
export const requestsHtml = (rows, opts) => (rows?.length ? rows.map((r) => requestHtml(r, opts)).join("") : '<li class="muted small">No requests yet.</li>');

// The exception panel in the risk editor (hosted mode). `api` has list(risk), request(risk, { reason, expiry }),
// decide(id, approve, note), withdraw(id) and revoke(risk, note); `onChanged(risk)` runs after any of them, so the app
// can reload the risk the database has just changed. Returns { show(risk, after) }.
export function initExceptionPanel({ $, esc, api, getRole, getUserId, today, toast, onChanged }) {
  const panel = $("#risk-exception-panel");
  let current = null;   // { id, risk }
  let requests = [];
  let formOpen = false;

  const render = () => {
    const { risk } = current;
    const role = getRole(), userId = getUserId();
    const state = exceptionState(risk, today());
    const pending = requests.find((r) => r.status === "requested");
    const approved = risk.exceptionApproved === "Yes";
    const parts = [`<div class="exception-status">${state.badge ? `<span class="badge ${state.cls}">${esc(state.badge)}</span> ` : ""}<span>${esc(state.text)}</span></div>`];
    const actions = [];
    if (pending) {
      if (canWithdraw(pending, { role, userId })) actions.push('<button type="button" class="small" data-exc="withdraw">Withdraw request</button>');
      if (canDecide(role)) {
        const why = decideProblem(pending, { role, userId });
        parts.push(`<div class="exception-decide"><label class="small">Note <span class="muted">(needed to reject)</span><input data-exc-note maxlength="2000" /></label>
          <button type="button" class="small primary" data-exc="approve" ${why ? "disabled" : ""}>Approve</button>
          <button type="button" class="small danger" data-exc="reject" ${why ? "disabled" : ""}>Reject</button>${why ? `<div class="small muted exception-note">${esc(why)}</div>` : ""}</div>`);
      }
    } else if (canRequest(role)) {
      actions.push(`<button type="button" class="small" data-exc="open-form">${approved ? "Request renewal" : "Request exception"}</button>`);
    }
    if (approved && canRevoke(role) && !pending) actions.push('<button type="button" class="small danger" data-exc="revoke">Revoke…</button>');
    if (actions.length) parts.push(`<div class="exception-actions">${actions.join(" ")}</div>`);
    if (formOpen && !pending) {
      parts.push(`<div class="exception-form"><label class="small">Reason <textarea data-exc-reason rows="2" maxlength="2000"></textarea></label>
        <label class="small">Ends on <input type="date" data-exc-expiry /></label>
        <button type="button" class="small primary" data-exc="send">Send for approval</button> <button type="button" class="small" data-exc="cancel">Cancel</button></div>`);
    }
    parts.push(`<details class="exception-history"><summary class="small">Requests and decisions (${requests.length})</summary><ul class="comment-log">${requestsHtml(requests, { esc })}</ul></details>`);
    panel.innerHTML = parts.join("");
  };

  async function load(id, after) {
    try {
      await after;
      const rows = await api.list(id);
      if (current?.id !== id) return;
      requests = rows;
      render();
    } catch (err) {
      if (current?.id === id) panel.innerHTML = `<div class="small error-text">Couldn't load the exception: ${esc(err.message)}</div>`;
    }
  }

  // Shows the panel for a saved risk (or asks for a save first). `risk` is the saved record.
  function show(risk, after = null) {
    const wanted = !!api;
    panel.classList.toggle("hidden", !wanted);
    if (!wanted) return;
    formOpen = false;
    if (!risk?.id) {
      current = null;
      panel.innerHTML = '<div class="small muted">Save the risk first, then request an exception.</div>';
      return;
    }
    current = { id: risk.id, risk };
    requests = [];
    render();
    load(risk.id, after);
  }

  async function act(run, done) {
    const id = current.id;
    try {
      await run();
      toast(done);
      formOpen = false;
      const risk = (await onChanged(id)) || current.risk;
      if (current?.id === id) { current.risk = risk; requests = await api.list(id); render(); }
    } catch (err) {
      toast(err.message, true);
    }
  }

  panel.addEventListener("click", (e) => {
    const button = e.target.closest("[data-exc]");
    if (!button || !current) return;
    const what = button.dataset.exc, id = current.id;
    const pending = requests.find((r) => r.status === "requested");
    const note = panel.querySelector("[data-exc-note]")?.value.trim() || "";
    if (what === "open-form") { formOpen = true; render(); }
    else if (what === "cancel") { formOpen = false; render(); }
    else if (what === "send") {
      const reason = panel.querySelector("[data-exc-reason]").value, expiry = panel.querySelector("[data-exc-expiry]").value;
      const problem = requestProblem({ reason, expiry }, today());
      if (problem) return toast(problem, true);
      act(() => api.request(id, { reason: reason.trim(), expiry }), "Exception requested");
    } else if (what === "approve" && pending) act(() => api.decide(pending.id, true, note), "Exception approved");
    else if (what === "reject" && pending) {
      if (!note) return toast("Add a note saying why it is rejected.", true);
      act(() => api.decide(pending.id, false, note), "Exception rejected");
    } else if (what === "withdraw" && pending) {
      if (confirm("Withdraw this request?")) act(() => api.withdraw(pending.id), "Request withdrawn");
    } else if (what === "revoke") {
      const why = prompt("Why is this exception being revoked? It ends the approval now.");
      if (why && why.trim()) act(() => api.revoke(id, why.trim()), "Exception revoked");
    }
  });

  return { show };
}
