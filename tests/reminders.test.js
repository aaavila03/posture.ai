// Due-date reminders on the dashboard: overdue, due this week and due this month.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReminders, daysUntil, whenText } from "../reminders.js";

const today = "2026-11-24";
// The default vendor here is Low risk, reviewed every 36 months, so 2020 is long overdue and 2026-10 is not due yet.
// A Critical vendor (regulated data, admin access) is reviewed every 6 months.
const vendor = (over = {}) => ({ id: "V-001", name: "Acme", status: "Active", criticality: "Medium", dataSensitivity: "Internal", access: "None", lastAssessed: "2025-01-01", ...over });

test("daysUntil counts whole days, negative once past", () => {
  assert.equal(daysUntil("2026-11-24", today), 0);
  assert.equal(daysUntil("2026-11-27", today), 3);
  assert.equal(daysUntil("2026-11-20", today), -4);
  assert.equal(daysUntil("2027-01-01", "2026-12-31"), 1);
});

test("whenText reads naturally", () => {
  assert.equal(whenText(-1), "1 day overdue");
  assert.equal(whenText(-29), "29 days overdue");
  assert.equal(whenText(0), "due today");
  assert.equal(whenText(1), "in 1 day");
  assert.equal(whenText(12), "in 12 days");
  assert.equal(whenText(null), "");
});

test("risks are grouped as overdue, this week or this month, and later ones are left out", () => {
  const r = buildReminders({ today, risks: [
    { id: "R-1", title: "Past", due: "2026-11-01", status: "In treatment" },
    { id: "R-2", title: "Today", due: "2026-11-24", status: "In treatment" },
    { id: "R-3", title: "Next week", due: "2026-12-01", status: "In treatment" },
    { id: "R-4", title: "In three weeks", due: "2026-12-15", status: "In treatment" },
    { id: "R-5", title: "Far away", due: "2027-03-01", status: "In treatment" },
  ] });
  assert.deepEqual(r.overdue.map((x) => x.id), ["R-1"]);
  assert.deepEqual(r.week.map((x) => x.id), ["R-2", "R-3"]);
  assert.deepEqual(r.month.map((x) => x.id), ["R-4"]);
  assert.equal(r.total, 4);
  assert.equal(r.urgent, 3);
});

test("a risk with two dates is one row, in the group of the earlier one, listing both", () => {
  const r = buildReminders({ today, risks: [{ id: "R-1", title: "Both", due: "2026-12-10", nextReview: "2026-11-30", status: "Monitoring" }] });
  assert.equal(r.total, 1);
  assert.equal(r.week.length, 1);
  assert.deepEqual(r.week[0].reasons.map((x) => x.text), ["Review due", "Treatment due"]);
  assert.equal(r.week[0].days, 6);
});

test("closed risks are skipped, and accepted risks are reviewed but have no treatment due", () => {
  const r = buildReminders({ today, risks: [
    { id: "R-1", title: "Closed", due: "2026-11-01", nextReview: "2026-11-01", status: "Closed" },
    { id: "R-2", title: "Accepted", due: "2026-11-01", nextReview: "2026-11-26", status: "Accepted" },
  ] });
  assert.deepEqual(r.overdue.map((x) => x.id), []);
  assert.deepEqual(r.week.map((x) => x.id), ["R-2"]);
  assert.deepEqual(r.week[0].reasons.map((x) => x.text), ["Review due"]);
});

test("vendors: review dates are grouped, offboarded ones are skipped, never assessed counts as overdue", () => {
  const r = buildReminders({ today, vendors: [
    vendor({ id: "V-1", name: "Overdue", lastAssessed: "2020-01-01" }),
    vendor({ id: "V-2", name: "Soon", criticality: "Critical", dataSensitivity: "Regulated (PII/PHI/PCI)", access: "Privileged / admin", lastAssessed: "2026-05-28" }),
    vendor({ id: "V-3", name: "Never", lastAssessed: "" }),
    vendor({ id: "V-4", name: "Gone", status: "Offboarded", lastAssessed: "" }),
    vendor({ id: "V-5", name: "Later", lastAssessed: "2026-10-01" }),
  ] });
  assert.deepEqual(r.overdue.map((x) => x.id).sort(), ["V-1", "V-3"]);
  assert.deepEqual(r.week.map((x) => x.id), ["V-2"]);
  assert.equal(r.overdue.find((x) => x.id === "V-3").reasons[0].text, "No review on record");
  assert.ok(![...r.overdue, ...r.week, ...r.month, ...r.waiting].some((x) => x.id === "V-4" || x.id === "V-5"));
});

test("open vendor follow-ups are noted on the vendor and wait on the vendor when nothing else is due", () => {
  const followups = { q1: { status: "open" }, q2: { status: "open" }, q3: { status: "resolved" } };
  const r = buildReminders({ today, vendors: [
    vendor({ id: "V-1", name: "Waiting", lastAssessed: "2026-10-01", intake: { followups } }),
    vendor({ id: "V-2", name: "Both", lastAssessed: "2020-01-01", intake: { followups: { q: { status: "open" } } } }),
  ] });
  assert.deepEqual(r.waiting.map((x) => x.id), ["V-1"]);
  assert.deepEqual(r.waiting[0].reasons.map((x) => x.text), ["2 open follow-ups"]);
  // One row for a vendor that is both overdue and waiting, not two.
  assert.equal(r.overdue.filter((x) => x.id === "V-2").length, 1);
  assert.deepEqual(r.overdue.find((x) => x.id === "V-2").reasons.map((x) => x.text), ["Review due", "1 open follow-up"]);
});

test("nothing due gives empty groups", () => {
  const r = buildReminders({ today, risks: [], vendors: [] });
  assert.deepEqual([r.overdue, r.week, r.month, r.waiting, r.total, r.urgent], [[], [], [], [], 0, 0]);
});
