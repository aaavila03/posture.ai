// Due-date reminders for the dashboard: what is overdue, due this week and due this month.
// One row per risk or vendor, however many dates it has: a risk with a treatment date and a review date is a
// single row listing both, in the group of its earliest. Vendors with open follow-up questions say so on their row.
import { nextReview, openFollowups } from "./vendors.js";

export const REMINDER_DAYS = 30;
const WEEK = 7;
const DAY = 86_400_000;

// Whole days from `today` to `date` (both YYYY-MM-DD); negative once the date has passed.
export const daysUntil = (date, today) => Math.round((Date.parse(`${date}T00:00:00Z`) - Date.parse(`${today}T00:00:00Z`)) / DAY);

const bucketOf = (days) => (days < 0 ? "overdue" : days <= WEEK ? "week" : "month");

// "29 days overdue", "due today", "in 5 days".
export function whenText(days) {
  if (days == null) return "";
  if (days < 0) return `${-days} day${days === -1 ? "" : "s"} overdue`;
  if (days === 0) return "due today";
  return `in ${days} day${days === 1 ? "" : "s"}`;
}

// risks and vendors are the lists the person can see; `today` is YYYY-MM-DD.
export function buildReminders({ risks = [], vendors = [], today, windowDays = REMINDER_DAYS }) {
  const rows = [];
  const within = (days) => days != null && days <= windowDays;

  for (const r of risks) {
    if (r.status === "Closed") continue;
    const reasons = [];
    // An accepted risk has no treatment to finish, but it is still reviewed.
    if (r.due && r.status !== "Accepted") reasons.push({ text: "Treatment due", date: r.due, days: daysUntil(r.due, today) });
    if (r.nextReview) reasons.push({ text: "Review due", date: r.nextReview, days: daysUntil(r.nextReview, today) });
    const due = reasons.filter((x) => within(x.days)).sort((a, b) => a.days - b.days);
    if (due.length) rows.push({ record: "risk", id: r.id, title: r.title || "Untitled risk", reasons: due, days: due[0].days, bucket: bucketOf(due[0].days) });
  }

  for (const v of vendors) {
    if (v.status === "Offboarded") continue;
    const reasons = [];
    const date = nextReview(v);
    if (date) {
      const days = daysUntil(date, today);
      if (within(days)) reasons.push({ text: "Review due", date, days });
    } else {
      // Never assessed counts as overdue, as it does in the Vendor reviews due tile.
      reasons.push({ text: "No review on record", date: null, days: null });
    }
    const open = openFollowups(v.intake);
    if (open) reasons.push({ text: `${open} open follow-up${open === 1 ? "" : "s"}`, date: null, days: null, followup: true });
    if (!reasons.length) continue;
    const dated = reasons.filter((x) => x.days != null);
    const never = reasons.some((x) => x.text === "No review on record");
    const days = dated.length ? Math.min(...dated.map((x) => x.days)) : null;
    // Never assessed is overdue; follow-ups alone are waiting on the vendor.
    const bucket = never ? "overdue" : days != null ? bucketOf(days) : "waiting";
    rows.push({ record: "vendor", id: v.id, title: v.name || "Unnamed vendor", reasons, days, bucket });
  }

  const order = (a, b) => (a.days ?? -Infinity) - (b.days ?? -Infinity) || a.title.localeCompare(b.title);
  const groups = { overdue: [], week: [], month: [], waiting: [] };
  for (const row of rows.sort(order)) groups[row.bucket].push(row);
  return { ...groups, total: rows.length, urgent: groups.overdue.length + groups.week.length };
}
