// People directory: the organisation's hierarchy, imported from a CSV or Excel file.
// Owner fields on risks and vendors are picked from it (plus the workspace's members),
// and choosing a risk owner fills in their department, BU director and BU VP.
import { xlsxToCsv } from "./xlsx.js";
import { formatPhone } from "./phone.js";

export const MAX_PEOPLE = 5000;
export const TEMPLATE_CSV = "First name,Last name,Email,Title,Department,Phone,Manager email\n"
  + "Jordan,Rivera,jordan.rivera@example.com,VP Technology,Technology,,\n"
  + "Sam,Lee,sam.lee@example.com,Director IT Infrastructure,IT Infrastructure,,jordan.rivera@example.com\n"
  + "Alex,Kim,alex.kim@example.com,Network Engineer,IT Infrastructure,(555) 010-2000,sam.lee@example.com\n";

// Accepted column headings (lower-case, spaces and punctuation ignored) for each field.
const HEADINGS = {
  first_name: ["firstname", "givenname", "first"],
  last_name: ["lastname", "surname", "familyname", "last"],
  name: ["name", "fullname", "displayname", "employeename", "employee"],
  email: ["email", "emailaddress", "workemail", "mail", "businessemail"],
  title: ["title", "jobtitle", "position", "role"],
  department: ["department", "dept", "businessunit", "team", "division"],
  phone: ["phone", "phonenumber", "workphone", "mobile", "telephone", "businessphone"],
  manager: ["manageremail", "manager", "reportsto", "supervisor", "supervisoremail", "managername", "reportstoemail", "linemanager"],
};
const key = (h) => h.toLowerCase().replace(/[^a-z]/g, "");
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const PHONE = /^[0-9+()./ x-]{0,40}$/;

export const fullName = (p) => [p?.first_name, p?.last_name].filter(Boolean).join(" ");

// Splits CSV text into rows of cells (quotes, doubled quotes and line breaks in quotes handled).
export function parseCsv(text) {
  const rows = [];
  let row = [], cell = "", quoted = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cell += '"'; i++; }
      else if (ch === '"') quoted = false;
      else cell += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ",") { row.push(cell); cell = ""; }
    else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(cell); rows.push(row); row = []; cell = "";
    } else cell += ch;
  }
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.filter((r) => r.some((c) => c.trim()));
}

// Turns rows (the first is the heading row) into people. Returns { people, errors }.
export function rowsToPeople(rows) {
  const errors = [];
  const head = (rows[0] || []).map(key);
  const col = {};
  for (const [field, names] of Object.entries(HEADINGS)) {
    const i = head.findIndex((h) => names.includes(h));
    if (i >= 0) col[field] = i;
  }
  if (col.email == null) return { people: [], errors: ["The file needs an Email column (see the template)."] };
  if (col.first_name == null && col.last_name == null && col.name == null) {
    return { people: [], errors: ["The file needs First name and Last name columns, or a Name column."] };
  }
  const cell = (r, f) => (col[f] == null ? "" : String(r[col[f]] ?? "").trim());
  const byEmail = new Map();
  rows.slice(1).forEach((r, n) => {
    const line = n + 2;
    const email = cell(r, "email").toLowerCase();
    let first = cell(r, "first_name"), last = cell(r, "last_name");
    if (!first && !last && cell(r, "name")) {
      const name = cell(r, "name");
      // "Last, First" or "First Last".
      [first, last] = name.includes(",") ? name.split(",").map((s) => s.trim()).reverse() : [name.split(" ")[0], name.split(" ").slice(1).join(" ")];
    }
    if (!email && !first && !last) return;
    if (!EMAIL.test(email)) return errors.push(`Row ${line}: missing or invalid email`);
    if (!first && !last) return errors.push(`Row ${line}: missing name`);
    let phone = formatPhone(cell(r, "phone"));
    if (!PHONE.test(phone)) { errors.push(`Row ${line}: phone "${phone}" ignored (digits, spaces and + ( ) . / - x only)`); phone = ""; }
    byEmail.set(email, {
      email, first_name: first.slice(0, 80), last_name: last.slice(0, 80), title: cell(r, "title").slice(0, 120),
      department: cell(r, "department").slice(0, 120), phone, manager_email: cell(r, "manager"),
    });
  });
  const people = [...byEmail.values()];
  // The manager column may hold an email or a name.
  const byName = new Map(people.map((p) => [fullName(p).toLowerCase(), p.email]));
  for (const p of people) {
    const m = p.manager_email.trim();
    p.manager_email = !m ? "" : EMAIL.test(m) ? m.toLowerCase()
      : byName.get(m.toLowerCase()) || byName.get(m.split(",").map((s) => s.trim()).reverse().join(" ").toLowerCase()) || "";
    if (m && !p.manager_email) errors.push(`${fullName(p)}: manager "${m}" isn't in the file`);
    if (p.manager_email === p.email) p.manager_email = "";
  }
  if (people.length > MAX_PEOPLE) return { people: [], errors: [`The file has ${people.length} people; the limit is ${MAX_PEOPLE}.`] };
  return { people, errors };
}

export async function readPeopleFile(file) {
  const excel = /\.xlsx$/i.test(file.name);
  if (!excel && !/\.(csv|txt)$/i.test(file.name)) throw new Error("choose a .csv or .xlsx file");
  let text = excel ? await xlsxToCsv(file) : await file.text();
  // Excel: the first sheet only.
  if (excel) text = text.split(/\n# Sheet: /)[0].replace(/^# Sheet: .*\n/, "");
  return rowsToPeople(parseCsv(text.replace(/^﻿/, "")));
}

// Lookups over the directory: by name (what owner fields store), by email, and up the manager chain.
export function directory(list) {
  const byEmail = new Map(list.map((p) => [p.email, p]));
  const byName = new Map();
  for (const p of list) if (fullName(p) && !byName.has(fullName(p).toLowerCase())) byName.set(fullName(p).toLowerCase(), p);
  const managers = (p) => {
    const out = [];
    const seen = new Set([p.email]);
    for (let m = byEmail.get(p.manager_email); m && !seen.has(m.email) && out.length < 25; m = byEmail.get(m.manager_email)) {
      seen.add(m.email);
      out.push(m);
    }
    return out;
  };
  return {
    list,
    names: [...byName.values()].map(fullName).sort((a, b) => a.localeCompare(b)),
    find: (name) => byName.get(String(name || "").trim().toLowerCase()),
    manager: (p) => byEmail.get(p?.manager_email),
    managers,
    // The nearest manager whose title matches (e.g. the BU director above a risk owner).
    leader: (p, pattern) => managers(p).find((m) => pattern.test(m.title || "")),
  };
}

// True when making mgr the manager of the person (now email, previously prev) would create a loop.
export function wouldLoop(list, email, prev, mgr) {
  if (!mgr) return false;
  const me = new Set([email, prev].filter(Boolean));
  const byEmail = new Map(list.map((p) => [p.email, p]));
  for (let m = mgr, n = 0; m && n < 100; m = byEmail.get(m)?.manager_email, n++) if (me.has(m)) return true;
  return false;
}

export const EMAIL_PATTERN = EMAIL;
export const PHONE_PATTERN = PHONE;

export const DIRECTOR = /\bdirector\b/i;
export const VP = /\b(s?e?vp|vice[- ]president)\b/i;

// Owner fields become a pick list of people once there's anyone to pick; until then they stay
// free text. A saved value that isn't in the list stays selectable so nothing is lost.
export function setOwnerField(form, name, names, value) {
  let el = form.elements[name];
  if (!el) return;
  const want = names.length ? "SELECT" : "INPUT";
  if (el.tagName !== want) {
    const next = document.createElement(want.toLowerCase());
    next.name = name;
    if (el.id) next.id = el.id;
    if (want === "INPUT") next.maxLength = 200;
    el.replaceWith(next);
    el = next;
  }
  if (want === "SELECT") {
    const opts = [["", "–"], ...names.map((n) => [n, n])];
    if (value && !names.includes(value)) opts.push([value, `${value} (not in directory)`]);
    el.replaceChildren(...opts.map(([v, label]) => new Option(label, v)));
  }
  el.value = value ?? "";
}
