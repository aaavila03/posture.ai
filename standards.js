// Internal standards loaded from files. Each file can be JSON, CSV or plain text, and the
// standards from all loaded files form one list for the Internal standard dropdown.
import { parseCsv } from "./people.js";

export const MAX_STANDARDS = 500;
const MAX_LENGTH = 200;
const NAME_HEADINGS = ["standard", "name", "title", "internal standard"];

const clean = (v) => String(v ?? "").replace(/\s+/g, " ").trim().slice(0, MAX_LENGTH);

// Reads the names out of one file. Returns { standards, errors }.
export function parseStandardsFile(fileName, text) {
  const body = String(text ?? "").replace(/^﻿/, "");
  const lower = String(fileName || "").toLowerCase();
  let names = [];
  try {
    if (lower.endsWith(".json") || body.trimStart().startsWith("[") || body.trimStart().startsWith("{")) {
      names = fromJson(JSON.parse(body));
    } else if (lower.endsWith(".csv")) {
      names = fromCsv(body);
    } else {
      names = body.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#"));
    }
  } catch (err) {
    return { standards: [], errors: [`${fileName}: ${err.message}`] };
  }
  const standards = mergeStandards([], names);
  if (!standards.length) return { standards, errors: [`${fileName}: no standards found`] };
  return { standards, errors: [] };
}

function fromJson(data) {
  const list = Array.isArray(data) ? data : Array.isArray(data?.standards) ? data.standards : null;
  if (!list) throw new Error("expected a list of standards");
  return list.map((item) => (typeof item === "string" ? item : item?.name ?? item?.title ?? item?.standard ?? ""));
}

function fromCsv(body) {
  const rows = parseCsv(body);
  if (!rows.length) return [];
  const head = rows[0].map((h) => h.trim().toLowerCase());
  const col = head.findIndex((h) => NAME_HEADINGS.includes(h));
  const index = col >= 0 ? col : 0;
  const dataRows = col >= 0 ? rows.slice(1) : rows;
  return dataRows.map((cells) => cells[index] ?? "");
}

// Adds names to a list, dropping blanks and repeats (ignoring case). Keeps the order of the first file.
export function mergeStandards(current, incoming) {
  const seen = new Set();
  const out = [];
  for (const raw of [...(current || []), ...(incoming || [])]) {
    const name = clean(raw);
    const key = name.toLowerCase();
    if (!name || seen.has(key)) continue;
    seen.add(key);
    out.push(name);
    if (out.length >= MAX_STANDARDS) break;
  }
  return out;
}

// Checks a list read from storage. Anything that isn't a short text name is dropped.
export function cleanStandards(list) {
  return mergeStandards([], Array.isArray(list) ? list.filter((s) => typeof s === "string") : []);
}

// The standards loaded in this workspace, so the AI reviews on every tab can use them.
let active = [];
export function setActiveStandards(list) {
  active = cleanStandards(list);
}

// Text added to an AI review prompt so the model can refer to the company's standards.
// Empty when no standards are loaded.
export function standardsPromptText() {
  if (!active.length) return "";
  return `\n\nOur internal standards (name the ones that apply when you review, and do not invent others):\n${active.map((s) => `- ${s}`).join("\n")}`;
}
