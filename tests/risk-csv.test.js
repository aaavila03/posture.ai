import { test } from "node:test";
import assert from "node:assert/strict";
import { riskRowsFromCsv, riskCsvTemplate, CSV_COLS } from "../risk-csv.js";

const custom = [{ id: "owner-field", label: "Governance: Owner name" }];

test("template has every export column plus the custom fields", () => {
  const header = riskCsvTemplate(custom);
  for (const c of CSV_COLS) assert.ok(header.includes(`"${c}"`), `missing ${c}`);
  assert.ok(header.endsWith('"Governance: Owner name"'));
});

test("an exported row imports back with its values", () => {
  const header = riskCsvTemplate(custom);
  // Written the way Export CSV writes it: levels as "3. Possible", stage as "2. Assessment",
  // and a title that starts with = is quoted with an apostrophe.
  const cells = { title: "'=HYPERLINK(x)", likelihood: "3. Possible", impact: "4. High",
    status: "2. Assessment", due: "2026-12-01", reviewFrequency: "Quarterly", nistControls: "AC-2; AC-3",
    inherentScore: "12", inherentLevel: "2. Medium", "Governance: Owner name": "Priya Raman" };
  const head = header.split(",").map((h) => h.replace(/^"|"$/g, ""));
  const row = head.map((h) => `"${(cells[h] ?? "").replace(/"/g, '""')}"`).join(",");
  const { risks, errors } = riskRowsFromCsv(`${header}\n${row}\n`, custom);
  assert.deepEqual(errors, []);
  assert.equal(risks.length, 1);
  const r = risks[0];
  assert.equal(r.title, "=HYPERLINK(x)");
  assert.equal(r.likelihood, 3);
  assert.equal(r.impact, 4);
  assert.equal(r.status, "Assessment");
  assert.equal(r.due, "2026-12-01");
  assert.equal(r.reviewFrequency, "Quarterly");
  assert.equal(r.nistControls, "AC-2; AC-3");
  assert.deepEqual(r.custom, { "owner-field": "Priya Raman" });
  assert.equal(r.inherentScore, undefined, "computed columns are ignored");
});

test("bad rows are skipped with the row number, and good rows still import", () => {
  const csv = [
    "title,likelihood,status,due",
    "Good risk,2,Identified,",
    ",3,Identified,",
    "Bad level,9,Identified,",
    "Bad stage,2,Nearly done,",
    "Bad date,2,Identified,12/01/2026",
  ].join("\n");
  const { risks, errors } = riskRowsFromCsv(csv);
  assert.deepEqual(risks.map((r) => r.title), ["Good risk"]);
  assert.equal(errors.length, 4);
  assert.match(errors[0], /^Row 3: title is required/);
  assert.match(errors[1], /^Row 4: likelihood must be 1–5/);
  assert.match(errors[2], /^Row 5: status must be one of/);
  assert.match(errors[3], /^Row 6: due must be a date/);
});

test("an empty level is allowed and the dash the export writes is treated as empty", () => {
  const { risks, errors } = riskRowsFromCsv("title,likelihood,impact\nNo scores,–,\n");
  assert.deepEqual(errors, []);
  assert.equal(risks[0].likelihood, undefined);
  assert.equal(risks[0].impact, undefined);
});

test("a file without a title column is refused", () => {
  const { risks, errors } = riskRowsFromCsv("name,owner\nThing,Someone\n");
  assert.deepEqual(risks, []);
  assert.match(errors[0], /needs a title column/);
});

test("a byte order mark at the start of the file is ignored", () => {
  const { risks } = riskRowsFromCsv("﻿title\nWith BOM\n");
  assert.equal(risks[0].title, "With BOM");
});

test("the exception expiry date is exported and imported, and must be a date", () => {
  assert.ok(CSV_COLS.includes("exceptionExpiry"));
  const header = riskCsvTemplate([]);
  const head = header.split(",").map((h) => h.replace(/^"|"$/g, ""));
  const row = (cells) => head.map((h) => `"${(cells[h] ?? "").replace(/"/g, '""')}"`).join(",");
  const ok = riskRowsFromCsv(`${header}\n${row({ title: "Exception", likelihood: "3", impact: "3", logException: "Yes", exceptionExpiry: "2026-12-10" })}\n`, []);
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.risks[0].exceptionExpiry, "2026-12-10");
  const bad = riskRowsFromCsv(`${header}\n${row({ title: "Exception", likelihood: "3", impact: "3", logException: "Yes", exceptionExpiry: "next week" })}\n`, []);
  assert.ok(bad.errors.some((e) => /exceptionExpiry must be a date/.test(String(e))));
});

test("the appetite columns are exported but worked out by the app, so an import ignores them", () => {
  assert.ok(CSV_COLS.includes("appetiteLimit") && CSV_COLS.includes("outsideAppetite"));
  const header = riskCsvTemplate([]);
  const head = header.split(",").map((h) => h.replace(/^"|"$/g, ""));
  const row = (cells) => head.map((h) => `"${(cells[h] ?? "").replace(/"/g, '""')}"`).join(",");
  const { risks, errors } = riskRowsFromCsv(`${header}\n${row({ title: "Appetite", likelihood: "3", impact: "3", appetiteLimit: "Low", outsideAppetite: "Yes" })}\n`, []);
  assert.deepEqual(errors, []);
  assert.equal(risks[0].appetiteLimit, undefined);
  assert.equal(risks[0].outsideAppetite, undefined);
});

test("the middle impact step is Medium, and files that still say Moderate import the same", async () => {
  const { IMPACT, shownCriticality, savedCriticality, riskRowsFromCsv } = await import("../risk-csv.js");
  assert.deepEqual(IMPACT, ["Very low", "Low", "Medium", "High", "Very high"]);
  const read = (impact, criticality) => riskRowsFromCsv(`title,impact,assetCriticality\nVPN,${impact},${criticality}`).risks[0];
  for (const text of ["Medium", "Moderate", "moderate", "3", "3. Medium", "3. Moderate"]) assert.equal(read(text, "3. Medium").impact, 3, text);
  // Saved asset criticality keeps its old form, so existing records and filters still match.
  assert.equal(read("Medium", "3. Medium").assetCriticality, "3. Moderate");
  assert.equal(read("Medium", "3. Moderate").assetCriticality, "3. Moderate");
  assert.equal(read("Medium", "4. High").assetCriticality, "4. High");
  assert.equal(shownCriticality("3. Moderate"), "3. Medium");
  assert.equal(shownCriticality("4. High"), "4. High");
  assert.equal(shownCriticality(undefined), undefined);
  assert.equal(savedCriticality(shownCriticality("3. Moderate")), "3. Moderate");
});

test("the AI is told to use the app's level names in its sentences", async () => {
  const { RISK_SYSTEM } = await import("../ai-tasks.js");
  assert.match(RISK_SYSTEM, /name risk levels Low, Medium, High and Critical/);
  assert.match(RISK_SYSTEM, /never write "Very High", "Very Low" or "Moderate"/);
});
