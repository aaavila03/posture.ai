import { test } from "node:test";
import assert from "node:assert/strict";
import { parseStandardsFile, mergeStandards, cleanStandards, MAX_STANDARDS } from "../standards.js";

test("a JSON array of names is read", () => {
  const { standards, errors } = parseStandardsFile("std.json", '["ISO 27001", "NIST CSF 2.0"]');
  assert.deepEqual(standards, ["ISO 27001", "NIST CSF 2.0"]);
  assert.deepEqual(errors, []);
});

test("a JSON object with objects inside is read by name, title or standard", () => {
  const text = JSON.stringify({ standards: [{ name: "Policy A" }, { title: "Policy B" }, { standard: "Policy C" }] });
  assert.deepEqual(parseStandardsFile("std.json", text).standards, ["Policy A", "Policy B", "Policy C"]);
});

test("a CSV with a standard column uses that column", () => {
  const csv = "id,standard,owner\n1,ISO 27001,IT\n2,SOC 2,Risk\n";
  assert.deepEqual(parseStandardsFile("standards.csv", csv).standards, ["ISO 27001", "SOC 2"]);
});

test("a CSV without a named column uses the first column", () => {
  assert.deepEqual(parseStandardsFile("standards.csv", "PCI DSS\nHIPAA\n").standards, ["PCI DSS", "HIPAA"]);
});

test("a text file has one standard per line, and comments are skipped", () => {
  const text = "# company standards\nISO 27001\n\n  NIST CSF 2.0  \n";
  assert.deepEqual(parseStandardsFile("standards.txt", text).standards, ["ISO 27001", "NIST CSF 2.0"]);
});

test("a file with nothing usable reports an error", () => {
  const { standards, errors } = parseStandardsFile("empty.txt", "\n\n");
  assert.deepEqual(standards, []);
  assert.match(errors[0], /no standards found/);
});

test("a broken JSON file reports an error instead of throwing", () => {
  const { standards, errors } = parseStandardsFile("bad.json", "[1, 2");
  assert.deepEqual(standards, []);
  assert.match(errors[0], /^bad\.json:/);
});

test("repeats across files are dropped, ignoring case, and the first spelling wins", () => {
  const first = parseStandardsFile("a.txt", "ISO 27001\nSOC 2").standards;
  const merged = mergeStandards(first, ["iso 27001", "PCI DSS", "  "]);
  assert.deepEqual(merged, ["ISO 27001", "SOC 2", "PCI DSS"]);
});

test("the list is capped", () => {
  const many = Array.from({ length: MAX_STANDARDS + 50 }, (_, i) => `Standard ${i}`);
  assert.equal(mergeStandards([], many).length, MAX_STANDARDS);
});

test("stored values that aren't short text are dropped", () => {
  assert.deepEqual(cleanStandards(["ISO", 5, null, { name: "x" }, "  "]), ["ISO"]);
  assert.deepEqual(cleanStandards("not a list"), []);
});

test("the AI prompt text lists the active standards, and is empty when there are none", async () => {
  const { setActiveStandards, standardsPromptText } = await import("../standards.js");
  setActiveStandards([]);
  assert.equal(standardsPromptText(), "");
  setActiveStandards(["ISO 27001", "  ", "NIST CSF 2.0"]);
  const text = standardsPromptText();
  assert.match(text, /- ISO 27001\n- NIST CSF 2\.0/);
  setActiveStandards([]);
});

test("a controls register becomes ID and control activity", () => {
  const csv = '"Function","ID","Control Activity","Owner"\n"Govern","GV.OC-01","Maintain an obligations register","SL"\n"Protect","PR.AA-02","Enforce MFA","IT"\n';
  assert.deepEqual(parseStandardsFile("register.csv", csv).standards, ["GV.OC-01: Maintain an obligations register", "PR.AA-02: Enforce MFA"]);
});

test("the short name of a control is its ID", async () => {
  const { standardId } = await import("../standards.js");
  assert.equal(standardId("GV.OC-01: Maintain an obligations register"), "GV.OC-01");
  assert.equal(standardId("NIST CSF 2.0"), "NIST CSF 2.0");
});
