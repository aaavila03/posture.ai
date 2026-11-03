// Threat risk assessments: the library's integrity, control selection and scoring.
// Run with: node --test tests/tra.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { CONTROLS, THREATS, THREAT_CATEGORIES, IMPACT_ROWS, TRIGGERS, AUTH_METHODS, ASSET_TYPES, CONTROL_SECTIONS, LIBRARY_VERSION } from "../tra-library.js";
import { impactRating, selectControls, controlsFor, riskLevel, scoreRisk, summarize, prepareForSave, blankThreatAssessment } from "../tra.js";

const assess = (overall, profile = {}, extra = {}) => ({
  ...blankThreatAssessment(),
  impact: overall ? { B2: { a: overall } } : {},
  profile: { assetTypes: ["app"], auth: {}, ...profile },
  ...extra,
});

test("the library is consistent", () => {
  assert.equal(new Set(CONTROLS.map((c) => c.id)).size, CONTROLS.length, "control IDs are unique");
  const threats = new Set(THREATS.map((t) => t.id));
  assert.equal(threats.size, THREATS.length, "threat IDs are unique");
  const assets = new Set(ASSET_TYPES.map(([k]) => k));
  const questions = new Set(["general", ...TRIGGERS.map((t) => t.key), ...AUTH_METHODS.map(([k]) => k)]);
  for (const c of CONTROLS) {
    assert.ok(c.text && c.gap && c.nist && c.section, `${c.id} has its text`);
    assert.ok(c.rules.length, `${c.id} has a rule, so it can be selected`);
    for (const r of c.rules) {
      assert.ok(questions.has(r.on), `${c.id} rule ${r.on} is a real question`);
      assert.ok(["L", "M", "H"].includes(r.tier), `${c.id} tier ${r.tier}`);
    }
    assert.ok(c.threats.length, `${c.id} has threats`);
    for (const t of c.threats) assert.ok(threats.has(t), `${c.id} threat ${t} exists`);
    for (const a of c.assets) assert.ok(assets.has(a), `${c.id} asset ${a} exists`);
  }
  for (const t of THREATS) assert.ok(THREAT_CATEGORIES.includes(t.category));
  assert.equal(new Set(CONTROLS.map((c) => c.section)).size, Object.keys(CONTROL_SECTIONS).length, "every section has controls");
  for (const r of IMPACT_ROWS) assert.equal(r.levels.length, 5, `${r.id} has five levels`);
});

test("the library names no company", () => {
  const source = readFileSync(new URL("../tra-library.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /\b(TECO|Emera|Tampa Electric|EMA-CSF|Florida Public Service)\b/i);
});

test("every question and asset type changes which controls are picked", () => {
  const all = { assetTypes: ["app", "os", "net", "ot"], auth: {} };
  const base = selectControls(assess("A", all)).length;
  for (const [key] of AUTH_METHODS) {
    assert.ok(selectControls(assess("A", { ...all, auth: { [key]: true } })).length > base, `sign-in method ${key}`);
  }
  for (const t of TRIGGERS) {
    assert.ok(selectControls(assess("A", { ...all, [t.key]: t.when })).length > base, `question ${t.key}`);
  }
  // Each asset type on its own picks a different set of controls.
  const sets = ASSET_TYPES.map(([type]) => selectControls(assess("A", { assetTypes: [type] })).map((c) => c.id).join());
  assert.ok(sets.every(Boolean));
  assert.equal(new Set(sets).size, ASSET_TYPES.length);
});

test("every control can be selected", () => {
  const everything = { assetTypes: ASSET_TYPES.map(([k]) => k), auth: Object.fromEntries(AUTH_METHODS.map(([k]) => [k, true])),
    ...Object.fromEntries(TRIGGERS.map((t) => [t.key, t.when])) };
  assert.equal(selectControls(assess("A", everything)).length, CONTROLS.length);
});

test("each control appears once, however many of its rules fire", () => {
  const picked = selectControls(assess("A", { assetTypes: ["app", "os", "net", "ot"], external: "Yes", internet: "Yes", thirdParty: "Yes", cloud: "Yes" }));
  assert.equal(new Set(picked.map((c) => c.id)).size, picked.length);
});

test("higher impact brings in more controls", () => {
  const count = (letter) => selectControls(assess(letter)).length;
  assert.ok(count("A") > count("C") && count("C") > count("E"));
  assert.equal(count("A"), count("B"));
  assert.equal(count("D"), count("E"));
});

test("no controls until there's an impact rating and an asset type", () => {
  assert.equal(selectControls(assess(null)).length, 0);
  assert.equal(selectControls(assess("B", { assetTypes: [] })).length, 0);
});

test("OT controls only apply to OT assets, and the end-of-life question only to OT", () => {
  assert.ok(selectControls(assess("B")).every((c) => !c.id.startsWith("O")));
  assert.ok(selectControls(assess("B", { assetTypes: ["ot"] })).every((c) => c.assets.includes("ot")));
  assert.deepEqual(selectControls(assess("B", { otEol: "Yes" })), selectControls(assess("B")));
});

test("the impact rating is the worst answer, and not applicable doesn't count", () => {
  assert.deepEqual(impactRating({ B1: { c: "D", i: "NA" }, L1: { c: "B", a: "C" }, R1: { i: "E" } }), { c: "B", i: "E", a: "C", overall: "B" });
  assert.equal(impactRating({ B1: { c: "NA" } }).overall, null);
  // B1 to B6 are scored for confidentiality and integrity too.
  for (const id of ["B1", "B2", "B3", "B4", "B5", "B6"]) {
    assert.equal(impactRating({ [id]: { c: "A" } }).c, "A");
    assert.equal(impactRating({ [id]: { i: "A" } }).i, "A");
  }
});

test("scores and risk levels follow the 1, 2, 5, 8, 10 scale", () => {
  const expected = { 100: "Very High", 80: "Very High", 64: "High", 50: "High", 40: "Moderate", 25: "Moderate", 20: "Moderate", 16: "Moderate", 10: "Low", 8: "Low", 5: "Low", 4: "Low", 2: "Very Low", 1: "Very Low" };
  for (const [score, level] of Object.entries(expected)) assert.equal(riskLevel(Number(score)), level, score);
  assert.equal(riskLevel(0), "");
  assert.deepEqual(scoreRisk("A", "Probable"), { score: 100, level: "Very High" });
  assert.deepEqual(scoreRisk("B", "Possible"), { score: 40, level: "Moderate" });
  assert.deepEqual(scoreRisk("E", "Remote"), { score: 1, level: "Very Low" });
  assert.deepEqual(scoreRisk("B", ""), { score: 0, level: "" });
});

test("the summary counts gaps, levels, treatments and threat categories", () => {
  const a = assess("B");
  const [first, second, third] = selectControls(a);
  a.answers = { [first.id]: { status: "No" }, [second.id]: { status: "Partially" }, [third.id]: { status: "Yes" } };
  a.gapDetails = {
    [first.id]: { likelihood: "Likely", residualLikelihood: "Unlikely", treatment: "Reduce", threats: ["intrusion", "not-a-threat"] },
    [second.id]: { likelihood: "Possible", threats: ["intrusion", "dos"] },
  };
  const s = summarize(a);
  assert.equal(s.gaps.length, 2);
  assert.equal(s.answered, 3);
  assert.equal(s.scored, 2);
  assert.equal(s.managedLevels.High, 1);
  assert.equal(s.managedLevels.Moderate, 1);
  assert.equal(s.residualLevels.Moderate, 1);
  assert.equal(s.treatments.Reduce, 1);
  assert.equal(s.highestManaged, "High");
  assert.equal(s.highestResidual, "Moderate");
  // intrusion averages 64 and 40 (52); denial of service is 40; the category averages those.
  assert.equal(s.categories.find((c) => c.category === "External attacks").score, 46);
  assert.equal(s.categories.find((c) => c.category === "External attacks").level, "Moderate");
  assert.equal(s.categories.find((c) => c.category === "Human error").score, 0);
});

test("a gap only counts while its control still applies", () => {
  const a = assess("B", { cloud: "Yes" });
  const cloudOnly = selectControls(a).find((c) => c.rules.every((r) => r.on === "cloud"));
  a.answers = { [cloudOnly.id]: { status: "No" } };
  assert.equal(summarize(a).gaps.length, 1);
  a.profile.cloud = "No";
  assert.equal(summarize(a).gaps.length, 0);
});

test("completing freezes the controls, and reopening releases them", () => {
  const a = prepareForSave(assess("C", {}, { status: "Completed" }));
  assert.deepEqual(a.frozenControls.map((c) => c.id), selectControls(a).map((c) => c.id));
  assert.equal(a.libraryVersion, LIBRARY_VERSION);
  // A frozen assessment keeps its controls even when its answers would now pick others.
  const moved = { ...a, impact: { B2: { a: "A" } } };
  assert.equal(controlsFor(moved).length, a.frozenControls.length);
  assert.ok(selectControls(moved).length > a.frozenControls.length);
  const again = prepareForSave(a);
  assert.equal(again.frozenControls, a.frozenControls, "saving again keeps the same frozen list");
  const reopened = prepareForSave({ ...a, status: "In progress" });
  assert.equal(reopened.frozenControls, undefined);
});
