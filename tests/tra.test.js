// Threat risk assessments: the library's integrity, control selection and scoring.
// Run with: node --test tests/tra.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { CONTROLS, THREATS, THREAT_CATEGORIES, IMPACT_ROWS, TRIGGERS, AUTH_METHODS, ASSET_TYPES, CONTROL_SECTIONS, LIBRARY_VERSION,
  FRAMEWORKS, CSF_FUNCTIONS, CSF_CATEGORIES, SP80053_FAMILIES } from "../tra-library.js";
import { impactRating, selectControls, controlsFor, riskLevel, scoreRisk, summarize, prepareForSave, blankThreatAssessment, cleanOutsideResponse, applyOutsideResponse, outsideChanges,
  inFramework, frameworkOf, isFramework, DEFAULT_FRAMEWORK } from "../tra.js";

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
    for (const r of c.rules) assert.ok(questions.has(r), `${c.id} rule ${r} is a real question`);
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

test("the impact rating doesn't change which controls apply", () => {
  const ids = (letter) => selectControls(assess(letter)).map((c) => c.id);
  assert.ok(ids(null).length > 0);
  for (const letter of ["A", "C", "E"]) assert.deepEqual(ids(letter), ids(null));
});

test("no controls until there's an asset type", () => {
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

test("gaps can be assessed before impact is rated, and score once it is", () => {
  const a = assess(null);
  const [first] = selectControls(a);
  a.answers = { [first.id]: { status: "No" } };
  a.gapDetails = { [first.id]: { likelihood: "Likely" } };
  let s = summarize(a);
  assert.equal(s.assessed, 1);
  assert.equal(s.gaps[0].managed.score, 0);
  assert.equal(s.highestManaged, "");
  a.impact = { B2: { a: "B" } };
  s = summarize(a);
  assert.deepEqual(s.gaps[0].managed, { score: 64, level: "High" });
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
  assert.equal(s.assessed, 2);
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
  const cloudOnly = selectControls(a).find((c) => c.rules.every((r) => r === "cloud"));
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
  const moved = { ...a, profile: { ...a.profile, cloud: "Yes" } };
  assert.equal(controlsFor(moved).length, a.frozenControls.length);
  assert.ok(selectControls(moved).length > a.frozenControls.length);
  const again = prepareForSave(a);
  assert.equal(again.frozenControls, a.frozenControls, "saving again keeps the same frozen list");
  const reopened = prepareForSave({ ...a, status: "In progress" });
  assert.equal(reopened.frozenControls, undefined);
});

test("outside answers keep only the known questions, controls and impact ratings", () => {
  const clean = cleanOutsideResponse({
    description: "Billing", riskOwner: "Mallory", impact: { B1: { c: "A" } }, gapDetails: { "AC-01": {} }, status: "Completed",
    profile: { assetTypes: ["app", "nope"], cloud: "Yes", web: "maybe", auth: { otp: true, nope: true, pins: "yes" }, vendor: "Acme", assetOwner: "Mallory" },
    answers: { "AC-01": { status: "No", evidence: "None", extra: "x" }, "AC-02": { status: "Sure" }, "XX-99": { status: "Yes" } },
  });
  assert.deepEqual(clean, {
    profile: { assetTypes: ["app"], auth: { otp: true }, cloud: "Yes", vendor: "Acme" },
    answers: { "AC-01": { status: "No", evidence: "None" } },
    impact: { B1: { c: "A" } },
    description: "Billing",
  });
  assert.deepEqual(cleanOutsideResponse(null), { profile: { assetTypes: [], auth: {} }, answers: {}, impact: {} });
  assert.equal(cleanOutsideResponse({ answers: { "AC-01": { status: "Yes", evidence: "x".repeat(5000) } } }).answers["AC-01"].evidence.length, 2000);
});

const applied = () => ({ ...blankThreatAssessment(), assetName: "Billing", riskOwner: "Ana", status: "In progress", impact: { B1: { c: "B" } },
  gapDetails: { "AC-01": { likelihood: "Likely" } }, description: "Old", profile: { assetTypes: ["os"], auth: { pins: true }, cloud: "No" },
  answers: { "AC-01": { status: "No", evidence: "Old evidence" }, "AC-02": { status: "Yes" } } });

test("applying outside answers fills steps 1 and 2 and leaves the rest alone", () => {
  const a = applied();
  const before = structuredClone(a);
  const next = applyOutsideResponse(a, {
    riskOwner: "Mallory", status: "Completed", description: "New", profile: { assetTypes: ["app"], auth: { otp: true }, cloud: "Yes" },
    answers: { "AC-01": { status: "Partially", compensating: "Reviews" }, "AC-03": { status: "Yes" } },
  });
  assert.deepEqual(a, before, "the original isn't changed");
  assert.equal(next.description, "New");
  assert.deepEqual(next.profile, { assetTypes: ["os", "app"], auth: { pins: true, otp: true }, cloud: "Yes" });
  assert.deepEqual(next.answers["AC-01"], { status: "Partially", evidence: "Old evidence", compensating: "Reviews" });
  assert.deepEqual(next.answers["AC-02"], { status: "Yes" }, "answers not in the response stay");
  assert.equal(next.riskOwner, "Ana");
  assert.equal(next.status, "In progress");
  assert.deepEqual(next.impact, a.impact);
  assert.deepEqual(next.gapDetails, a.gapDetails);
});

test("a blank outside form can't remove asset types or sign-in methods", () => {
  const next = applyOutsideResponse(applied(), { profile: { assetTypes: [], auth: {} } });
  assert.deepEqual(next.profile, applied().profile);
});

test("the review lists every change and flags ones that make the asset look safer", () => {
  const a = { ...applied(), profile: { assetTypes: ["app"], auth: {}, cloud: "Yes", internet: "Yes" } };
  const { rows, flagged, removed } = outsideChanges(a, {
    description: "New", profile: { cloud: "No", web: "Yes" },
    answers: { "AC-01": { status: "Yes", evidence: "Trust me" }, "AC-02": { status: "No" }, "AC-03": { status: "Yes" } },
  });
  const row = (start) => rows.find((x) => x.label.startsWith(start));
  // Controls are listed by their reference in the framework, here the default (SP 800-53).
  const title = (id) => { const c = CONTROLS.find((x) => x.id === id); return `${c.nist}: ${c.text}`; };
  assert.deepEqual([row("Description").from, row("Description").to, row("Description").flag], ["Old", "New", false]);
  assert.equal(row(title("AC-01")).flag, true, "a gap marked as met is flagged");
  assert.equal(row(title("AC-02")).flag, false, "a worse answer isn't flagged");
  assert.equal(row(title("AC-03")).flag, false, "a first answer isn't flagged");
  assert.equal(row(`Evidence for ${title("AC-01")}`).to, "Trust me");
  const csf = outsideChanges(a, { answers: { "AC-01": { status: "Yes" } } }, "csf2").rows;
  assert.ok(csf[0].label.startsWith(`${CONTROLS[0].csf}: `), "the review uses the workspace's framework");
  assert.equal(rows.find((x) => x.label.startsWith("Runs in, or stores data")).flag, true, "exposure answered away is flagged");
  assert.equal(rows.find((x) => x.label.startsWith("Has web")).flag, false);
  assert.equal(flagged, 2);
  assert.ok(removed.some((c) => c.rules.every((r) => r === "cloud")), "lists controls the answers remove");
});

test("the review shows no changes when nothing differs", () => {
  const a = applied();
  const { rows, removed, flagged } = outsideChanges(a, { description: "Old", profile: { cloud: "No" }, answers: { "AC-02": { status: "Yes" } } });
  assert.deepEqual([rows, removed, flagged], [[], [], 0]);
});

test("every control has a place in both frameworks", () => {
  assert.deepEqual(FRAMEWORKS.map(([key]) => key), ["csf2", "sp80053"]);
  assert.ok(isFramework(DEFAULT_FRAMEWORK) && !isFramework("iso27001") && !isFramework(null));
  for (const c of CONTROLS) {
    assert.match(c.nist, /^[A-Z]{2}-\d{1,2}$/, `${c.id} has an SP 800-53 control`);
    assert.ok(SP80053_FAMILIES[c.nist.split("-")[0]], `${c.id} is in a real SP 800-53 family`);
    assert.match(c.csf, /^[A-Z]{2}\.[A-Z]{2}-\d{2}$/, `${c.id} has a CSF 2.0 subcategory`);
    assert.ok(CSF_CATEGORIES[c.csf.split("-")[0]] && CSF_FUNCTIONS[c.csf.slice(0, 2)], `${c.id} is in a real CSF 2.0 category`);
  }
});

test("the framework sets each control's reference, group and order, and nothing else", () => {
  const a = assess("B", { cloud: "Yes", thirdParty: "Yes" });
  const first = selectControls(a)[0];
  assert.deepEqual([inFramework(first, "sp80053").ref, inFramework(first, "sp80053").group], ["AC-2", "Access Control (AC)"]);
  assert.deepEqual([inFramework(first, "csf2").ref, inFramework(first, "csf2").group],
    ["PR.AA-01", "Protect: Identity Management, Authentication, and Access Control (PR.AA)"]);
  for (const fw of ["csf2", "sp80053"]) {
    const controls = controlsFor(a, fw);
    assert.deepEqual(controls.map((c) => c.id).sort(), selectControls(a).map((c) => c.id).sort(), "the same controls apply");
    const groups = controls.map((c) => c.group);
    assert.deepEqual(groups.filter((g, i) => g !== groups[i - 1]), [...new Set(groups)], "each group's controls are listed together");
    assert.ok(controls.every((c, i) => !i || controls[i - 1].rank <= c.rank), "groups follow the framework's order");
  }
  assert.equal(controlsFor(a, "csf2")[0].group.startsWith("Govern: "), true, "CSF starts with Govern");
  a.answers = { [first.id]: { status: "No" } };
  a.gapDetails = { [first.id]: { likelihood: "Likely" } };
  const csf = summarize(a, "csf2"), sp = summarize(a, "sp80053");
  assert.deepEqual([csf.gaps.length, csf.gaps[0].managed], [sp.gaps.length, sp.gaps[0].managed], "scores don't depend on the framework");
  assert.equal(csf.sections.find((s) => s.gaps).section, "Protect: Identity Management, Authentication, and Access Control (PR.AA)");
  assert.equal(sp.sections.find((s) => s.gaps).section, "Access Control (AC)");
  assert.equal(csf.sections.reduce((n, s) => n + s.controls, 0), csf.controls.length);
});

test("a completed assessment keeps its framework when the workspace changes", () => {
  assert.equal(frameworkOf(assess("C"), "csf2"), "csf2");
  assert.equal(frameworkOf(assess("C"), null), DEFAULT_FRAMEWORK, "shown with the default until the workspace chooses");
  const done = prepareForSave(assess("C", {}, { status: "Completed" }), "csf2");
  assert.equal(done.framework, "csf2");
  assert.equal(frameworkOf(done, "sp80053"), "csf2");
  assert.equal(controlsFor(done, "sp80053")[0].ref.includes("."), true, "still shown with CSF references");
  assert.equal(prepareForSave(done, "sp80053").framework, "csf2", "saving again doesn't move it");
  const reopened = prepareForSave({ ...done, status: "In progress" }, "sp80053");
  assert.equal(reopened.framework, "sp80053", "reopening moves it to the workspace's framework");
  // Completed before frameworks were recorded: follows the workspace, with references from the library.
  const old = { ...done, framework: undefined, frozenControls: done.frozenControls.map(({ csf, ...c }) => c) };
  assert.equal(controlsFor(old, "csf2")[0].ref.includes("."), true);
});

test("AI controls apply only when the asset uses AI, and are mapped to both frameworks", () => {
  const ai = (c) => c.id.startsWith("AI-");
  const picked = (profile) => selectControls(assess("B", profile)).filter(ai);
  assert.equal(picked({}).length, 0, "none without AI");
  const uses = picked({ ai: "Yes" }), acts = picked({ ai: "Yes", aiActs: "Yes" }), trains = picked({ ai: "Yes", aiActs: "Yes", aiTrain: "Yes" });
  assert.ok(uses.length > 0 && acts.length > uses.length && trains.length > acts.length, "each AI question adds its controls");
  assert.equal(trains.length, CONTROLS.filter(ai).length);
  assert.equal(picked({ ai: "No", aiActs: "No", aiTrain: "No" }).length, 0);
  for (const type of ASSET_TYPES.map(([k]) => k)) assert.ok(picked({ assetTypes: [type], ai: "Yes" }).length > 0, `AI controls apply to ${type} assets`);
  for (const fw of ["csf2", "sp80053"]) {
    const controls = controlsFor(assess("B", { ai: "Yes", aiActs: "Yes", aiTrain: "Yes" }), fw).filter(ai);
    assert.ok(controls.every((c) => c.ref && c.rank >= 0 && !c.group.includes("undefined")), `every AI control has a place in ${fw}`);
  }
  const aiThreats = ["promptinject", "datapoison", "aioutput"];
  for (const id of aiThreats) assert.ok(CONTROLS.some((c) => ai(c) && c.threats.includes(id)), `${id} is used by an AI control`);
});

test("a link that starts from step 1's choices lists the same controls as the assessment", () => {
  // What a link always carries (see tra_outside_load): asset types, sign-in methods and Yes/No answers.
  const scope = (profile) => Object.fromEntries(Object.entries(profile).filter(([k, v]) => ["assetTypes", "auth"].includes(k) || ["Yes", "No"].includes(v)));
  const a = assess("B", { assetTypes: ["app", "ot"], auth: { passwords: true, keys: true }, cloud: "Yes", web: "Yes", centralAuth: "No", otEol: "Yes",
    ai: "Yes", aiActs: "Yes", aiTrain: "No", vendor: "Acme", notes: "Private", deployment: "Public" });
  const form = cleanOutsideResponse({ profile: scope(a.profile) });
  assert.deepEqual(Object.keys(form.profile).filter((k) => ["vendor", "notes", "deployment"].includes(k)), [], "free text isn't carried");
  assert.deepEqual(form.answers, {});
  for (const fw of ["csf2", "sp80053"]) {
    assert.deepEqual(controlsFor(form, fw).map((c) => [c.id, c.ref, c.group]), controlsFor(a, fw).map((c) => [c.id, c.ref, c.group]));
  }
  assert.ok(selectControls(cleanOutsideResponse({})).length === 0, "a form with nothing to start from lists no controls");
});

test("impact ratings from the outside form are checked, applied and listed for review", () => {
  const clean = cleanOutsideResponse({ impact: { B1: { c: "A", i: "Z", a: "NA" }, XX9: { c: "A" }, B2: "bad" } });
  assert.deepEqual(clean.impact, { B1: { c: "A", a: "NA" } });
  const a = applied();
  const next = applyOutsideResponse(a, { impact: { B1: { i: "E" }, B2: { c: "D" } } });
  assert.deepEqual(next.impact, { B1: { c: "B", i: "E" }, B2: { c: "D" } });
  const { rows, flagged } = outsideChanges(a, { impact: { B1: { i: "E" } } });
  const label = `Impact: ${IMPACT_ROWS.find((r) => r.id === "B1").label} (integrity)`;
  assert.ok(rows.some((r) => r.label === label && r.from === "" && r.to.startsWith("E –")), "the integrity rating is listed");
  assert.equal(flagged, 0, "impact ratings are listed, not flagged as making the asset look safer");
});
