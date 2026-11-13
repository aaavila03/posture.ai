// Risk register sections: the list a workspace keeps and the names it accepts.
// Run with: node --test tests/risk-sections.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { cleanRiskSections, sectionNameProblem, fieldProblem, parseOptions, newId, allIds, DEFAULT_RISK_SECTIONS, BUILT_IN_SECTIONS } from "../risk-sections.js";

test("no saved list means the default, which includes Other", () => {
  assert.deepEqual(cleanRiskSections(null), DEFAULT_RISK_SECTIONS);
  assert.deepEqual(cleanRiskSections(null).map((s) => s.name), ["Other"]);
});

test("a stored list is cleaned: bad, duplicate and built-in names are dropped", () => {
  const clean = cleanRiskSections([
    { id: "gov", name: "  Governance   " }, { id: "gov", name: "Duplicate id" }, { id: "x y", name: "Bad id" },
    { id: "ops", name: "governance" }, { id: "wf", name: "Workflow & governance" }, { id: "blank", name: "   " }, "nope", { id: "oth", name: "Other" },
  ]);
  assert.deepEqual(clean, [{ id: "gov", name: "Governance", fields: [] }, { id: "oth", name: "Other", fields: [] }]);
});

test("an empty list stays empty, so the admin can remove Other", () => {
  assert.deepEqual(cleanRiskSections([]), []);
});

test("names are checked against the list and the built-in sections", () => {
  const sections = [{ id: "gov", name: "Governance" }];
  assert.equal(sectionNameProblem("", sections), "Give the section a name");
  assert.match(sectionNameProblem("governance", sections), /already a section/);
  assert.match(sectionNameProblem("Ownership", sections), /built-in/);
  assert.match(sectionNameProblem("x".repeat(61), sections), /60 characters/);
  assert.equal(sectionNameProblem("Governance", sections, "gov"), "", "a section can keep its own name");
  assert.equal(sectionNameProblem("Risk culture", sections), "");
  assert.equal(BUILT_IN_SECTIONS.length, 5);
});

test("fields keep their type, and only pick lists keep choices", () => {
  const clean = cleanRiskSections([{ id: "gov", name: "Governance", fields: [
    { id: "a1", label: "Owner approved", type: "yesno", options: ["x"] },
    { id: "a2", label: "Tier", type: "picklist", options: ["Tier 1", "tier 1", " ", "Tier 2"] },
    { id: "a3", label: "Script", type: "script" },
    { id: "a4", label: "", type: "text" },
    { id: "gov", label: "Same id as the section", type: "text" },
  ] }]);
  assert.deepEqual(clean[0].fields, [
    { id: "a1", label: "Owner approved", type: "yesno" },
    { id: "a2", label: "Tier", type: "picklist", options: ["Tier 1", "Tier 2"] },
  ]);
});

test("field names and choices are checked before they're saved", () => {
  const sections = [{ id: "gov", name: "Governance", fields: [{ id: "a1", label: "Owner approved", type: "yesno" }] }];
  assert.equal(fieldProblem({ id: "b1", label: "", type: "text" }, sections), "Give the field a name");
  assert.match(fieldProblem({ id: "b1", label: "owner approved", type: "text" }, sections), /already a field/);
  assert.equal(fieldProblem({ id: "a1", label: "Owner approved", type: "yesno" }, sections, "a1"), "", "a field keeps its own name");
  assert.match(fieldProblem({ id: "b1", label: "Tier", type: "picklist", options: [] }, sections), /at least one choice/);
  assert.deepEqual(parseOptions("Tier 1, Tier 2,\n , Tier 3"), ["Tier 1", "Tier 2", "Tier 3"]);
});

test("new ids are unique, lower-case and clear of every section and field", () => {
  const sections = [{ id: "f1", name: "x", fields: [{ id: "f2" }] }];
  for (let i = 0; i < 50; i++) {
    const id = newId(allIds(sections));
    assert.match(id, /^[a-z0-9]{1,20}$/);
    assert.ok(!["f1", "f2"].includes(id));
  }
});
