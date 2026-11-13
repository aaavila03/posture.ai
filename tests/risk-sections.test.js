// Risk register sections: the list a workspace keeps and the names it accepts.
// Run with: node --test tests/risk-sections.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { cleanRiskSections, sectionNameProblem, newSectionId, DEFAULT_RISK_SECTIONS, BUILT_IN_SECTIONS } from "../risk-sections.js";

test("no saved list means the default, which includes Other", () => {
  assert.deepEqual(cleanRiskSections(null), DEFAULT_RISK_SECTIONS);
  assert.deepEqual(cleanRiskSections(null).map((s) => s.name), ["Other"]);
});

test("a stored list is cleaned: bad, duplicate and built-in names are dropped", () => {
  const clean = cleanRiskSections([
    { id: "gov", name: "  Governance   " }, { id: "gov", name: "Duplicate id" }, { id: "x y", name: "Bad id" },
    { id: "ops", name: "governance" }, { id: "wf", name: "Workflow & governance" }, { id: "blank", name: "   " }, "nope", { id: "oth", name: "Other" },
  ]);
  assert.deepEqual(clean, [{ id: "gov", name: "Governance" }, { id: "oth", name: "Other" }]);
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

test("new ids are unique and lower-case", () => {
  const existing = [{ id: "s1" }];
  for (let i = 0; i < 50; i++) {
    const id = newSectionId(existing);
    assert.match(id, /^[a-z0-9]{1,20}$/);
    assert.notEqual(id, "s1");
  }
});
