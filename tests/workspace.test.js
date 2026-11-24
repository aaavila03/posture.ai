// Deleting a workspace asks for its name; this is the check on what was typed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { nameMatches } from "../workspace.js";

test("typing the workspace name confirms, ignoring spaces around it", () => {
  assert.equal(nameMatches("Acme Corp", "Acme Corp"), true);
  assert.equal(nameMatches("  Acme Corp  ", "Acme Corp"), true);
  assert.equal(nameMatches("Acme Corp", " Acme Corp "), true);
});

test("anything else does not confirm", () => {
  assert.equal(nameMatches("acme corp", "Acme Corp"), false, "the case must match");
  assert.equal(nameMatches("Acme", "Acme Corp"), false);
  assert.equal(nameMatches("Acme Corp Ltd", "Acme Corp"), false);
  assert.equal(nameMatches("Acme  Corp", "Acme Corp"), false, "spaces inside the name must match");
  assert.equal(nameMatches("", "Acme Corp"), false);
});

test("an empty or missing name can never be confirmed", () => {
  assert.equal(nameMatches("", ""), false);
  assert.equal(nameMatches("   ", "   "), false);
  assert.equal(nameMatches(undefined, undefined), false);
  assert.equal(nameMatches(null, "Acme Corp"), false);
  assert.equal(nameMatches("Acme Corp", null), false);
});
