// How the record tables show dates. Run with: node --test tests/dates.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { tableDate } from "../dates.js";

test("a stored date reads like Jan 1, 2027, whatever the time zone", () => {
  assert.equal(tableDate("2027-01-01"), "Jan 1, 2027");
  assert.equal(tableDate("2026-11-09"), "Nov 9, 2026");
  assert.equal(tableDate("2026-12-31"), "Dec 31, 2026");
});

test("anything that isn't a stored date is shown as it is", () => {
  assert.equal(tableDate(""), "");
  assert.equal(tableDate(undefined), "");
  assert.equal(tableDate(null), "");
  assert.equal(tableDate("Q1 2027"), "Q1 2027");
  assert.equal(tableDate("2027-13-01"), "2027-13-01");
});
