// Risk appetite: the limits, and which risks are outside them.
import { test } from "node:test";
import assert from "node:assert/strict";
import { APPETITE_LEVELS, APPETITE_CATEGORIES, cleanAppetite, limitFor, appetiteCheck, appetiteText } from "../appetite.js";

const appetite = cleanAppetite({ default: "Medium", categories: { "Data Breach": "Low", "Third-Party/Supply Chain": "High" } });

test("a valid appetite is kept, and anything else is dropped", () => {
  assert.deepEqual(appetite, { default: "Medium", categories: { "Data Breach": "Low", "Third-Party/Supply Chain": "High" } });
  assert.equal(cleanAppetite(null), null);
  assert.equal(cleanAppetite(undefined), null);
  assert.equal(cleanAppetite("High"), null);
  assert.equal(cleanAppetite({ default: "Severe" }), null);
  assert.equal(cleanAppetite({ categories: { "Data Breach": "Low" } }), null);
});

test("unknown categories and unknown levels are removed from the limits", () => {
  const a = cleanAppetite({ default: "High", categories: { "Data Breach": "Severe", "Made up": "Low", Other: "Critical", "Insider Threat": 3 } });
  assert.deepEqual(a, { default: "High", categories: { Other: "Critical" } });
  assert.ok(APPETITE_CATEGORIES.includes("Other") && APPETITE_LEVELS.length === 4);
});

test("a category uses its own limit, or the default", () => {
  assert.equal(limitFor(appetite, "Data Breach"), "Low");
  assert.equal(limitFor(appetite, "Third-Party/Supply Chain"), "High");
  assert.equal(limitFor(appetite, "Insider Threat"), "Medium");
  assert.equal(limitFor(appetite, undefined), "Medium");
  assert.equal(limitFor(null, "Data Breach"), null);
});

test("a risk is outside appetite only when its residual level is above the limit", () => {
  const check = (category, residualLevel, status = "In treatment") => appetiteCheck(appetite, { category, residualLevel, status });
  assert.deepEqual(check("Insider Threat", "Medium"), { limit: "Medium", over: 0, outside: false });
  assert.deepEqual(check("Insider Threat", "Low"), { limit: "Medium", over: 0, outside: false });
  assert.deepEqual(check("Insider Threat", "High"), { limit: "Medium", over: 1, outside: true });
  assert.deepEqual(check("Insider Threat", "Critical"), { limit: "Medium", over: 2, outside: true });
  // A stricter limit for one category, a looser one for another.
  assert.equal(check("Data Breach", "Medium").outside, true);
  assert.equal(check("Third-Party/Supply Chain", "High").outside, false);
  assert.equal(check("Third-Party/Supply Chain", "Critical").outside, true);
});

test("nothing is flagged without an appetite, and closed risks are left out", () => {
  assert.equal(appetiteCheck(null, { category: "Data Breach", residualLevel: "Critical", status: "Identified" }), null);
  assert.equal(appetiteCheck(appetite, { category: "Data Breach", residualLevel: "Critical", status: "Closed" }), null);
});

test("appetiteText explains where a risk stands", () => {
  const over = appetiteCheck(appetite, { category: "Data Breach", residualLevel: "High", status: "Identified" });
  assert.equal(appetiteText(over, { residualLevel: "High", category: "Data Breach" }), "Outside appetite: residual High is above the Low limit for Data Breach.");
  const within = appetiteCheck(appetite, { category: "Insider Threat", residualLevel: "Low", status: "Identified" });
  assert.equal(appetiteText(within, { residualLevel: "Low", category: "Insider Threat" }), "Within appetite (limit Medium).");
  assert.equal(appetiteText(null, { residualLevel: "Low" }), "");
});
