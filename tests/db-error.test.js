// Errors from a hosted database that hasn't had the latest migrations applied.
import { test } from "node:test";
import assert from "node:assert/strict";
import { dbErrorMessage } from "../store.js";

test("a missing function or column says the database needs updating", () => {
  const missingFn = { code: "PGRST202", message: "Could not find the function public.set_org_risk_appetite(appetite, org) in the schema cache" };
  const missingCol = { code: "42703", message: "column organizations.risk_appetite does not exist" };
  for (const err of [missingFn, missingCol, { message: "Could not find the 'x' column of 'risks' in the schema cache" }]) {
    assert.match(dbErrorMessage(err), /database needs updating.*supabase db push/);
  }
});

test("other errors keep their own message", () => {
  assert.equal(dbErrorMessage({ code: "42501", message: "permission denied" }), "permission denied");
  assert.equal(dbErrorMessage(new Error("browser storage is full or unavailable")), "browser storage is full or unavailable");
});
