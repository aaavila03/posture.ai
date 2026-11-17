// The /demo page is a copy of index.html whose relative links start at the site
// root (a <base> tag would be blocked by the page's base-uri 'none' policy).
// This test keeps the copy in step with index.html.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = readFileSync(join(root, "index.html"), "utf8");
const demo = readFileSync(join(root, "demo", "index.html"), "utf8");

test("demo page is index.html with root-absolute local links", () => {
  const expected = app.replace(/((?:href|src)=")(?!https?:|#|data:|mailto:|\/)/g, "$1/");
  assert.notEqual(expected, app, "index.html should have relative local links");
  assert.equal(demo, expected);
});
