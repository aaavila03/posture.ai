// The /demo page is a copy of index.html that only adds a <base> tag, so its
// relative links resolve to the site root. This test keeps the copy in step.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const app = readFileSync(join(root, "index.html"), "utf8");
const demo = readFileSync(join(root, "demo", "index.html"), "utf8");

test("demo page is index.html plus one base tag", () => {
  const expected = app.replace("<head>\n", '<head>\n  <base href="/" />\n');
  assert.notEqual(expected, app, "index.html should contain a <head> line");
  assert.equal(demo, expected);
});
