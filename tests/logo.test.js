import { test } from "node:test";
import assert from "node:assert/strict";
import { logoImg } from "../logo.js";

const PNG = "data:image/png;base64,iVBORw0KGgo=";

test("a logo becomes an image tag", () => {
  assert.equal(logoImg(PNG, "rh-logo", "Acme logo"), `<img class="rh-logo" src="${PNG}" alt="Acme logo" />`);
  assert.match(logoImg("data:image/svg+xml;base64,PHN2Zz4=", "x"), /^<img /);
});

test("no logo, or anything that isn't an image data URL, gives nothing", () => {
  for (const bad of [null, "", "https://example.com/logo.png", "javascript:alert(1)", "data:text/html;base64,PHA+",
    `${PNG}" onerror="alert(1)`, "data:image/png;base64,abc def"]) {
    assert.equal(logoImg(bad, "x"), "", String(bad));
  }
});

test("the alt text is escaped", () => {
  assert.match(logoImg(PNG, "x", 'A "quoted" <b>name</b>'), /alt="A &#34;quoted&#34; &#60;b&#62;name&#60;\/b&#62;"/);
});
