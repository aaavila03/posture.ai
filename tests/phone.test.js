import { test } from "node:test";
import assert from "node:assert/strict";
import { formatPhone, formatPhoneTyping } from "../phone.js";

test("US numbers become (555) 010-1000", () => {
  for (const raw of ["5550101000", "555-010-1000", "555.010.1000", "(555)010-1000", "1 555 010 1000", "+1 (555) 010-1000", " 555 010 1000 "]) {
    assert.equal(formatPhone(raw), "(555) 010-1000", raw);
  }
});

test("extensions are kept", () => {
  assert.equal(formatPhone("555-010-1000 ext. 42"), "(555) 010-1000 x42");
  assert.equal(formatPhone("5550101000x7"), "(555) 010-1000 x7");
});

test("other numbers are left as typed", () => {
  assert.equal(formatPhone(""), "");
  assert.equal(formatPhone(null), "");
  assert.equal(formatPhone("+44 20 7946 0000"), "+44 20 7946 0000");
  assert.equal(formatPhone("010-1000"), "010-1000");
});

test("typing fills in the punctuation", () => {
  assert.equal(formatPhoneTyping("5"), "(5");
  assert.equal(formatPhoneTyping("5550"), "(555) 0");
  assert.equal(formatPhoneTyping("(555) 0101"), "(555) 010-1");
  assert.equal(formatPhoneTyping("5550101000"), "(555) 010-1000");
  assert.equal(formatPhoneTyping("+44 20"), "+44 20");
  assert.equal(formatPhoneTyping("(555) 010-1000 x"), "(555) 010-1000 x");
});
