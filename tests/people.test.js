// People directory: reading import files and walking the reporting lines.
// Run with: node --test tests/people.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { parseCsv, rowsToPeople, directory, fullName, DIRECTOR, VP, TEMPLATE_CSV } from "../people.js";

test("parses quoted CSV cells", () => {
  assert.deepEqual(parseCsv('a,"b, c","say ""hi"""\r\n\n"line\nbreak",x\n'), [["a", "b, c", 'say "hi"'], ["line\nbreak", "x"]]);
});

test("the template imports cleanly", () => {
  const { people, errors } = rowsToPeople(parseCsv(TEMPLATE_CSV));
  assert.equal(errors.length, 0);
  assert.equal(people.length, 3);
  assert.equal(people[2].manager_email, "sam.lee@example.com");
});

test("accepts other headings, full names and managers given by name", () => {
  const { people, errors } = rowsToPeople(parseCsv(
    "Employee Name,Work Email,Job Title,Dept,Reports To\n"
    + "\"Park, Val\",VAL@x.com,Vice President Ops,Ops,\n"
    + "Dee Ray,dee@x.com,Director,Ops,Val Park\n"
    + "Eli Ng,eli@x.com,Analyst,Ops,\"Ray, Dee\"\n"));
  assert.deepEqual(errors, []);
  assert.deepEqual(people.map((p) => [fullName(p), p.email, p.manager_email]), [
    ["Val Park", "val@x.com", ""], ["Dee Ray", "dee@x.com", "val@x.com"], ["Eli Ng", "eli@x.com", "dee@x.com"]]);
});

test("reports bad rows and keeps the good ones", () => {
  const { people, errors } = rowsToPeople(parseCsv(
    "First name,Last name,Email,Phone,Manager email\nA,B,not-an-email,,\n,,c@x.com,,\nD,E,d@x.com,call me,\nF,G,f@x.com,,ghost@x.com\n"));
  assert.deepEqual(people.map((p) => p.email), ["d@x.com", "f@x.com"]);
  assert.equal(people[0].phone, "");
  assert.equal(errors.length, 3);
});

test("needs an email column and a name", () => {
  assert.match(rowsToPeople([["Name"], ["X"]]).errors[0], /Email column/);
  assert.match(rowsToPeople([["Email"], ["x@x.com"]]).errors[0], /Name column/);
});

test("finds the BU director and VP up the chain, and survives loops", () => {
  const d = directory([
    { email: "vp@x", first_name: "Val", last_name: "Park", title: "SVP Technology", manager_email: "ceo@x" },
    { email: "ceo@x", first_name: "Cy", last_name: "Oh", title: "CEO", manager_email: "vp@x" },
    { email: "dir@x", first_name: "Dee", last_name: "Ray", title: "Director, IT", manager_email: "vp@x" },
    { email: "mgr@x", first_name: "Mo", last_name: "Li", title: "Manager", manager_email: "dir@x" },
    { email: "eng@x", first_name: "Eli", last_name: "Ng", title: "Engineer", manager_email: "mgr@x" },
  ]);
  const eli = d.find("eli ng");
  assert.equal(fullName(d.leader(eli, DIRECTOR)), "Dee Ray");
  assert.equal(fullName(d.leader(eli, VP)), "Val Park");
  assert.equal(d.managers(d.find("Val Park")).length, 1);
  assert.deepEqual(d.names, ["Cy Oh", "Dee Ray", "Eli Ng", "Mo Li", "Val Park"]);
});
