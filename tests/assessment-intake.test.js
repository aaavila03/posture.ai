// Ad-hoc assessment intake questionnaire: the question sets, answer clean-up, routing
// triggers and what the answers fill in on the report.
// Run with: node --test tests/assessment-intake.test.js
import assert from "node:assert/strict";
import test from "node:test";
import { REQUEST_TYPES, ASSESSMENT_TYPES, typeKey, requestTypes, cleanTypes, intakeSections, intakeQuestions, cleanIntakeAnswers, isAnswered, answerText, intakeTriggers, intakePrefill } from "../assessment-intake-questions.js";
import { applyIntake, intakeAnswersHtml, assessmentPrompt, blankAssessment } from "../assessments.js";

const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const all = REQUEST_TYPES.map(([k]) => k);

test("every request gets the common questions, and request types add their own", () => {
  assert.deepEqual(intakeSections([]).map((s) => s.title), ["Request and business need", "Ownership and users", "Product and vendor", "Data", "Deployment",
    "Connectivity and integrations", "Authentication and access", "Dependencies and prior reviews"]);
  assert.equal(intakeQuestions([]).length, 41);
  assert.deepEqual(all, ["macro", "software", "hardware", "ai", "extension", "opensource", "media", "upgrade", "access"]);
  assert.deepEqual(intakeSections(["ai", "macro"]).slice(8).map((s) => s.title), ["Macros and macro-enabled files", "Artificial intelligence"]);
  assert.equal(intakeQuestions(["macro"]).length, 41 + 18);
  assert.equal(intakeQuestions(all).length, 41 + 18 + 17 + 18 + 10 + 11 + 14 + 11 + 10 + 14);
  assert.deepEqual(cleanTypes(["ai", "nope", "ai", 3]), ["ai"]);
  assert.deepEqual(cleanTypes("ai"), []);
});

test("the assessment type decides the question sets, with AI capability adding the AI set", () => {
  assert.deepEqual(ASSESSMENT_TYPES, ["Macros", "Software", "Hardware", "AI", "Browser extension / add-in", "Open-source software", "Removable media",
    "Software upgrade", "Specialized access / configuration", "Other"]);
  for (const [key, label] of REQUEST_TYPES) assert.equal(typeKey(label), key, label);
  assert.equal(typeKey("Other"), "");
  assert.equal(typeKey(""), "");
  assert.equal(typeKey(undefined), "");
  // Types written before the list existed.
  assert.equal(typeKey("Commercial software"), "software");
  assert.equal(typeKey("Custom program – macros"), "macro");
  assert.equal(typeKey("SaaS / cloud service"), "software");
  assert.equal(typeKey("Open-source software"), "opensource");
  assert.equal(typeKey("AI tool assessment"), "ai");
  assert.equal(typeKey("Hardware / device"), "hardware");
  assert.equal(typeKey("Infrastructure assessment"), "");
  assert.deepEqual(requestTypes({ assessmentType: "Software" }), ["software"]);
  assert.deepEqual(requestTypes({ assessmentType: "Software", aiCapability: "Yes" }), ["software", "ai"]);
  assert.deepEqual(requestTypes({ assessmentType: "AI", aiCapability: "Yes" }), ["ai"]);
  assert.deepEqual(requestTypes({ assessmentType: "Other", aiCapability: "No" }), []);
  assert.deepEqual(requestTypes({ aiCapability: "Yes", intakeTypes: ["macro"] }), ["ai"], "a stored list of sets is not used");
  assert.deepEqual(requestTypes(null), []);
  assert.equal(intakeQuestions(requestTypes({ assessmentType: "Macros" })).length, 41 + 18);
});

test("question IDs are unique and stable, and yes/no questions are told apart", () => {
  const questions = intakeQuestions(all);
  assert.equal(new Set(questions.map((q) => q.id)).size, questions.length);
  const byId = Object.fromEntries(questions.map((q) => [q.id, q]));
  assert.equal(byId.RQ1.text, "What technology, product or capability is being requested?");
  assert.equal(byId.RQ1.kind, "text");
  assert.equal(byId.DP4.text, "Does it require administrative privileges?");
  assert.equal(byId.DP4.kind, "yn");
  assert.equal(byId.RQ5.kind, "text", "a choice between options needs a written answer");
  assert.equal(byId.MC15.text, "Will users be required to weaken Microsoft Office macro protections?");
  assert.equal(byId.SA10.kind, "yn");
  assert.ok(questions.every((q) => !/TECO/.test(q.text)), "no company name in the questions");
});

test("only answers to known questions are kept", () => {
  const cleaned = cleanIntakeAnswers({ RQ1: { t: "A tool", a: "Yes", extra: 1 }, DP4: { a: "Yes", t: "  " }, DA3: { a: "Maybe" }, CN1: { a: "No", t: "Offline" },
    ZZ9: { t: "unknown" }, RQ2: "text", __proto__: { t: "x" }, RQ3: { t: "x".repeat(5000) } });
  assert.deepEqual(cleaned.RQ1, { t: "A tool" }, "a written question takes no yes/no");
  assert.deepEqual(cleaned.DP4, { a: "Yes", t: "  " });
  assert.equal(cleaned.DA3, undefined);
  assert.deepEqual(cleaned.CN1, { a: "No", t: "Offline" });
  assert.equal(cleaned.ZZ9, undefined);
  assert.equal(cleaned.RQ2, undefined);
  assert.equal(cleaned.RQ3.t.length, 4000);
  assert.deepEqual(cleanIntakeAnswers(null), {});
  const [rq1, dp4, cn1] = ["RQ1", "DP4", "CN1"].map((id) => intakeQuestions([]).find((q) => q.id === id));
  assert.ok(isAnswered(rq1, cleaned) && isAnswered(dp4, cleaned));
  assert.ok(!isAnswered(dp4, { DP4: { t: "details only" } }), "a yes/no question needs its answer");
  assert.equal(answerText(cn1, cleaned), "No – Offline");
  assert.equal(answerText(rq1, cleaned), "A tool");
});

test("routing triggers come from the yes/no answers and the request type", () => {
  assert.deepEqual(intakeTriggers([], {}), []);
  const t = intakeTriggers(["software"], { DP4: { a: "Yes" }, DA5: { a: "Yes" }, PV4: { a: "No" }, SW7: { a: "Yes" }, CN3: { a: "No" } });
  assert.deepEqual(t.map((x) => x.label), ["External data transfer or storage", "Administrative or privileged access", "Security-control exceptions", "Unsupported or unmaintained technology"]);
  assert.deepEqual(t[1].because, ["Does it require administrative privileges?"]);
  assert.deepEqual(intakeTriggers(["ai"], {}).map((x) => x.label), ["AI processing"]);
  assert.deepEqual(intakeTriggers(["ai"], {})[0].because, ["Request type: AI"]);
  assert.deepEqual(intakeTriggers([], { SW7: { a: "Yes" } }), [], "answers to questions that weren't asked are ignored");
});

test("answers fill in report details", () => {
  const response = { contributor: { name: "Pat Doe" }, answers: { RQ1: { t: "An archive tool" }, RQ2: { t: "Opening supplier files." }, RQ3: { t: "The built-in one can't open 7z." },
    OW3: { t: "250 users" }, PV1: { t: "ZipIt 24.1" }, PV6: { t: "Per-device licence" } } };
  const p = intakePrefill(["ai"], response);
  assert.equal(p.requestor, "Pat Doe");
  assert.equal(p.population, "250 users");
  assert.equal(p.version, "ZipIt 24.1");
  assert.equal(p.licenseType, "Per-device licence");
  assert.equal(p.aiCapability, "Yes");
  assert.equal(p.scope, "What is requested: An archive tool\nBusiness need: Opening supplier files. The built-in one can't open 7z.");
  assert.equal(intakePrefill([], { answers: { OW1: { t: "Sam Lee" } }, contributor: { name: "Pat Doe" } }).requestor, "Sam Lee");
  assert.equal(intakePrefill([], {}).aiCapability, "");
});

test("adding intake answers keeps them with the assessment and fills only blank fields", () => {
  const a = { ...blankAssessment(), solution: "Archive utility", assessmentType: "Software", intakeTypes: ["macro"], population: "40 users", riskOwner: "Dana" };
  const response = { contributor: { name: "Pat Doe", email: "pat@example.test", extra: "x" }, answers: { RQ1: { t: "An archive tool" }, OW3: { t: "250 users" }, PV1: { t: "24.1" }, ZZ1: { t: "x" } }, riskOwner: "injected" };
  const { assessment, filled } = applyIntake(a, response, "2026-11-10T10:00:00Z");
  assert.deepEqual(filled, ["requestor", "version", "scope"]);
  assert.equal(assessment.population, "40 users", "what the analyst entered is kept");
  assert.equal(assessment.requestor, "Pat Doe");
  assert.equal(assessment.version, "24.1");
  assert.equal(assessment.riskOwner, "Dana");
  assert.deepEqual(assessment.intake, { types: ["software"], submittedAt: "2026-11-10T10:00:00Z",
    response: { answers: { RQ1: { t: "An archive tool" }, OW3: { t: "250 users" }, PV1: { t: "24.1" } }, contributor: { name: "Pat Doe", email: "pat@example.test" } } });
  assert.equal(a.intake, undefined, "the original isn't changed");
  assert.ok(assessmentPrompt(assessment).includes("- How many users are expected? 250 users"));
  assert.ok(!assessmentPrompt(a).includes("Intake answers"));
});

test("the analyst's view lists triggers and answered questions, escaped", () => {
  const html = intakeAnswersHtml(["software"], { answers: { RQ1: { t: "<b>Tool</b>" }, DP4: { a: "Yes", t: "For install" } } }, esc);
  for (const s of ["1 escalation or routing trigger to consider", "Administrative or privileged access", "Raised by: Does it require administrative privileges?",
    "2 of 58 questions answered", "Request and business need (1 of 5)", "&lt;b&gt;Tool&lt;/b&gt;", "<dd>Yes – For install</dd>", "Software and applications (0 of 17)"]) assert.ok(html.includes(s), s);
  assert.ok(!html.includes("<b>Tool</b>"));
  assert.ok(!html.includes("Why is the technology needed?"), "unanswered questions are left out");
  assert.ok(intakeAnswersHtml([], { answers: {} }, esc).includes("raise no escalation or routing triggers"));
});
