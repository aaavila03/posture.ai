// Intake questionnaire for ad-hoc risk assessments: the questions the business answers before
// a risk analyst does the assessment. They come from the intake question categories of the
// Ad Hoc Cyber Risk Assessment procedure: a common set asked for every request, plus sets the
// analyst adds for the type of request. Shared by the app and the page the business opens
// from a link (assessment-intake.html).
//
// A question is its text, or [text, "text"] where a question that reads like a yes/no one
// needs a written answer. Question IDs are the section code plus the position (RQ1, RQ2…), and
// answers are stored by ID, so add new questions at the end of a section and never reorder.

const COMMON = [
  ["RQ", "Request and business need", [
    "What technology, product or capability is being requested?",
    "What business problem or process does it support?",
    "Why is the technology needed?",
    "Is an existing approved solution available?",
    ["Is the request temporary, pilot, limited or ongoing?", "text"],
  ]],
  ["OW", "Ownership and users", [
    "Who is the requester?",
    "Who is the business owner?",
    "How many users are expected?",
    "Which business areas will use the solution?",
    ["Are users internal, external, privileged or third-party?", "text"],
  ]],
  ["PV", "Product and vendor", [
    "What is the product and version?",
    "Who is the vendor or developer?",
    "Where will the product be obtained?",
    "Is the product commercially supported?",
    "How are updates and patches provided?",
    "What licensing or subscription is required?",
  ]],
  ["DA", "Data", [
    "What company information will be accessed, processed, stored or transmitted?",
    "What is the expected data classification?",
    "Will sensitive, confidential, regulated or operational information be used?",
    "Where will information be stored?",
    "Will data leave the company environment?",
    "Are files or results shared with external parties?",
  ]],
  ["DP", "Deployment", [
    "How will the technology be installed or accessed?",
    ["Is installation local, server-based, cloud-based or browser-based?", "text"],
    "Who will install and support it?",
    "Does it require administrative privileges?",
    "Does it require changes to standard security settings?",
  ]],
  ["CN", "Connectivity and integrations", [
    "Does the technology require internet connectivity?",
    "Does it connect to external services?",
    "Does it integrate with company systems?",
    "Does it use APIs, databases, file shares, email or automated imports/exports?",
    "Are network, firewall or proxy changes required?",
  ]],
  ["AU", "Authentication and access", [
    "How do users authenticate?",
    "Is single sign-on supported?",
    "Is multifactor authentication available?",
    "What permissions are required?",
    "How will access be approved, reviewed and removed?",
  ]],
  ["DR", "Dependencies and prior reviews", [
    "Are Procurement, Legal, Privacy, Architecture or another control function involved?",
    "Has the product or vendor previously been assessed?",
    "Are there existing approvals or documented exceptions?",
    "Are technical SMEs required?",
  ]],
];

// Added by request type: [key, code, label on the picker, section heading, questions].
const BY_TYPE = [
  ["macro", "MC", "Macros", "Macros and macro-enabled files", [
    "Which workbook or file requires macro functionality?",
    "What business process does the macro support?",
    "Why is the macro necessary?",
    "Is a non-macro alternative available?",
    "Who developed the macro?",
    "Where was the macro obtained?",
    "Has the code been reviewed or tested?",
    "What users and business areas will use it?",
    "What data will the macro access or modify?",
    "Does it import or export data?",
    "Does it connect to databases, APIs, websites, email or external systems?",
    "Does it write files to local, network or cloud locations?",
    "Will the macro be digitally signed?",
    "How will the workbook be distributed and updated?",
    "Will users be required to weaken Microsoft Office macro protections?",
    ["Is the use temporary, pilot, legacy or ongoing?", "text"],
    "What is the business impact if macro functionality is not enabled?",
    "What changes would require reassessment?",
  ]],
  ["software", "SW", "Software", "Software and applications", [
    "What software and version are requested?",
    "What operating systems are supported?",
    "Where will the software be downloaded from?",
    "Is the publisher and installer trusted?",
    "Does the software require local administrator privileges?",
    "Does it install services, drivers, extensions or background processes?",
    "Does it require exceptions to endpoint security controls?",
    "What data does the software access or create?",
    "Does the software transmit telemetry or other data externally?",
    "Does it connect to cloud services, databases, APIs or third-party systems?",
    "How are vulnerabilities, patches and version updates handled?",
    "Is vendor support available?",
    "Does the software support logging?",
    "How will access and licensing be managed?",
    "What is the intended user population?",
    "Is packaging or deployment support required?",
    "What future changes would materially alter the assessed risk?",
  ]],
  ["hardware", "HW", "Hardware", "Hardware and connected devices", [
    "What device and model are requested?",
    "What business function does the device perform?",
    "Where will the device be installed?",
    ["Is it connected by USB, wired network, Wi-Fi, Bluetooth or another method?", "text"],
    "Does the device store or process company data?",
    "Does it require software, drivers or management tools?",
    "Does it have firmware?",
    "How are software and firmware updated?",
    "Does it expose administrative or management interfaces?",
    "Does it require vendor remote access?",
    "Does it connect to cloud or external services?",
    "What authentication options are available?",
    "What logging and monitoring are supported?",
    "Who will administer and support the device?",
    "What physical security controls apply?",
    "How will data be retained, transferred and destroyed?",
    "What is the operational impact if the device is unavailable?",
    "What future changes would require reassessment?",
  ]],
  ["ai", "AI", "AI", "Artificial intelligence", [
    "Will prompts, files, source code, customer data, employee data, or other internal information be submitted to the solution?",
    "Does the provider use submitted content to train, improve, or otherwise develop its models?",
    "Can model training and content retention be disabled or otherwise controlled?",
    "What administrative, access, retention, and data-segregation controls are available?",
    "Where is submitted information processed and stored?",
    "Are outputs reviewed by an appropriate person before being used for business purposes?",
    "Will AI-generated outputs support employment, financial, safety, regulatory, or other consequential business decisions?",
    "Does the solution integrate with company systems, applications, repositories, or data sources?",
    ["Is the request for individual use, a limited pilot, or broader deployment?", "text"],
    "Are additional Privacy, Legal, Compliance, Records Management, or other reviews required based on the proposed use?",
  ]],
  ["extension", "EX", "Browser extension / add-in", "Browser extensions and add-ins", [
    "What browser or application does the extension/add-in modify?",
    "Where is it obtained, and who is the publisher?",
    "What permissions does it request?",
    "Can it read or modify webpage, email, document or clipboard content?",
    "Does it transmit data externally?",
    ["Does it require access to all websites or only specified domains?", "text"],
    "Is it centrally deployable and manageable?",
    "How are updates delivered?",
    "Can use be limited to approved users?",
    "Does it integrate with Microsoft 365 or other company systems?",
    "What happens if the extension/add-in is compromised or removed?",
  ]],
  ["opensource", "OS", "Open-source software", "Open-source software", [
    "What open-source package, component and version are requested?",
    "What repository or distribution source will be used?",
    "Who maintains the component?",
    "How active is the project?",
    "When was the latest supported release?",
    "Are known vulnerabilities present?",
    "What license applies?",
    "Are there legal or redistribution obligations?",
    "Will the package be modified?",
    "What dependencies are introduced?",
    "Who will monitor vulnerabilities and updates?",
    "Is a software bill of materials available?",
    ["Is the component used in development, production or an operationally critical system?", "text"],
    "What is the replacement or removal plan if maintenance stops?",
  ]],
  ["media", "RM", "Removable media", "Removable media", [
    "What business need requires removable media?",
    "What type of media is requested?",
    "What data will be stored or transferred?",
    "Is encryption available and required?",
    "Is the media company-owned and inventoried?",
    "Which devices will read or write to it?",
    "Is external or third-party use involved?",
    "How will malware scanning occur?",
    "How will use be restricted to authorized users?",
    "What retention and secure-disposal requirements apply?",
    "Can an approved secure transfer method meet the need instead?",
  ]],
  ["upgrade", "UP", "Software upgrade", "Software upgrade", [
    "What product and versions are involved?",
    "Is the current version unsupported or approaching end of support?",
    "What security vulnerabilities does the upgrade address?",
    "Does the upgrade change hosting, connectivity, authentication or data handling?",
    "Are new cloud services, integrations or telemetry introduced?",
    "Does the vendor require new permissions or infrastructure?",
    "Has compatibility and regression testing been completed?",
    "Is there a rollback plan?",
    "Does the upgrade materially change the previously assessed use?",
    "Is a new vendor, Privacy, Architecture or other specialized review required?",
  ]],
  ["access", "SA", "Specialized access / configuration", "Specialized access and configuration", [
    "What access, privilege, configuration change, or exception is being requested?",
    "What business activity requires the requested access or change?",
    "Who requires the access and how many users are affected?",
    "Which systems, applications, endpoints, or environments are affected?",
    "Is elevated or administrative access required?",
    "Can the business need be met using a lower level of privilege?",
    ["Is the access permanent, temporary, or time-bound?", "text"],
    "How will access be approved, provisioned, reviewed, and removed?",
    "What authentication controls apply, including MFA where applicable?",
    "Will existing security controls need to be disabled, bypassed, or weakened?",
    "What compensating controls are available?",
    "What logging and monitoring will apply?",
    "What is the impact if the requested access or configuration is misused or compromised?",
    "What changes would require reassessment?",
  ]],
];

export const YES_NO = ["Yes", "No", "Not sure"];
// The request types that have their own question set: [key, label].
export const REQUEST_TYPES = BY_TYPE.map(([key, , label]) => [key, label]);
const TYPE_KEYS = new Set(REQUEST_TYPES.map(([k]) => k));
export const cleanTypes = (types) => (Array.isArray(types) ? [...new Set(types.filter((t) => TYPE_KEYS.has(t)))] : []);

// An assessment's type is one of the request types, or "Other" for a request that fits none
// of them and gets the common questions only.
export const OTHER_TYPE = "Other";
export const ASSESSMENT_TYPES = [...REQUEST_TYPES.map(([, label]) => label), OTHER_TYPE];
// Types written before the list existed ("Commercial software", "Custom program – macros"…)
// are matched by what they mention, most specific first.
const TYPE_WORDS = [["macro", /macro/i], ["extension", /extension|add-?in|plug-?in/i], ["opensource", /open[- ]?source/i], ["media", /removable|usb (drive|stick|media)/i],
  ["upgrade", /upgrade/i], ["access", /access|privilege|configuration|exception/i], ["hardware", /hardware|device|printer|scanner/i], ["ai", /\bAI\b|artificial intelligence/],
  ["software", /software|application|program|saas|cloud|freeware|utility/i]];
export function typeKey(label) {
  const text = String(label || "").trim();
  const exact = REQUEST_TYPES.find(([, l]) => l.toLowerCase() === text.toLowerCase());
  return exact ? exact[0] : text ? TYPE_WORDS.find(([, words]) => words.test(text))?.[0] || "" : "";
}
// The question sets an assessment's intake questionnaire uses: the one for its assessment
// type, plus the AI set when it has AI capability.
export function requestTypes(assessment) {
  return cleanTypes([typeKey(assessment?.assessmentType), assessment?.aiCapability === "Yes" ? "ai" : ""]);
}

const YES_NO_START = /^(Is|Are|Does|Do|Will|Has|Have|Can)\b/;
const build = (code, title, questions, type = null) => ({ code, title, type,
  questions: questions.map((q, i) => {
    const [text, kind] = Array.isArray(q) ? q : [q, YES_NO_START.test(q) ? "yn" : "text"];
    return { id: `${code}${i + 1}`, text, kind };
  }) });
const COMMON_SECTIONS = COMMON.map(([code, title, questions]) => build(code, title, questions));
const TYPE_SECTIONS = BY_TYPE.map(([key, code, , title, questions]) => build(code, title, questions, key));

// The sections of a questionnaire: the common ones, then one for each request type chosen.
export function intakeSections(types) {
  const chosen = cleanTypes(types);
  return [...COMMON_SECTIONS, ...TYPE_SECTIONS.filter((s) => chosen.includes(s.type))];
}
export const intakeQuestions = (types) => intakeSections(types).flatMap((s) => s.questions);
const EVERY_QUESTION = new Map([...COMMON_SECTIONS, ...TYPE_SECTIONS].flatMap((s) => s.questions).map((q) => [q.id, q]));

const MAX_TEXT = 4000;
const short = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
// Keeps only answers to known questions: { a: "Yes" | "No" | "Not sure", t: written answer }.
export function cleanIntakeAnswers(answers) {
  const out = {};
  if (!answers || typeof answers !== "object") return out;
  for (const [id, q] of EVERY_QUESTION) {
    const given = answers[id];
    if (!given || typeof given !== "object") continue;
    const a = q.kind === "yn" && YES_NO.includes(given.a) ? given.a : "", t = short(given.t, MAX_TEXT);
    if (a || t.trim()) out[id] = { ...(a ? { a } : {}), ...(t ? { t } : {}) };
  }
  return out;
}
export const isAnswered = (question, answers) => {
  const given = answers?.[question.id];
  return question.kind === "yn" ? !!given?.a : !!given?.t?.trim();
};
export const answerText = (question, answers) => {
  const given = answers?.[question.id] || {};
  return [question.kind === "yn" ? given.a : "", given.t?.trim()].filter(Boolean).join(" – ");
};

// Escalation and routing triggers for the analyst to consider, worked out from the yes/no
// answers: [trigger, what it means, answers that raise it as [question ID, answer], request
// types that raise it]. A trigger doesn't stop the assessment: the analyst decides the path.
const TRIGGERS = [
  ["Sensitive or regulated data", "The solution will access, process, store or transmit sensitive, confidential, regulated or operational information.",
    [["DA3", "Yes"], ["AI1", "Yes"]]],
  ["External data transfer or storage", "Company information will be sent to, processed by or stored with an external party or service.",
    [["DA5", "Yes"], ["DA6", "Yes"], ["SW9", "Yes"], ["EX5", "Yes"], ["RM7", "Yes"]]],
  ["Administrative or privileged access", "The solution needs elevated privileges, administrator access or other privileged permissions.",
    [["DP4", "Yes"], ["SW5", "Yes"], ["SA5", "Yes"]]],
  ["Security-control exceptions", "An existing security control would be disabled, bypassed, weakened or excepted.",
    [["DP5", "Yes"], ["SW7", "Yes"], ["MC15", "Yes"], ["SA10", "Yes"]]],
  ["External connectivity or exposure", "The solution introduces external connectivity, remote administration, externally reachable interfaces or network changes.",
    [["CN2", "Yes"], ["CN5", "Yes"], ["SW10", "Yes"], ["HW9", "Yes"], ["HW10", "Yes"], ["HW11", "Yes"], ["MC11", "Yes"]]],
  ["Unsupported or unmaintained technology", "The product or a component is unsupported, end-of-life or has no adequate way to receive security updates.",
    [["PV4", "No"], ["SW12", "No"], ["OS6", "Yes"]]],
  ["Significant integrations", "The solution integrates with company systems, repositories or other sensitive environments.",
    [["CN3", "Yes"], ["AI8", "Yes"], ["EX10", "Yes"]]],
  ["AI processing", "AI capabilities will process business information, or the use may need Privacy, Legal, Compliance or Records Management review.",
    [["AI2", "Yes"], ["AI7", "Yes"]], ["ai"]],
  ["Privacy, Legal, Compliance, Procurement, Architecture or other governance", "The request falls within another control function's area of responsibility.",
    [["DR1", "Yes"], ["AI10", "Yes"], ["UP10", "Yes"], ["OS8", "Yes"]]],
  ["Material change to a previously assessed use", "The users, data, connectivity, functionality or business use differs materially from what was assessed before.",
    [["UP4", "Yes"], ["UP5", "Yes"], ["UP9", "Yes"]]],
];
// The triggers raised by a set of answers, each with the questions that raised it.
export function intakeTriggers(types, answers) {
  const chosen = cleanTypes(types), asked = new Map(intakeQuestions(chosen).map((q) => [q.id, q]));
  return TRIGGERS.map(([label, meaning, raisedBy, byType = []]) => {
    const because = raisedBy.filter(([id, value]) => asked.has(id) && answers?.[id]?.a === value).map(([id]) => asked.get(id).text);
    for (const [key, name] of REQUEST_TYPES) if (byType.includes(key) && chosen.includes(key)) because.unshift(`Request type: ${name}`);
    return because.length ? { label, meaning, because } : null;
  }).filter(Boolean);
}

// Report fields the answers can fill in: each is filled only where the analyst left it blank.
export function intakePrefill(types, response) {
  const answers = response?.answers || {};
  const t = (id) => answers[id]?.t?.trim() || "";
  const scope = [["What is requested", t("RQ1")], ["Business need", [t("RQ2"), t("RQ3")].filter(Boolean).join(" ")], ["Duration", t("RQ5")],
    ["Business owner", t("OW2")], ["Business areas", t("OW4")]].filter(([, v]) => v).map(([label, v]) => `${label}: ${v}`).join("\n");
  return {
    requestor: t("OW1") || response?.contributor?.name?.trim() || "", population: t("OW3"), version: t("PV1"), licenseType: t("PV6"),
    scope, aiCapability: cleanTypes(types).includes("ai") ? "Yes" : "",
  };
}
