// Persistence for risks and vendors: browser storage in demo mode, or the
// Supabase database (protected by row-level security) in cloud mode.

// Storage keys keep the original "riskpilot." prefix so existing browser data still loads.
const LOCAL_KEYS = { risks: "riskpilot.risks", vendors: "riskpilot.vendors", briefing: "riskpilot.briefing", people: "riskpilot.people", assessments: "riskpilot.assessments" };

// Fields that may be stored for each record; anything else (e.g. from an
// imported file) is dropped, and strings are length-capped.
const FIELDS = {
  risks: ["id", "title", "description", "memo", "asset", "assetCriticality", "category", "riskGroup", "threatType", "threatSource",
    "dataImpact", "businessImpact", "ticket", "vulnRef", "internalStandard", "nistControls",
    "likelihood", "impact", "residualLikelihood", "residualImpact",
    "treatment", "logException", "exceptionApproved", "controls", "estimatedCost", "remediationProject", "treatmentCompletion", "due",
    "reviewFrequency", "nextReview", "owner", "ownerDepartment", "assetOwner", "delegate", "buDirector", "buVp",
    "complianceAnalyst", "riskAnalyst", "grcManager", "status", "createdBy", "createdDate", "submittedBy", "submittedDate",
    "treatmentBy", "treatmentDate", "approvedBy", "approvedDate", "completedBy", "completedDate",
    "oversightReview", "committeeReview", "committeeNotes", "comments", "created", "updated"],
  vendors: ["id", "name", "service", "owner", "status", "criticality", "dataSensitivity", "access", "lastAssessed", "dataTypes",
    "notes", "answers", "aiAssessment", "intake", "intakeModules", "nercVendor", "cip013Vendor", "created", "updated"],
  assessments: ["id", "solution", "assessmentType", "status", "assetOwner", "riskOwner", "reviewer", "assessmentDate", "outcome",
    "complianceReview", "inherentRisk", "residualRisk", "otImpact", "nercImpact", "topRisks", "topRecommendations",
    "info", "scope", "evidence", "additionalInfo", "solutionOverview", "dataHandling", "dataClasses", "dataClassNotes",
    "businessImpact", "security", "cloud", "cloudChecks", "ai", "ot", "otAnswers", "nerc", "nercAnswers", "dependencies", "dependencyRows",
    "findings", "recommendations", "conditionsRequired", "riskAcceptance", "followUpReview", "determinationComments",
    "conditions", "assumptions", "actions", "approvals", "cloudReview", "aiReview", "otReview", "nercReview", "dependenciesIdentified",
    "summaryComments", "finalStatement", "created", "updated"],
};
const MAX_STRING = 20000;

function clean(value, depth = 0) {
  if (typeof value === "string") return value.slice(0, MAX_STRING);
  if (typeof value === "number") return Number.isFinite(value) ? value : null;
  if (typeof value === "boolean" || value == null) return value ?? null;
  if (depth > 6) return null;
  if (Array.isArray(value)) return value.slice(0, 500).map((v) => clean(v, depth + 1));
  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value).slice(0, 500)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      out[k.slice(0, 100)] = clean(v, depth + 1);
    }
    return out;
  }
  return null;
}

export function sanitizeRecord(kind, record) {
  const out = {};
  for (const f of FIELDS[kind]) if (record?.[f] !== undefined) out[f] = clean(record[f]);
  return out;
}

export const ID_PATTERN = { risks: /^R-\d{3,6}$/, vendors: /^V-\d{3,6}$/, assessments: /^A-\d{3,6}$/ };

export class LocalStore {
  constructor({ safeGet, safeSet }) { Object.assign(this, { safeGet, safeSet }); this.cloud = false; }

  async load() {
    const read = (k) => { try { return JSON.parse(this.safeGet(localStorage, LOCAL_KEYS[k]) || "[]"); } catch { return []; } };
    return { risks: read("risks"), vendors: read("vendors"), assessments: read("assessments") };
  }

  save(kind, list) {
    this.safeSet(localStorage, LOCAL_KEYS[kind], JSON.stringify(list));
    return Promise.resolve();
  }

  async loadBriefing() {
    try { return JSON.parse(this.safeGet(localStorage, LOCAL_KEYS.briefing) || "null"); } catch { return null; }
  }

  async saveBriefing(report) {
    this.safeSet(localStorage, LOCAL_KEYS.briefing, JSON.stringify(report));
  }

  // People directory (see people.js). Demo mode has no members, only the directory.
  async loadPeople() {
    try { return JSON.parse(this.safeGet(localStorage, LOCAL_KEYS.people) || "[]"); } catch { return []; }
  }

  async importPeople(people, replace) {
    const current = replace ? [] : await this.loadPeople();
    const merged = new Map(current.map((p) => [p.email, p]));
    for (const p of people) merged.set(p.email, p);
    this.safeSet(localStorage, LOCAL_KEYS.people, JSON.stringify([...merged.values()]));
    return merged.size;
  }

  async clearPeople() {
    this.safeSet(localStorage, LOCAL_KEYS.people, "[]");
  }

  // Same rules as save_person / delete_person in the schema (the app checks for loops first).
  async savePerson(person, previousEmail) {
    const list = await this.loadPeople();
    const prev = previousEmail || person.email;
    if (prev !== person.email && list.some((p) => p.email === person.email)) throw new Error("someone in the directory already has that email");
    const next = list.filter((p) => p.email !== prev).map((p) => (p.manager_email === prev ? { ...p, manager_email: person.email } : p));
    next.push(person);
    this.safeSet(localStorage, LOCAL_KEYS.people, JSON.stringify(next));
  }

  async deletePerson(email) {
    const list = await this.loadPeople();
    const mgr = list.find((p) => p.email === email)?.manager_email || "";
    const next = list.filter((p) => p.email !== email).map((p) => (p.manager_email === email ? { ...p, manager_email: mgr } : p));
    this.safeSet(localStorage, LOCAL_KEYS.people, JSON.stringify(next));
  }
}

// Saves by diffing against the last state known to match the server, so only
// changed records are written. Saves are queued so they apply in order.
export class CloudStore {
  constructor({ client, orgId, onError }) {
    Object.assign(this, { client, orgId, onError });
    this.cloud = true;
    this.snapshot = { risks: new Map(), vendors: new Map(), assessments: new Map() };
    this.queue = Promise.resolve();
  }

  async load() {
    const out = {};
    for (const kind of ["risks", "vendors", "assessments"]) {
      const { data, error } = await this.client.from(kind).select("display_id, data").eq("org_id", this.orgId).order("display_id");
      if (error) throw error;
      out[kind] = data.map((row) => ({ ...row.data, id: row.display_id }));
      this.snapshot[kind] = new Map(out[kind].map((r) => [r.id, JSON.stringify(sanitizeRecord(kind, r))]));
    }
    return out;
  }

  async loadBriefing() {
    const { data, error } = await this.client.from("briefings").select("report").eq("org_id", this.orgId).maybeSingle();
    if (error) throw error;
    return data?.report ?? null;
  }

  // Vendors' online questionnaire responses: status for every vendor, or one in full.
  async listIntakeResponses() {
    const { data, error } = await this.client.from("intake_responses").select("vendor_ref, status, updated_at, submitted_at").eq("org_id", this.orgId);
    if (error) throw error;
    return data;
  }

  async getIntakeResponse(vendorRef) {
    const { data, error } = await this.client.from("intake_responses").select("response, status, updated_at, submitted_at")
      .eq("org_id", this.orgId).eq("vendor_ref", vendorRef).maybeSingle();
    if (error) throw error;
    return data;
  }

  // Documents the vendor stored with their response; contents only when asked for.
  async getIntakeDocuments(vendorRef, { withData = false } = {}) {
    const { data, error } = await this.client.from("intake_documents")
      .select(withData ? "name, media_type, size, data" : "name, media_type, size")
      .eq("org_id", this.orgId).eq("vendor_ref", vendorRef).order("created_at");
    if (error) throw error;
    return data.map((d) => ({ name: d.name, mediaType: d.media_type, size: d.size, ...(withData ? { data: d.data } : {}) }));
  }

  // The people directory plus the workspace's members (members who aren't in the directory
  // are added from their profiles). Each person has member: true when they use the app.
  async loadPeople() {
    const [people, members, profiles] = await Promise.all([
      this.client.from("people").select("email, first_name, last_name, title, department, phone, manager_email").eq("org_id", this.orgId),
      this.client.from("memberships").select("user_id, email").eq("org_id", this.orgId),
      this.client.from("profiles").select("user_id, first_name, last_name, title, department, phone"),
    ]);
    for (const r of [people, members, profiles]) if (r.error) throw r.error;
    const profile = new Map(profiles.data.map((p) => [p.user_id, p]));
    const memberEmails = new Set(members.data.map((m) => m.email.toLowerCase()));
    const list = people.data.map((p) => ({ ...p, member: memberEmails.has(p.email) }));
    const listed = new Set(list.map((p) => p.email));
    for (const m of members.data) {
      const email = m.email.toLowerCase();
      if (listed.has(email)) continue;
      const p = profile.get(m.user_id);
      const named = p?.first_name || p?.last_name;
      list.push({ email, first_name: named ? p.first_name : email, last_name: named ? p.last_name : "", title: p?.title || "",
        department: p?.department || "", phone: p?.phone || "", manager_email: "", member: true, fromMembers: true });
    }
    return list;
  }

  // Admins only (see import_people in the schema). Returns the directory's new size.
  async importPeople(people, replace) {
    const { data, error } = await this.client.rpc("import_people", { org: this.orgId, rows: people, replace });
    if (error) throw error;
    return data;
  }

  async clearPeople() {
    const { error } = await this.client.rpc("clear_people", { org: this.orgId });
    if (error) throw error;
  }

  async savePerson(person, previousEmail) {
    const { error } = await this.client.rpc("save_person", { org: this.orgId, person, previous_email: previousEmail || null });
    if (error) throw error;
  }

  async deletePerson(email) {
    const { error } = await this.client.rpc("delete_person", { org: this.orgId, person_email: email });
    if (error) throw error;
  }

  // Replaces the workspace's saved briefing (analysts and above; see save_briefing in the schema).
  async saveBriefing(report) {
    const { error } = await this.client.rpc("save_briefing", { org: this.orgId, briefing: report });
    if (error) throw error;
  }

  save(kind, list) {
    const next = new Map(list.map((r) => [r.id, JSON.stringify(sanitizeRecord(kind, r))]));
    this.queue = this.queue.then(() => this.sync(kind, next)).catch((err) => this.onError(err));
    return this.queue;
  }

  async sync(kind, next) {
    const prev = this.snapshot[kind];
    const removed = [...prev.keys()].filter((id) => !next.has(id));
    const added = [...next.keys()].filter((id) => !prev.has(id));
    const changed = [...next.keys()].filter((id) => prev.has(id) && prev.get(id) !== next.get(id));
    const body = (id) => { const { id: _, ...data } = JSON.parse(next.get(id)); return data; };

    if (removed.length) {
      const { error } = await this.client.from(kind).delete().eq("org_id", this.orgId).in("display_id", removed);
      if (error) throw error;
    }
    if (added.length) {
      const rows = added.map((id) => ({ org_id: this.orgId, display_id: id, data: body(id) }));
      const { error } = await this.client.from(kind).insert(rows);
      if (error) throw error;
    }
    for (const id of changed) {
      const { error } = await this.client.from(kind).update({ data: body(id) }).eq("org_id", this.orgId).eq("display_id", id);
      if (error) throw error;
    }
    this.snapshot[kind] = next;
  }
}
