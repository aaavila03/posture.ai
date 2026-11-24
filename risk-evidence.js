// Evidence files on a risk (hosted mode): a PDF, a text file or a PNG/JPEG image. The database checks every file again
// (type, size, count and that the content matches its type), so these checks are to give a clear message before sending.

export const EVIDENCE_MAX_BYTES = 5 * 1024 * 1024;
export const EVIDENCE_MAX_FILES = 10;

// Allowed types, by file extension. A file's type is taken from its extension, and the browser's own type
// for it must agree (a blank type is allowed, since browsers don't always know one).
const TYPES = { pdf: ["application/pdf"], txt: ["text/plain"], png: ["image/png"], jpg: ["image/jpeg"], jpeg: ["image/jpeg"] };
export const EVIDENCE_ACCEPT = ".pdf,.txt,.png,.jpg,.jpeg";

export const extensionOf = (name) => (String(name).match(/\.([A-Za-z0-9]+)$/)?.[1] || "").toLowerCase();

// The media type to store for a file, or "" if the file isn't an allowed type.
export function evidenceType({ name, type }) {
  const allowed = TYPES[extensionOf(name)];
  if (!allowed) return "";
  return !type || allowed.includes(type) ? allowed[0] : "";
}

// Why a file can't be added, or "" if it can. `existing` is the names already on the risk.
export function evidenceProblem({ name, size, type }, existing = []) {
  if (!evidenceType({ name, type })) return "Evidence can be a PDF, a text file or a PNG or JPEG image.";
  if (!(size > 0)) return "That file is empty.";
  if (size > EVIDENCE_MAX_BYTES) return `That file is over ${EVIDENCE_MAX_BYTES / 1024 / 1024} MB.`;
  if (String(name).length > 200) return "That file's name is too long (200 characters at most).";
  if (existing.length >= EVIDENCE_MAX_FILES) return `A risk can have at most ${EVIDENCE_MAX_FILES} evidence files.`;
  if (existing.includes(name)) return "This risk already has a file with that name. Remove it first to replace it.";
  return "";
}

export const sizeText = (bytes) => (bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : bytes >= 1024 ? `${Math.round(bytes / 1024)} KB` : `${bytes} B`);

// One evidence row (name, type, size, date) as a list item with Download and, if allowed, Remove.
export function evidenceHtml(rows, { esc, canRemove = false, date = (at) => new Date(at).toLocaleDateString() }) {
  if (!rows?.length) return '<li class="muted small">No evidence attached.</li>';
  return rows.map((r) => `<li class="evidence-row"><div><strong>${esc(r.name)}</strong>
      <div class="small muted">${esc(sizeText(r.size))} · added ${esc(date(r.created_at))}</div></div>
      <div class="evidence-actions"><button type="button" class="small" data-evidence-download="${esc(r.id)}">Download</button>
      ${canRemove ? `<button type="button" class="small danger" data-evidence-remove="${esc(r.id)}">Remove</button>` : ""}</div></li>`).join("");
}

// Base64 of a file's bytes, for sending to the database.
export function toBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

// A downloadable file from stored base64 and its type.
export function fromBase64(data, type) {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type });
}
