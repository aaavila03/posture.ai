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

// How a file is previewed: images and text open in a dialog in the app, and a PDF opens in the browser's own viewer in a
// new tab. Nothing uploaded is ever put into the page as markup.
export const THUMB_MAX_BYTES = 1024 * 1024;
export const TEXT_PREVIEW_BYTES = 100 * 1024;
export const previewKind = (type) => (type === "application/pdf" ? "pdf" : type === "image/png" || type === "image/jpeg" ? "image" : type === "text/plain" ? "text" : "");
export const hasThumbnail = (row) => previewKind(row.media_type) === "image" && row.size <= THUMB_MAX_BYTES;

// The first part of a text file for the preview, as plain text. `truncated` is whether the rest is not shown.
export function textPreview(bytes, limit = TEXT_PREVIEW_BYTES) {
  const truncated = bytes.length > limit;
  let text = new TextDecoder("utf-8").decode(truncated ? bytes.subarray(0, limit) : bytes);
  // Cutting in the middle of a character leaves one broken character at the end.
  if (truncated) text = text.replace(/\uFFFD$/, "");
  return { text, truncated, total: bytes.length };
}

// One evidence row (name, size, date) as a list item with Preview, Download and, if allowed, Remove. An image small enough
// has a thumbnail, which the page fills in once the file is fetched.
export function evidenceHtml(rows, { esc, canRemove = false, date = (at) => new Date(at).toLocaleDateString() }) {
  if (!rows?.length) return '<li class="muted small">No evidence attached.</li>';
  return rows.map((r) => `<li class="evidence-row">
      ${hasThumbnail(r) ? `<img class="evidence-thumb" data-evidence-thumb="${esc(r.id)}" alt="Preview of ${esc(r.name)}" hidden />` : ""}
      <div class="evidence-name"><strong>${esc(r.name)}</strong>
      <div class="small muted">${esc(sizeText(r.size))} · added ${esc(date(r.created_at))}</div></div>
      <div class="evidence-actions">${previewKind(r.media_type) ? `<button type="button" class="small" data-evidence-preview="${esc(r.id)}">Preview</button>` : ""}<button type="button" class="small" data-evidence-download="${esc(r.id)}">Download</button>
      ${canRemove ? `<button type="button" class="small danger" data-evidence-remove="${esc(r.id)}">Remove</button>` : ""}</div></li>`).join("");
}

// Base64 of a file's bytes, for sending to the database.
export function toBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

// The bytes of a file from its stored base64.
export function bytesFromBase64(data) {
  const binary = atob(data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// A downloadable or viewable file from stored base64 and its type.
export const fromBase64 = (data, type) => new Blob([bytesFromBase64(data)], { type });

// Previews a file. An image or text opens in the preview dialog (text as plain text, never as markup); a PDF opens in the
// browser's own viewer in a new tab. The tab is opened straight from the click, before the file is fetched, so the
// browser's pop-up blocker allows it. `getFile(id)` returns { name, media_type, data } (base64). Returns preview(row).
export function initEvidencePreview({ $, getFile, toast, openTab = (...args) => window.open(...args) }) {
  const dialog = $("#evidence-preview-dialog"), image = $("#evidence-preview-image"), text = $("#evidence-preview-text"), note = $("#evidence-preview-note");
  let url = "";
  const close = () => { if (dialog.open) dialog.close(); };
  dialog.addEventListener("close", () => {
    if (url) URL.revokeObjectURL(url);
    url = "";
    image.removeAttribute("src");
    text.textContent = "";
  });
  $("#btn-evidence-preview-close").addEventListener("click", close);
  dialog.addEventListener("click", (e) => { if (e.target === dialog) close(); });

  return async function preview(row) {
    const kind = previewKind(row.media_type);
    if (kind === "pdf") {
      const tab = openTab("", "_blank");
      if (!tab) return toast("Allow pop-ups to preview PDFs, or use Download.", true);
      tab.opener = null;
      try {
        const file = await getFile(row.id);
        const pdfUrl = URL.createObjectURL(fromBase64(file.data, file.media_type));
        tab.location.href = pdfUrl;
        setTimeout(() => URL.revokeObjectURL(pdfUrl), 5 * 60 * 1000);
      } catch (err) {
        tab.close();
        throw err;
      }
      return;
    }
    if (!kind) return;
    const file = await getFile(row.id);
    $("#evidence-preview-title").textContent = row.name;
    image.classList.toggle("hidden", kind !== "image");
    text.classList.toggle("hidden", kind !== "text");
    note.classList.add("hidden");
    if (kind === "image") {
      url = URL.createObjectURL(fromBase64(file.data, file.media_type));
      image.src = url;
      image.alt = row.name;
    } else {
      const { text: shown, truncated, total } = textPreview(bytesFromBase64(file.data));
      text.textContent = shown;
      if (truncated) {
        note.textContent = `Showing the first ${Math.round(new TextEncoder().encode(shown).length / 1024)} KB of ${Math.round(total / 1024)} KB. Download the file to read the rest.`;
        note.classList.remove("hidden");
      }
    }
    dialog.showModal();
  };
}
