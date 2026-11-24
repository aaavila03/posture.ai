// Evidence files on a risk (hosted mode). Run with: node --test tests/risk-evidence.test.js
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { evidenceType, evidenceProblem, evidenceHtml, sizeText, toBase64, extensionOf, EVIDENCE_MAX_BYTES, EVIDENCE_MAX_FILES, EVIDENCE_ACCEPT,
  previewKind, hasThumbnail, textPreview, bytesFromBase64, THUMB_MAX_BYTES, TEXT_PREVIEW_BYTES } from "../risk-evidence.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

test("a file's type comes from its extension, and the browser's type must agree", () => {
  assert.equal(evidenceType({ name: "policy.pdf", type: "application/pdf" }), "application/pdf");
  assert.equal(evidenceType({ name: "POLICY.PDF", type: "" }), "application/pdf");
  assert.equal(evidenceType({ name: "shot.jpg", type: "image/jpeg" }), "image/jpeg");
  assert.equal(evidenceType({ name: "shot.jpeg", type: "image/jpeg" }), "image/jpeg");
  assert.equal(evidenceType({ name: "shot.png", type: "image/png" }), "image/png");
  assert.equal(evidenceType({ name: "notes.txt", type: "text/plain" }), "text/plain");
  // Types that are refused, or that disagree with the extension.
  for (const name of ["page.html", "icon.svg", "macro.xlsm", "report.docx", "run.exe", "noextension", "archive.pdf.exe"]) assert.equal(evidenceType({ name, type: "" }), "", name);
  assert.equal(evidenceType({ name: "shot.png", type: "text/html" }), "");
  assert.equal(evidenceType({ name: "policy.pdf", type: "image/png" }), "");
  assert.equal(extensionOf("a.b.PDF"), "pdf");
});

test("the file picker offers only the allowed extensions", () => {
  assert.equal(EVIDENCE_ACCEPT, ".pdf,.txt,.png,.jpg,.jpeg");
  assert.match(readFileSync(new URL("../index.html", import.meta.url), "utf8"), /id="risk-evidence-file" accept="\.pdf,\.txt,\.png,\.jpg,\.jpeg"/);
});

test("problems are explained before anything is sent", () => {
  const ok = { name: "policy.pdf", size: 1000, type: "application/pdf" };
  assert.equal(evidenceProblem(ok), "");
  assert.match(evidenceProblem({ ...ok, name: "page.html" }), /PDF, a text file or a PNG or JPEG/);
  assert.match(evidenceProblem({ ...ok, size: 0 }), /empty/);
  assert.equal(evidenceProblem({ ...ok, size: EVIDENCE_MAX_BYTES }), "");
  assert.match(evidenceProblem({ ...ok, size: EVIDENCE_MAX_BYTES + 1 }), /over 5 MB/);
  assert.match(evidenceProblem({ ...ok, name: `${"a".repeat(200)}.pdf` }), /name is too long/);
  assert.match(evidenceProblem(ok, ["policy.pdf"]), /already has a file with that name/);
  assert.equal(evidenceProblem(ok, Array.from({ length: EVIDENCE_MAX_FILES - 1 }, (_, i) => `f${i}.pdf`)), "");
  assert.match(evidenceProblem(ok, Array.from({ length: EVIDENCE_MAX_FILES }, (_, i) => `f${i}.pdf`)), /at most 10/);
});

test("sizes read naturally", () => {
  assert.equal(sizeText(512), "512 B");
  assert.equal(sizeText(2048), "2 KB");
  assert.equal(sizeText(5 * 1024 * 1024), "5.0 MB");
});

test("the list shows each file, escapes its name, and offers Remove only to those who can", () => {
  const rows = [{ id: "1", name: "<img src=x onerror=1>.pdf", size: 2048, created_at: "2026-11-24T10:00:00Z" }];
  const html = evidenceHtml(rows, { esc, date: () => "24 Nov 2026" });
  assert.ok(!html.includes("<img"));
  assert.match(html, /&lt;img src=x onerror=1&gt;\.pdf/);
  assert.match(html, /2 KB · added 24 Nov 2026/);
  assert.match(html, /data-evidence-download="1"/);
  assert.ok(!html.includes("data-evidence-remove"));
  assert.match(evidenceHtml(rows, { esc, canRemove: true }), /data-evidence-remove="1"/);
  assert.match(evidenceHtml([], { esc }), /No evidence attached/);
});

test("base64 round trips, including a file bigger than one chunk", () => {
  const bytes = new Uint8Array(100000).map((_, i) => i % 256);
  const encoded = toBase64(bytes.buffer);
  assert.deepEqual(new Uint8Array(Buffer.from(encoded, "base64")), bytes);
  assert.equal(toBase64(new TextEncoder().encode("hello").buffer), "aGVsbG8=");
});

test("the client's limits match the database's", () => {
  const sql = readFileSync(new URL("../supabase/migrations/20261127000000_risk_evidence.sql", import.meta.url), "utf8");
  assert.match(sql, new RegExp(`size between 1 and ${EVIDENCE_MAX_BYTES}`));
  assert.match(sql, new RegExp(`at most ${EVIDENCE_MAX_FILES} evidence files`));
  assert.match(sql, new RegExp(`>= ${EVIDENCE_MAX_FILES} then`));
  for (const type of ["application/pdf", "text/plain", "image/png", "image/jpeg"]) assert.ok(sql.includes(`'${type}'`), type);
  // Nothing else is let in: no SVG, no HTML.
  assert.ok(!sql.includes("svg") && !sql.includes("text/html"));
});

test("the migration lets viewers read and analysts change, and keeps anonymous callers out", () => {
  const sql = readFileSync(new URL("../supabase/migrations/20261127000000_risk_evidence.sql", import.meta.url), "utf8");
  assert.match(sql, /risk_evidence_select[^;]+has_role\(org_id, 'viewer'\)/);
  assert.match(sql, /risk_evidence_insert[^;]+has_role\(org_id, 'analyst'\)/);
  assert.match(sql, /risk_evidence_delete[^;]+has_role\(org_id, 'analyst'\)/);
  assert.match(sql, /revoke all on public\.risk_evidence from anon, authenticated/);
  assert.ok(!/grant[^;]*update[^;]*risk_evidence/i.test(sql), "files cannot be updated");
});

test("each type has its way to preview, and nothing else does", () => {
  assert.equal(previewKind("application/pdf"), "pdf");
  assert.equal(previewKind("image/png"), "image");
  assert.equal(previewKind("image/jpeg"), "image");
  assert.equal(previewKind("text/plain"), "text");
  for (const type of ["text/html", "image/svg+xml", "application/zip", "", undefined]) assert.equal(previewKind(type), "", String(type));
});

test("only an image up to 1 MB has a thumbnail", () => {
  assert.equal(hasThumbnail({ media_type: "image/png", size: THUMB_MAX_BYTES }), true);
  assert.equal(hasThumbnail({ media_type: "image/jpeg", size: 10 }), true);
  assert.equal(hasThumbnail({ media_type: "image/png", size: THUMB_MAX_BYTES + 1 }), false);
  assert.equal(hasThumbnail({ media_type: "application/pdf", size: 10 }), false);
  assert.equal(hasThumbnail({ media_type: "text/plain", size: 10 }), false);
});

test("a text preview is plain text, cut at 100 KB, and says so", () => {
  const short = textPreview(new TextEncoder().encode("hello <b>world</b>\nsecond line"));
  assert.deepEqual(short, { text: "hello <b>world</b>\nsecond line", truncated: false, total: 30 });
  const long = textPreview(new TextEncoder().encode("a".repeat(TEXT_PREVIEW_BYTES + 500)));
  assert.equal(long.truncated, true);
  assert.equal(long.text.length, TEXT_PREVIEW_BYTES);
  assert.equal(long.total, TEXT_PREVIEW_BYTES + 500);
  // A multi-byte character cut in half at the limit is dropped, not shown broken.
  const cut = textPreview(new TextEncoder().encode("ab€"), 4);
  assert.equal(cut.text, "ab");
  assert.equal(cut.truncated, true);
  assert.equal(textPreview(new Uint8Array()).text, "");
});

test("the list has Preview where a file can be previewed, a thumbnail for small images, and escapes names", () => {
  const rows = [
    { id: "i", name: "shot.png", media_type: "image/png", size: 2048, created_at: "2026-11-24T10:00:00Z" },
    { id: "big", name: "big.png", media_type: "image/png", size: THUMB_MAX_BYTES + 1, created_at: "2026-11-24T10:00:00Z" },
    { id: "p", name: "<b>policy</b>.pdf", media_type: "application/pdf", size: 10, created_at: "2026-11-24T10:00:00Z" },
    { id: "x", name: "odd.bin", media_type: "application/zip", size: 10, created_at: "2026-11-24T10:00:00Z" },
  ];
  const html = evidenceHtml(rows, { esc, date: () => "d" });
  assert.match(html, /data-evidence-thumb="i"/);
  assert.ok(!html.includes('data-evidence-thumb="big"'));
  assert.ok(!html.includes('data-evidence-thumb="p"'));
  for (const id of ["i", "big", "p"]) assert.match(html, new RegExp(`data-evidence-preview="${id}"`));
  assert.ok(!html.includes('data-evidence-preview="x"'));
  assert.ok(!html.includes("<b>policy"));
  assert.deepEqual(Array.from(bytesFromBase64("aGVsbG8=")), [104, 101, 108, 108, 111]);
});
