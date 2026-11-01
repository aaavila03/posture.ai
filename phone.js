// US phone numbers: shown and saved as (555) 010-1000, with an optional extension
// (x123). Numbers that aren't 10 digits (or 11 starting with 1), such as
// international ones, are left as typed.
const EXTENSION = /\s*(?:x|ext\.?|extension)\s*(\d{1,6})\s*$/i;

export function formatPhone(raw) {
  const value = String(raw ?? "").trim();
  if (!value || value.startsWith("+") && !value.startsWith("+1")) return value;
  const ext = value.match(EXTENSION);
  let digits = (ext ? value.slice(0, ext.index) : value).replace(/\D/g, "");
  if (digits.length === 11 && digits[0] === "1") digits = digits.slice(1);
  if (digits.length !== 10) return value;
  return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}${ext ? ` x${ext[1]}` : ""}`;
}

// While typing: (555, (555) 010, (555) 010-1000. Left alone once it looks international
// or has an extension, so those can be typed freely.
export function formatPhoneTyping(raw) {
  const value = String(raw ?? "");
  if (/[+a-z]/i.test(value)) return value;
  let digits = value.replace(/\D/g, "");
  if (digits.length === 11 && digits[0] === "1") digits = digits.slice(1);
  if (!digits || digits.length > 10) return value;
  if (digits.length < 4) return `(${digits}`;
  if (digits.length < 7) return `(${digits.slice(0, 3)}) ${digits.slice(3)}`;
  return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`;
}

// Formats every phone field (input type="tel") on the page as people type and when they leave it.
export function formatPhoneInputs(root = document) {
  root.addEventListener("input", (e) => {
    const el = e.target;
    if (el.type !== "tel" || !e.inputType?.startsWith("insert")) return;
    // Only when typing at the end, so editing the middle of a number isn't disturbed.
    if (el.selectionStart !== el.value.length) return;
    el.value = formatPhoneTyping(el.value);
  });
  root.addEventListener("change", (e) => {
    if (e.target.type === "tel") e.target.value = formatPhone(e.target.value);
  }, true);
}
