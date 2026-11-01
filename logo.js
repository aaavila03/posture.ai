// The organisation's own logo: uploaded under Settings, shown in the top bar, on the
// dashboard, on the executive briefing, on assessment PDFs and on vendor questionnaires.
// Saved as a small data URL; raster images are scaled down in the browser first.
export const LOGO_TYPES = ["image/png", "image/jpeg", "image/webp", "image/svg+xml"];
const MAX_W = 640, MAX_H = 240;
const MAX_SVG = 150_000;
export const LOGO_PATTERN = /^data:image\/(png|jpeg|webp|svg\+xml);base64,[A-Za-z0-9+/]+={0,2}$/;

const readDataUrl = (file) => new Promise((resolve, reject) => {
  const r = new FileReader();
  r.onload = () => resolve(r.result);
  r.onerror = () => reject(new Error("couldn't read the file"));
  r.readAsDataURL(file);
});

export async function prepareLogo(file) {
  if (!LOGO_TYPES.includes(file.type)) throw new Error("choose a PNG, JPG, WebP or SVG image");
  if (file.type === "image/svg+xml") {
    if (file.size > MAX_SVG) throw new Error("SVG logos must be under 150 KB");
    const url = await readDataUrl(file);
    if (!LOGO_PATTERN.test(url)) throw new Error("couldn't read the SVG");
    return url;
  }
  if (file.size > 10_000_000) throw new Error("images must be under 10 MB");
  const img = new Image();
  img.src = await readDataUrl(file);
  await img.decode().catch(() => { throw new Error("couldn't open the image"); });
  const scale = Math.min(1, MAX_W / img.naturalWidth, MAX_H / img.naturalHeight);
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(img.naturalWidth * scale));
  canvas.height = Math.max(1, Math.round(img.naturalHeight * scale));
  canvas.getContext("2d").drawImage(img, 0, 0, canvas.width, canvas.height);
  // PNG keeps transparency; photos are smaller as JPEG.
  const png = canvas.toDataURL("image/png");
  return png.length <= 280_000 || file.type === "image/png" && png.length <= 300_000 ? png : canvas.toDataURL("image/jpeg", 0.9);
}

// An <img> for the logo, or "" when there is none (or it isn't a safe image data URL).
export const logoImg = (logo, cls, alt = "") => (logo && LOGO_PATTERN.test(logo)
  ? `<img class="${cls}" src="${logo}" alt="${String(alt).replace(/[&<>"]/g, (c) => `&#${c.charCodeAt(0)};`)}" />` : "");
