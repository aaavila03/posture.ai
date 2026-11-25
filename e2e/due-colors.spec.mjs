// Browser test: the Due soon panel uses its own colours, none of them a risk level colour, and its text stays readable
// in the light and dark themes.
import { test, expect } from "@playwright/test";

const luminance = ([r, g, b]) => [r, g, b].map((v) => v / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4))
  .reduce((sum, v, i) => sum + v * [0.2126, 0.7152, 0.0722][i], 0);
const contrast = (a, b) => { const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const rgb = (text) => text.match(/\d+/g).slice(0, 3).map(Number);

for (const scheme of ["light", "dark"]) {
  test(`due soon in the ${scheme} theme: no risk level colours, and readable labels`, async ({ page }) => {
    const errors = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("dialog", (dialog) => dialog.accept());
    await page.emulateMedia({ colorScheme: scheme });
    await page.clock.install({ time: new Date("2026-11-25T12:00:00") });
    await page.goto("/demo/");
    await page.locator('.tab[data-view="settings"]').click();
    await page.getByRole("button", { name: "Load sample data" }).click();
    await page.locator('.tab[data-view="dashboard"]').click();
    await expect(page.locator("#due-soon .due-when").first()).toBeVisible();

    const riskColours = await page.evaluate(() => ["--critical", "--high", "--medium", "--low"].map((name) => {
      const probe = document.createElement("span"); probe.style.color = `var(${name})`; document.body.append(probe);
      const colour = getComputedStyle(probe).color; probe.remove(); return colour;
    }));
    const used = await page.locator("#due-soon").evaluate((card) => [...card.querySelectorAll(".due-pin, .due-dot, .due-when, .due-tile-m, .due-filter b, .due-lane, .due-scale span:first-child")]
      .flatMap((el) => { const s = getComputedStyle(el); return [s.backgroundColor, s.color, s.borderTopColor]; }));
    for (const colour of riskColours) expect(used, `no risk colour ${colour}`).not.toContain(colour);

    const labels = await page.locator("#due-soon .due-when, #due-soon .due-tile-m").evaluateAll((els) => els.map((el) => { const s = getComputedStyle(el); return [s.color, s.backgroundColor]; }));
    expect(labels.length).toBeGreaterThan(3);
    for (const [ink, fill] of labels) expect(contrast(rgb(ink), rgb(fill)), `${ink} on ${fill}`).toBeGreaterThanOrEqual(4.5);
    // The overdue colour used as words (the filter count and the timeline's "Overdue") is readable on the panel.
    const words = await page.locator('#due-soon .due-scale span:first-child, #due-soon .due-filter.critical b').evaluateAll((els) => els.map((el) => {
      let behind = el;
      while (getComputedStyle(behind).backgroundColor === "rgba(0, 0, 0, 0)") behind = behind.parentElement;
      return [getComputedStyle(el).color, getComputedStyle(behind).backgroundColor];
    }));
    expect(words.length).toBeGreaterThan(0);
    for (const [ink, fill] of words) expect(contrast(rgb(ink), rgb(fill)), `${ink} on ${fill}`).toBeGreaterThanOrEqual(4.5);
    // The Overdue section is light in both themes, with readable text; the other sections follow the theme.
    const lane = async (key) => page.locator(`#due-soon .due-lane[data-due="${key}"]`).evaluate((el) => ({
      background: getComputedStyle(el).backgroundColor,
      texts: [...el.querySelectorAll("h3, .due-title, .due-id, .due-chip, .due-kind, .due-count")].map((t) => {
        let behind = t;
        while (getComputedStyle(behind).backgroundColor === "rgba(0, 0, 0, 0)") behind = behind.parentElement;
        return [getComputedStyle(t).color, getComputedStyle(behind).backgroundColor];
      }),
    }));
    const overdue = await lane("overdue");
    expect(luminance(rgb(overdue.background)), "overdue is light").toBeGreaterThan(0.85);
    for (const [ink, fill] of overdue.texts) expect(contrast(rgb(ink), rgb(fill)), `${ink} on ${fill}`).toBeGreaterThanOrEqual(4.5);
    const week = await lane("week");
    expect(luminance(rgb(week.background)) > 0.85, "this week follows the theme").toBe(scheme === "light");
    expect(errors).toEqual([]);
  });
}
