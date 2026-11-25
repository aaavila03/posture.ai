// Browser test: "Preview form" in the vendor's intake questionnaire section is as visible as the buttons beside it.
import { test, expect } from "@playwright/test";

test("the Preview form link looks like the buttons beside it and still opens the form in a new tab", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await page.locator('.tab[data-view="vendors"]').click();
  await page.locator("#vendor-table tbody tr").first().locator("button.vendor-name").click();
  const link = page.locator("#intake-preview");
  // The questionnaire section is a later step of the vendor editor.
  const steps = page.locator("#vendor-dialog .vendor-steps button");
  for (let i = 0; i < (await steps.count()) && !(await link.isVisible()); i++) await steps.nth(i).click();
  await expect(link).toBeVisible();

  const look = (selector) => page.locator(selector).evaluate((el) => {
    const s = getComputedStyle(el);
    return { color: s.color, background: s.backgroundColor, border: s.borderTopColor, underline: s.textDecorationLine, height: Math.round(el.getBoundingClientRect().height) };
  });
  const preview = await look("#intake-preview"), neighbour = await look("#btn-intake-link");
  expect(preview).toEqual(neighbour);
  await expect(link).toHaveAttribute("target", "_blank");
  await expect(link).toHaveAttribute("href", /intake\.html$/);
  expect(errors).toEqual([]);
});
