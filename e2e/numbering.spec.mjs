// Browser test: the risk register's drop-downs read in words, while what is saved, filtered and exported keeps its form.
import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";

test("no numbered choices on screen; saved values, filters and the CSV are unchanged", async ({ page }) => {
  const errors = [];
  page.on("pageerror", (err) => errors.push(err.message));
  page.on("dialog", (dialog) => dialog.accept());
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto("/demo/");
  await page.locator('.tab[data-view="settings"]').click();
  await page.getByRole("button", { name: "Load sample data" }).click();
  await expect(page.locator("#toast")).toContainText("sample");
  await page.locator('.tab[data-view="register"]').click();

  const choices = await page.locator("#risk-form option, #risk-filters option").allTextContents();
  expect(choices).toEqual(expect.arrayContaining(["Rare", "Almost certain", "Very low", "Very high", "Critical", "Identified", "Closed"]));
  expect(choices.filter((c) => /^[1-6]\. /.test(c))).toEqual([]);
  expect(await page.locator('#risk-form select[name="status"] option').evaluateAll((els) => els.map((el) => el.value))).toContain("In treatment");

  // The level filters still match.
  await page.locator('#risk-filters [data-rf="inherent"]').evaluate((el) => { el.value = "4. Critical"; el.dispatchEvent(new Event("change", { bubbles: true })); });
  await expect(page.locator("#risk-table tbody tr").first().locator("button.row-name")).toBeVisible();

  await page.locator("#risk-table button.row-name").first().click();
  await page.locator('[data-rstep="1"]').click();
  // The line under each level names which word is which.
  await expect(page.locator("#risk-form")).toContainText(/Likelihood: (Rare|Unlikely|Possible|Likely|Almost certain) · Impact: (Very low|Low|Medium|High|Very high)/);

  const download = page.waitForEvent("download");
  await page.locator("#btn-export-csv").evaluate((el) => el.click());
  const csv = readFileSync(await (await download).path(), "utf8");
  expect(csv).toMatch(/"[1-6]\. (Identified|Assessment|In treatment|Monitoring|Accepted|Closed)"/);
  expect(csv).toMatch(/"[1-5]\. (Rare|Unlikely|Possible|Likely|Almost certain)"/);
  expect(errors, "no errors on the page").toEqual([]);
});
