// Browser smoke test of the demo page (demo mode: no sign-in, data in the browser, AI falls back to the offline rules).
// Run with: npm run test:e2e   (locally, PW_CHANNEL=chrome uses the Chrome you already have installed)
import { defineConfig } from "@playwright/test";

const port = Number(process.env.PORT) || 4173;

export default defineConfig({
  testDir: "e2e",
  testMatch: "*.spec.mjs",
  timeout: 30_000,
  fullyParallel: true,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: { baseURL: `http://localhost:${port}`, channel: process.env.PW_CHANNEL || undefined, trace: "retain-on-failure", viewport: { width: 1280, height: 800 } },
  webServer: { command: "node e2e/serve.mjs", url: `http://localhost:${port}/demo/`, reuseExistingServer: !process.env.CI, env: { PORT: String(port) } },
});
