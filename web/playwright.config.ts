import { defineConfig, devices } from "@playwright/test";

// Runs against a live stack (compose.e2e.yaml: Core + web). WEB_URL is where the UI listens.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL: process.env.WEB_URL ?? "http://localhost:3000", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
