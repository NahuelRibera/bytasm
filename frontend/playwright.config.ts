import { defineConfig, devices } from "@playwright/test";

// Two real servers serving the built UI (run `vite build` first; `npm run e2e`
// does). Each starts with an empty data directory under frontend/.e2e-data/.
export const FIXTURES_URL = "http://127.0.0.1:8811";
// Test-only: self_built mode, so a test-authored ELF with an HTML-like section
// name can be imported (blueprint 9.2). The default stays fixtures-only.
export const SELF_BUILT_URL = "http://127.0.0.1:8812";

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["list"]],
  use: { ...devices["Desktop Chrome"], trace: "off" },
  webServer: [
    {
      command: "node e2e/start-server.mjs fixtures 8811",
      url: `${FIXTURES_URL}/api/v1/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: "node e2e/start-server.mjs self_built 8812",
      url: `${SELF_BUILT_URL}/api/v1/health`,
      reuseExistingServer: false,
      timeout: 60_000,
    },
  ],
});
