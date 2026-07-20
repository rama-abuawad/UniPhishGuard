const { defineConfig, devices } = require("@playwright/test");

module.exports = defineConfig({
  testDir: "./tests/e2e",
  timeout: 30000,
  use: {
    baseURL: "https://localhost:8000",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  webServer: {
    command: "powershell.exe -ExecutionPolicy Bypass -File ../backend/run_https.ps1",
    cwd: __dirname,
    url: "https://localhost:8000/health",
    ignoreHTTPSErrors: true,
    reuseExistingServer: true,
    timeout: 20000,
  },
  projects: [
    {
      name: "edge",
      use: {
        ...devices["Desktop Chrome"],
        channel: "msedge",
      },
    },
  ],
});
