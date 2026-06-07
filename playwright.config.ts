import { defineConfig, devices } from '@playwright/test';

const envWorkers = Number.parseInt(process.env.PLAYWRIGHT_WORKERS ?? '', 10);
const workers = Number.isInteger(envWorkers) && envWorkers > 0 ? envWorkers : undefined;
const isCI = !!process.env.CI;

export default defineConfig({
  testDir: 'e2e',
  timeout: 30 * 1000,
  workers,
  // Fail CI if a `.only` was left in a spec, and retry flaky tests on CI only so
  // local runs surface flakiness instead of hiding it behind retries.
  forbidOnly: isCI,
  retries: isCI ? 2 : 0,
  use: {
    baseURL: process.env.PLAYWRIGHT_BASE_URL ?? 'http://localhost:8080',
    headless: true,
    ignoreHTTPSErrors: process.env.PLAYWRIGHT_IGNORE_HTTPS_ERRORS === 'true',
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
    {
      name: 'firefox',
      use: { ...devices['Desktop Firefox'] },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
});
