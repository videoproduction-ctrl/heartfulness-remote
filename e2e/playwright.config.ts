import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.spec\.ts$/,
  timeout: 90_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  outputDir: "test-results",
  use: {
    headless: true,
    viewport: { width: 1280, height: 800 },
    video: process.env.E2E_VIDEO ? "on" : "retain-on-failure",
    trace: "retain-on-failure",
    launchOptions: {
      args: [
        // Let pion see real host candidates instead of mDNS names in the container.
        "--disable-features=WebRtcHideLocalIpsWithMdns",
        "--autoplay-policy=no-user-gesture-required",
      ],
    },
  },
});
