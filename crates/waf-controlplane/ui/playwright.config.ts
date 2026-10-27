// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E2E harness for the control-plane SPA. Runs against the REAL backend: two `waf-controlplane`
// binaries (built with `embed-ui`) — one in token mode (governance OFF) and one in session mode
// (governance ON) — both on the same Postgres. Two Playwright projects target the two ports.
//
// Prerequisites (see RUNBOOK §M): a Postgres reachable via WAF_CP_DATABASE_URL, `npm run build`
// (embeds the UI) and `npm run e2e:server` (builds the release binary). `npm run e2e` does all three.

import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";

const dir = path.dirname(fileURLToPath(import.meta.url));

if (!process.env.WAF_CP_DATABASE_URL) {
  throw new Error(
    "E2E requires a Postgres: set WAF_CP_DATABASE_URL (e.g. postgres://postgres:pw@localhost/postgres). See RUNBOOK §M.",
  );
}

const TOKEN_PORT = 9701;
const SESSION_PORT = 9702;

// Non-secret test fixtures (a throwaway DB is assumed — see RUNBOOK §M).
export const API_TOKEN = "e2e-token";
export const ADMIN_USER = "admin";
export const ADMIN_PW = "e2e-adminpw";
const AUDIT_KEY = "0e".repeat(32); // 64 hex chars = a 32-byte Ed25519 seed

const binName = process.platform === "win32" ? "waf-controlplane.exe" : "waf-controlplane";
const binPath = path.resolve(dir, "../../../target/release", binName);
const toml = (f: string) => path.resolve(dir, "tests/e2e", f);

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [["list"], ["html", { open: "never" }]],
  globalSetup: "./tests/e2e/global-setup.ts",
  webServer: [
    {
      command: `"${binPath}" "${toml("token.toml")}"`,
      url: `http://127.0.0.1:${TOKEN_PORT}/healthz`,
      env: { WAF_CP_API_TOKEN: API_TOKEN },
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "pipe",
      stderr: "pipe",
    },
    {
      command: `"${binPath}" "${toml("session.toml")}"`,
      url: `http://127.0.0.1:${SESSION_PORT}/healthz`,
      env: { WAF_CP_AUDIT_KEY: AUDIT_KEY, WAF_CP_BOOTSTRAP_ADMIN_PASSWORD: ADMIN_PW },
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      stdout: "pipe",
      stderr: "pipe",
    },
  ],
  projects: [
    {
      // Governance OFF: the token gate. Runs `*.shared.spec.ts` + `*.token.spec.ts`.
      name: "token",
      testMatch: /\.(shared|token)\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"], channel: undefined, baseURL: `http://127.0.0.1:${TOKEN_PORT}` },
    },
    {
      // Governance ON: username/password + RBAC. Runs `*.shared.spec.ts` + `*.session.spec.ts`.
      name: "session",
      testMatch: /\.(shared|session)\.spec\.ts$/,
      use: { ...devices["Desktop Chrome"], channel: undefined, baseURL: `http://127.0.0.1:${SESSION_PORT}` },
    },
  ],
});
