// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// E1 smoke: the SPA is served and the public API responds. Runs in BOTH projects (token + session),
// each against its own backend (baseURL), so the whole harness — two binaries, embed-ui, Postgres,
// global-setup — is proven end to end before the auth/RBAC/view specs build on it.

import { expect, test } from "@playwright/test";

test("serves the SPA shell and the public API responds", async ({ page, request }) => {
  await page.goto("/");
  await expect(page).toHaveTitle(/Light WAF/);
  await expect(page.locator("#root")).toBeAttached();

  const res = await request.get("/api/version");
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(typeof body.version).toBe("string");
});

test("exposes the auth-config the UI uses to pick its login flow", async ({ request }) => {
  const res = await request.get("/api/auth/config");
  expect(res.ok()).toBeTruthy();
  const cfg = await res.json();
  expect(typeof cfg.governance).toBe("boolean");
});
