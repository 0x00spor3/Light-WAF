// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E2 — RBAC: a viewer (`alice`, seeded in global-setup) sees only the read views, none of the admin
// nav, and is blocked by the backend when navigating straight to an admin route. The nav gating is
// cosmetic; the 403 proves the server enforces RBAC regardless.

import { expect, test } from "@playwright/test";

async function loginAsAlice(page: import("@playwright/test").Page): Promise<void> {
  await page.goto("/");
  await page.getByPlaceholder("Username").fill("alice");
  await page.getByPlaceholder("Password").fill("alicepw");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator(".whoami .role-chip")).toHaveText("viewer");
}

test("a viewer sees no admin nav", async ({ page }) => {
  await loginAsAlice(page);
  // Read views are present…
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Account" })).toBeVisible();
  // …admin / operator views are not.
  for (const item of ["Users", "Tokens", "Audit", "Compliance", "Rules"]) {
    await expect(page.getByRole("link", { name: item, exact: true })).toHaveCount(0);
  }
});

test("the backend blocks a viewer from an admin route (403)", async ({ page }) => {
  await loginAsAlice(page);
  // Navigate straight to the admin Users view: the API returns 403, so the data load fails — the view
  // shows a forbidden error instead of the user list (the nav gating above is cosmetic; THIS is the
  // server enforcing RBAC).
  await page.goto("/users");
  const err = page.locator(".state.error");
  await expect(err).toBeVisible();
  await expect(err).toContainText("403");
});
