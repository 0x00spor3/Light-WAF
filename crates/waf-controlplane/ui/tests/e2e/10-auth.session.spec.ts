// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E2 — session mode (governance ON): username/password login rejects bad creds, admits the admin
// (with the right role + admin nav), and logs out. No SSO button when OIDC is not configured.

import { expect, test } from "@playwright/test";
import { ADMIN_PW, ADMIN_USER } from "../../playwright.config";

test("rejects a wrong password, admits the admin, then logs out", async ({ page }) => {
  await page.goto("/");
  const user = page.getByPlaceholder("Username");
  await expect(user).toBeVisible();

  // Wrong password → error, still on the login form.
  await user.fill(ADMIN_USER);
  await page.getByPlaceholder("Password").fill("wrong-password");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText("Invalid credentials.")).toBeVisible();

  // Correct password → dashboard, whoami shows the admin role, admin nav present.
  await page.getByPlaceholder("Password").fill(ADMIN_PW);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible();
  await expect(page.locator(".whoami")).toContainText(ADMIN_USER);
  await expect(page.locator(".whoami .role-chip")).toHaveText("admin");
  await expect(page.getByRole("link", { name: "Users", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Compliance" })).toBeVisible();

  // Logout → back to the login form.
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByPlaceholder("Username")).toBeVisible();
});

test("no SSO button when OIDC is not configured", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByPlaceholder("Username")).toBeVisible();
  await expect(page.getByRole("link", { name: "Sign in with SSO" })).toHaveCount(0);
});
