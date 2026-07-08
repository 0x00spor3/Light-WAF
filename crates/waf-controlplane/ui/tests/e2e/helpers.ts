// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// Shared login helpers for the E2E specs (not a *.spec.ts, so it is not collected as a test file).

import { expect, type Page } from "@playwright/test";
import { ADMIN_PW, ADMIN_USER, API_TOKEN } from "../../playwright.config";

/** Session mode: sign in as the bootstrap admin and wait for the dashboard. */
export async function loginAdmin(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByPlaceholder("Username").fill(ADMIN_USER);
  await page.getByPlaceholder("Password").fill(ADMIN_PW);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator(".whoami .role-chip")).toHaveText("admin");
}

/** Token mode: enter the API token and wait for the dashboard. */
export async function loginToken(page: Page): Promise<void> {
  await page.goto("/");
  await page.getByPlaceholder("API token").fill(API_TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible();
}
