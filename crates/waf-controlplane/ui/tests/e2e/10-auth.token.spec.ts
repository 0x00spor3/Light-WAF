// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E2 — token mode (governance OFF): the bearer-token gate rejects a bad token and admits the real one.

import { expect, test } from "@playwright/test";
import { API_TOKEN } from "../../playwright.config";

test("the token gate rejects a wrong token and admits the real one", async ({ page }) => {
  await page.goto("/");

  // The token prompt is shown (no session, governance off).
  const input = page.getByPlaceholder("API token");
  await expect(input).toBeVisible();

  // A wrong token is rejected and the gate stays.
  await input.fill("definitely-wrong");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByText("Token rejected.")).toBeVisible();
  await expect(input).toBeVisible();

  // The real token admits us → the dashboard nav renders.
  await input.fill(API_TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("link", { name: "Overview" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Events" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Alerts" })).toBeVisible();
  // Governance-only views are not present in token mode.
  await expect(page.getByRole("link", { name: "Users", exact: true })).toHaveCount(0);
});
