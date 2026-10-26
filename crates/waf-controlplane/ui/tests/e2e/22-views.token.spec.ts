// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E3 — token mode: the views available without governance (Overview / Events / Alerts / Rules) render.

import { expect, test } from "@playwright/test";
import { loginToken } from "./helpers";

test("token-mode views render", async ({ page }) => {
  await loginToken(page);

  await expect(page.getByRole("heading", { name: "Decision volumes" })).toBeVisible();

  await page.getByRole("link", { name: "Events", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Denied requests" })).toBeVisible();

  await page.getByRole("link", { name: "Alerts", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Fired alerts" })).toBeVisible();

  await page.getByRole("link", { name: "Rules", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Publish a ruleset version" })).toBeVisible();
});
