// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// E3 — session mode (admin): every view renders, the Events drill-down reconstructs a verdict, and
// the signed audit chain verifies.

import { expect, test } from "@playwright/test";
import { loginAdmin } from "./helpers";

test.beforeEach(async ({ page }) => {
  await loginAdmin(page);
});

// (nav link text → a heading unique to that view).
const VIEWS: [string, string][] = [
  ["Events", "Denied requests"],
  ["Alerts", "Fired alerts"],
  ["Rules", "Publish a ruleset version"],
  ["Users", "Users"],
  ["Tokens", "Service tokens"],
  ["Audit", "Audit log"],
  ["Compliance", "Compliance report"],
  ["Account", "Change password"],
];

test("every view renders from the nav", async ({ page }) => {
  // Overview is the landing view.
  await expect(page.getByRole("heading", { name: "Decision volumes" })).toBeVisible();
  for (const [nav, heading] of VIEWS) {
    await page.getByRole("link", { name: nav, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading })).toBeVisible();
  }
});

test("the Events drill-down shows the verdict + score breakdown", async ({ page }) => {
  await page.getByRole("link", { name: "Events", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Denied requests" })).toBeVisible();

  const firstRow = page.locator("table.rows-hover tbody tr.clickable").first();
  await expect(firstRow).toBeVisible(); // seeded in global-setup
  await firstRow.click();

  await expect(page).toHaveURL(/\/events\/.+/);
  await expect(page.getByRole("heading", { name: "Verdict" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Score breakdown" })).toBeVisible();
});

test("the audit chain verifies", async ({ page }) => {
  await page.getByRole("link", { name: "Audit", exact: true }).click();
  await page.getByRole("button", { name: "Verify chain" }).click();
  await expect(page.locator(".verify-banner.ok")).toContainText("Chain verified");
});
