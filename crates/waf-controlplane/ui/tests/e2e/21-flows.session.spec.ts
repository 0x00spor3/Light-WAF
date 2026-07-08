// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// E3 — session mode (admin): the key write flows through the UI — publish a rule, generate + verify a
// compliance report, and mint a service token.

import { expect, test } from "@playwright/test";
import { loginAdmin } from "./helpers";

test.beforeEach(async ({ page }) => {
  await loginAdmin(page);
});

test("publishing a rule creates a new current version", async ({ page }) => {
  await page.getByRole("link", { name: "Rules", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Publish a ruleset version" })).toBeVisible();

  await page.locator("textarea").fill('SecRule ARGS "@rx (?i)e2eplaywright" "id:9700,phase:2,severity:CRITICAL,block"');
  await page.getByPlaceholder("change note (optional)").fill("e2e publish");
  await page.getByRole("button", { name: "Publish & make current" }).click();

  // The Versions table now has a row flagged current.
  await expect(page.getByText("current", { exact: true }).first()).toBeVisible();
});

test("generating a compliance report + verifying its signature", async ({ page }) => {
  await page.getByRole("link", { name: "Compliance", exact: true }).click();
  await page.getByRole("button", { name: "Generate" }).click();

  await expect(page.getByRole("heading", { name: "Access control" })).toBeVisible();
  await expect(page.locator(".verify-banner.ok")).toContainText("Audit chain verified");

  await page.getByRole("button", { name: "Verify signature" }).click();
  await expect(page.getByText("Bundle signature verified")).toBeVisible();
});

test("creating a service token reveals the secret once", async ({ page }) => {
  await page.getByRole("link", { name: "Tokens", exact: true }).click();
  await page.getByPlaceholder("token name").fill(`e2e-tok-${Date.now()}`);
  await page.getByRole("button", { name: "Create token" }).click();

  const reveal = page.locator(".token-reveal");
  await expect(reveal).toBeVisible();
  await expect(reveal.locator("code")).not.toBeEmpty();
});
