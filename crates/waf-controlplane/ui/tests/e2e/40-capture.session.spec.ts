// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// C5 — Request-capture drill-down UI: an operator can reveal the full captured request (headers,
// cookies, body) of a denied event, and sees the node-side redaction banner; a viewer never gets the
// panel at all (mirrors the ViewCaptures RBAC — operator-and-up). A fixed event + capture are seeded
// in global-setup under the request id below.

import { expect, test, type Page } from "@playwright/test";

const CAPTURE_RID = "e2e-capture-fixed";

async function login(page: Page, user: string, pw: string, role: string): Promise<void> {
  await page.goto("/");
  await page.getByPlaceholder("Username").fill(user);
  await page.getByPlaceholder("Password").fill(pw);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator(".whoami .role-chip")).toHaveText(role);
}

test("an operator reveals the captured request (audited)", async ({ page }) => {
  await login(page, "bob", "bobpw", "operator");
  await page.goto(`/events/${CAPTURE_RID}`);

  // The panel is present but the sensitive data is not fetched until explicitly revealed.
  const panel = page.locator(".panel", { hasText: "Captured request" });
  await expect(panel).toBeVisible();
  await expect(panel.getByText("user=admin")).toHaveCount(0);

  await panel.getByRole("button", { name: "Reveal captured request" }).click();

  // Redaction banner (node-side), the request header, and the body all render.
  await expect(panel.getByText("Redacted node-side:")).toBeVisible();
  await expect(panel.getByText("password", { exact: true })).toBeVisible();
  await expect(panel.getByText("content-type", { exact: true })).toBeVisible();
  await expect(panel.locator(".cap-body")).toContainText("user=admin");

  // The Hex toggle switches the body view to a hex dump.
  await panel.getByRole("button", { name: "Hex", exact: true }).click();
  await expect(panel.locator(".cap-body")).toContainText("00000000");
});

test("a viewer never sees the capture panel", async ({ page }) => {
  await login(page, "alice", "alicepw", "viewer");
  await page.goto(`/events/${CAPTURE_RID}`);

  // The event detail itself loads (ReadObservability), but the capture panel is gated out entirely —
  // the viewer cannot even trigger the audited fetch.
  await expect(page.getByRole("heading", { name: "Verdict", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Captured request", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Reveal captured request" })).toHaveCount(0);
});
