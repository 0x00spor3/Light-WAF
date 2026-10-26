// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E3+ — API attack-surface inventory (token mode, §4-B pt3 discovery). End-to-end against the REAL
// backend: seed denied events (a declared endpoint hit per-id + an undeclared one) straight into the
// binary via the bearer-gated ingest, then open the "API Inventory" view and confirm the control
// plane templated + classified them against the configured OpenAPI spec (documented vs shadow), with
// the per-id paths folded into one endpoint. The spec is `tests/e2e/openapi.json` (declares only
// `/api/e2e-inv/{id}`), wired via `[controlplane.api_inventory]` in `token.toml`.

import { expect, test } from "@playwright/test";
import { API_TOKEN } from "../../playwright.config";
import { loginToken } from "./helpers";

/** POST one correlated request+blocked pair (a denied event carrying method/path) to the ingest API. */
async function seedDenied(
  request: import("@playwright/test").APIRequestContext,
  baseURL: string,
  path: string,
) {
  const ts = new Date().toISOString();
  const rid = `inv-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const ndjson =
    JSON.stringify({ timestamp: ts, fields: { message: "→ request", request_id: rid, method: "GET", path, client_ip: "203.0.113.77" } }) +
    "\n" +
    JSON.stringify({ timestamp: ts, fields: { message: "request blocked", request_id: rid, rule_id: "schema-api-unknown-route", score: 6 } }) +
    "\n";
  const res = await request.post(`${baseURL}/ingest/events?node=inv-e2e`, {
    headers: { "content-type": "application/x-ndjson", authorization: `Bearer ${API_TOKEN}` },
    data: ndjson,
  });
  expect(res.ok()).toBeTruthy();
}

test("API Inventory classifies seeded endpoints (documented vs shadow) and folds per-id paths", async ({
  page,
  request,
  baseURL,
}) => {
  const url = baseURL!;
  // A declared endpoint hit with two different ids (must fold), plus an undeclared endpoint (shadow).
  await seedDenied(request, url, "/api/e2e-inv/42");
  await seedDenied(request, url, "/api/e2e-inv/43");
  await seedDenied(request, url, "/api/e2e-inv-shadow");

  await loginToken(page);
  await page.getByRole("link", { name: "API Inventory" }).click();
  await expect(page.getByRole("heading", { name: "API attack surface" })).toBeVisible();

  // Documented: the two per-id paths fold into one templated endpoint.
  const documented = page.locator("tr", { hasText: "/api/e2e-inv/{}" });
  await expect(documented).toBeVisible();
  await expect(documented.locator(".badge")).toHaveText("documented");

  // Shadow: the undeclared endpoint.
  const shadow = page.locator("tr", { hasText: "/api/e2e-inv-shadow" });
  await expect(shadow).toBeVisible();
  await expect(shadow.locator(".badge")).toHaveText("shadow");

  // The "Shadow only" filter hides the documented row.
  await page.getByRole("combobox").selectOption("shadow");
  await expect(page.locator("tr", { hasText: "/api/e2e-inv/{}" })).toHaveCount(0);
  await expect(page.locator("tr", { hasText: "/api/e2e-inv-shadow" })).toBeVisible();
});
