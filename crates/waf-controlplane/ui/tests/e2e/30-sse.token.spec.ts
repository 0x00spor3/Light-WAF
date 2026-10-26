// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// E3+ — SSE live refresh (token mode). End-to-end proof that the "notify-then-pull" stream works
// against the REAL backend: with the Events view open, ingest a new decision event straight into the
// same binary the browser is connected to; the process-local EventBus fires an `events` notice on
// `GET /api/stream`, the SPA refreshes silently, and the new row appears WITHOUT a manual reload —
// and well under the 20s poll fallback, so the stream (not the slow poll) is what drove the refresh.

import { expect, test } from "@playwright/test";
import { API_TOKEN } from "../../playwright.config";
import { loginToken } from "./helpers";

test("Events view refreshes live via SSE when a new event is ingested", async ({ page, request, baseURL }) => {
  await loginToken(page);

  // Open the Events view; on mount it subscribes to /api/stream (bearer via fetch-reader).
  await page.getByRole("link", { name: "Events", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Denied requests" })).toBeVisible();
  // Let the initial load settle and the SSE connection establish before we ingest.
  await expect(page.locator(".live")).toBeVisible();

  // A distinctive client IP (TEST-NET-2) that no earlier seed used, so its row is unambiguous.
  const clientIp = `198.51.100.${10 + Math.floor(Math.random() * 240)}`;
  await expect(page.getByText(clientIp)).toHaveCount(0);

  // Ingest one correlated request+block for that IP into the SAME binary (bearer-gated ingest).
  const ts = new Date().toISOString();
  const rid = `sse-${Date.now()}`;
  const ndjson =
    JSON.stringify({
      timestamp: ts,
      fields: { message: "→ request", request_id: rid, method: "GET", path: "/sse-probe", client_ip: clientIp },
    }) +
    "\n" +
    JSON.stringify({
      timestamp: ts,
      fields: {
        message: "request blocked",
        request_id: rid,
        rule_id: "sse-probe-rule",
        reason: "anomaly score exceeded",
        score: 6,
        score_contributions: JSON.stringify([{ module: "sqli", rule_id: "sse-probe-rule", severity: "critical", points: 6 }]),
      },
    }) +
    "\n";
  const res = await request.post(`${baseURL}/ingest/events?node=sse-e2e`, {
    headers: { "content-type": "application/x-ndjson", authorization: `Bearer ${API_TOKEN}` },
    data: ndjson,
  });
  expect(res.ok()).toBeTruthy();

  // The row must appear with NO manual reload, comfortably under the 20s poll fallback — this is the
  // SSE stream doing the work.
  await expect(page.getByText(clientIp)).toBeVisible({ timeout: 10_000 });
});
