// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

// Alert evidence (token mode): three blocks from one IP fire the `e2e-alert-burst` rule configured in
// token.toml (threshold 3, grouped by client IP). Opening the fired alert lists exactly those three
// denied requests — not the probe rule's block from another IP, which is in the window and matches
// the rule's filters but is a different group — and a row leads to the event drill-down.

import { expect, test, type APIRequestContext } from "@playwright/test";
import { API_TOKEN } from "../../playwright.config";
import { loginToken } from "./helpers";

const PROBE_RULE = "e2e-alert-probe";

/** Ingest one correlated request + block line pair per `[requestId, clientIp, path]`. */
async function ingestBlocks(
  request: APIRequestContext,
  baseURL: string | undefined,
  blocks: [string, string, string][],
): Promise<void> {
  const ts = new Date().toISOString();
  const lines = blocks.flatMap(([rid, clientIp, path]) => [
    JSON.stringify({ timestamp: ts, fields: { message: "→ request", request_id: rid, method: "GET", path, client_ip: clientIp } }),
    JSON.stringify({
      timestamp: ts,
      fields: {
        message: "request blocked",
        request_id: rid,
        rule_id: PROBE_RULE,
        reason: "anomaly score exceeded",
        score: 7,
        score_contributions: JSON.stringify([{ module: "sqli", rule_id: PROBE_RULE, severity: "critical", points: 7 }]),
      },
    }),
  ]);
  const res = await request.post(`${baseURL}/ingest/events?node=alert-e2e`, {
    headers: { "content-type": "application/x-ndjson", authorization: `Bearer ${API_TOKEN}` },
    data: `${lines.join("\n")}\n`,
  });
  expect(res.ok()).toBeTruthy();
}

test("a fired alert lists the events that fired it", async ({ page, request, baseURL }) => {
  // IPs derived from the clock, so a re-run against the same DB (within the rule's 1h window and
  // its cooldown) gets a fresh group and never counts an earlier run's events.
  const t = Date.now();
  const octets = `${(t >> 16) & 255}.${(t >> 8) & 255}.${t & 255}`;
  const firedIp = `10.${octets}`;
  const otherIp = `192.168.${(t >> 8) & 255}.${t & 255}`;
  const rid = (s: string) => `alert-e2e-${t}-${s}`;

  await loginToken(page);
  await page.getByRole("link", { name: "Alerts", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Fired alerts" })).toBeVisible();

  await ingestBlocks(request, baseURL, [
    [rid("0"), firedIp, "/alert-probe/0"],
    [rid("1"), firedIp, "/alert-probe/1"],
    [rid("2"), firedIp, "/alert-probe/2"],
    // Same rule, same window, other group: below threshold, and never part of the fired alert.
    [rid("other"), otherIp, "/alert-probe/other"],
  ]);

  // The evaluator fires within a few cycles; the Alerts view refreshes on the SSE notice.
  const alertRow = page.locator("tbody tr", { hasText: firedIp });
  await expect(alertRow).toBeVisible({ timeout: 15_000 });
  await expect(page.locator("tbody tr", { hasText: otherIp })).toHaveCount(0);
  await alertRow.click();

  await expect(page).toHaveURL(/\/alerts\/\d+$/);
  const summary = page.locator(".panel", { has: page.getByRole("heading", { name: "Alert", exact: true }) });
  await expect(summary).toContainText("e2e-alert-burst");
  await expect(summary).toContainText(`client_ip=${firedIp}`);
  await expect(summary).toContainText(`rule=${PROBE_RULE}`);
  await expect(summary).toContainText("3600s");
  // Still ongoing: the three events are in the window ending now (threshold 3).
  await expect(summary).toContainText("3 matching events in the last 3600s — still above threshold");
  // Fired with a snapshot: no "approximate" / "unavailable" notice.
  await expect(summary.locator(".alert-notice")).toHaveCount(0);

  // Exactly the three events of the fired group, newest first; the other IP's block is absent.
  const events = page.locator(".panel", { has: page.getByRole("heading", { name: "Events", exact: true }) });
  const rows = events.locator("tbody tr");
  await expect(rows).toHaveCount(3);
  for (const i of ["0", "1", "2"]) {
    await expect(events.getByText(`/alert-probe/${i}`, { exact: true })).toBeVisible();
  }
  await expect(events.getByText(otherIp)).toHaveCount(0);
  await expect(events.getByText("/alert-probe/other")).toHaveCount(0);
  // The listed total matches the fired value, so the "differs" note is not shown.
  await expect(events.getByText("the alert counted")).toHaveCount(0);

  // A row opens that event's drill-down.
  await rows.filter({ hasText: "/alert-probe/1" }).click();
  await expect(page).toHaveURL(new RegExp(`/events/${rid("1")}$`));
  await expect(page.getByRole("heading", { name: "Verdict" })).toBeVisible();
  await expect(page.getByText(rid("1"))).toBeVisible();
});
