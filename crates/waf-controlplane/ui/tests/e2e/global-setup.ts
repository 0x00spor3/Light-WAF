// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

// Runs once before the E2E suite: wait for both backends, then seed deterministic data via the API
// (idempotent — safe to re-run against the same throwaway Postgres). Assumes a fresh/throwaway DB so
// the session binary bootstraps `admin` with the harness password (see RUNBOOK §M).

import type { FullConfig } from "@playwright/test";
import { ADMIN_PW, ADMIN_USER, API_TOKEN } from "../../playwright.config";

const TOKEN = "http://127.0.0.1:9701";
const SESSION = "http://127.0.0.1:9702";

async function waitReady(base: string): Promise<void> {
  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(`${base}/healthz`);
      if (r.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`backend not ready: ${base}`);
}

/** Log in as admin (session mode) and return the session cookie, or null. */
async function adminCookie(): Promise<string | null> {
  const res = await fetch(`${SESSION}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PW }),
  });
  if (!res.ok) return null;
  const raw = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.()[0] ?? res.headers.get("set-cookie");
  return raw ? raw.split(";")[0] : null;
}

/** Seed a few denied events (correlated request+block NDJSON) so Overview/Events have data. */
async function seedEvents(): Promise<void> {
  const ts = new Date().toISOString();
  const run = Date.now();
  const lines: string[] = [];
  for (let i = 0; i < 4; i++) {
    const rid = `e2e-${run}-${i}`;
    lines.push(
      JSON.stringify({ timestamp: ts, fields: { message: "→ request", request_id: rid, method: "GET", path: `/?q=${i}`, client_ip: "203.0.113.7" } }),
    );
    lines.push(
      JSON.stringify({
        timestamp: ts,
        fields: {
          message: "request blocked",
          request_id: rid,
          rule_id: "sqli-union-select",
          reason: "anomaly score exceeded",
          score: 6,
          score_contributions: JSON.stringify([{ module: "sqli", rule_id: "sqli-union-select", severity: "critical", points: 6 }]),
        },
      }),
    );
  }
  // The token binary's ingest is bearer-gated; decision_events land in the shared Postgres.
  await fetch(`${TOKEN}/ingest/events?node=edge-e2e`, {
    method: "POST",
    headers: { "content-type": "application/x-ndjson", authorization: `Bearer ${API_TOKEN}` },
    body: `${lines.join("\n")}\n`,
  });
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  await waitReady(TOKEN);
  await waitReady(SESSION);

  // Seed a viewer for the RBAC test (idempotent: a 409 on re-run is fine).
  try {
    const cookie = await adminCookie();
    if (cookie) {
      await fetch(`${SESSION}/api/users`, {
        method: "POST",
        headers: { "content-type": "application/json", cookie },
        body: JSON.stringify({ username: "alice", password: "alicepw", role: "viewer" }),
      });
    }
  } catch (e) {
    console.warn("global-setup: seeding a viewer was skipped:", e);
  }

  // Seed denied events so the Overview/Events views have data + a drill-down target.
  try {
    await seedEvents();
  } catch (e) {
    console.warn("global-setup: seeding events was skipped:", e);
  }
}
