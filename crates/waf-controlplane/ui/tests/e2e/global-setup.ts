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

/** A fixed denied event + its captured request (request-capture feature), for the C5 capture UI test. */
const CAPTURE_RID = "e2e-capture-fixed";

async function seedFixedCapture(): Promise<void> {
  const ts = new Date().toISOString();
  // 1. The decision event, so the drill-down page loads (get_event is ReadObservability).
  const lines = [
    JSON.stringify({ timestamp: ts, fields: { message: "→ request", request_id: CAPTURE_RID, method: "POST", path: "/login", client_ip: "203.0.113.9" } }),
    JSON.stringify({
      timestamp: ts,
      fields: {
        message: "request blocked",
        request_id: CAPTURE_RID,
        rule_id: "sqli-union-select",
        reason: "anomaly score exceeded",
        score: 8,
        score_contributions: JSON.stringify([{ module: "sqli", rule_id: "sqli-union-select", severity: "critical", points: 8 }]),
      },
    }),
  ];
  await fetch(`${TOKEN}/ingest/events?node=edge-e2e`, {
    method: "POST",
    headers: { "content-type": "application/x-ndjson", authorization: `Bearer ${API_TOKEN}` },
    body: `${lines.join("\n")}\n`,
  });
  // 2. The captured request on the side-channel (bearer-gated, idempotent). `password` was redacted
  //    node-side, so the value never leaves the node — only the name is reported.
  const body = "user=admin&password=***REDACTED***";
  const capture = {
    request_id: CAPTURE_RID,
    method: "POST",
    path: "/login",
    query: null,
    http_version: "HTTP/1.1",
    headers: [["content-type", "application/x-www-form-urlencoded"]],
    cookies: [],
    body_b64: Buffer.from(body).toString("base64"),
    body_size: Buffer.byteLength(body),
    body_truncated: false,
    redacted: ["password"],
  };
  await fetch(`${TOKEN}/ingest/captures?node=edge-e2e`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${API_TOKEN}` },
    body: JSON.stringify(capture),
  });
}

export default async function globalSetup(_config: FullConfig): Promise<void> {
  await waitReady(TOKEN);
  await waitReady(SESSION);

  // Seed a viewer + an operator for the RBAC tests (idempotent: a 409 on re-run is fine).
  try {
    const cookie = await adminCookie();
    if (cookie) {
      for (const u of [
        { username: "alice", password: "alicepw", role: "viewer" },
        { username: "bob", password: "bobpw", role: "operator" },
      ]) {
        await fetch(`${SESSION}/api/users`, {
          method: "POST",
          headers: { "content-type": "application/json", cookie },
          body: JSON.stringify(u),
        });
      }
    }
  } catch (e) {
    console.warn("global-setup: seeding users was skipped:", e);
  }

  // Seed denied events so the Overview/Events views have data + a drill-down target.
  try {
    await seedEvents();
  } catch (e) {
    console.warn("global-setup: seeding events was skipped:", e);
  }

  // Seed a fixed denied event + its captured request for the C5 capture-panel test.
  try {
    await seedFixedCapture();
  } catch (e) {
    console.warn("global-setup: seeding a capture was skipped:", e);
  }
}
