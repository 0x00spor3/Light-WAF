-- SPDX-FileCopyrightText: 2026 0x00spor3
-- SPDX-License-Identifier: BUSL-1.1
--
-- Control-plane schema v1 (§7). Populated by the ingestion pipeline (Phase 2) from the OPEN
-- telemetry: decision_events from the JSON decision-log, metric_rollups from /metrics scrapes.

-- One denied-request event (blocked | rejected), reconstructed from the OPEN decision-log. The
-- per-rule breakdown is kept verbatim as JSONB so the drill-down (Phase 3) rebuilds the verdict.
CREATE TABLE IF NOT EXISTS decision_events (
    id            BIGSERIAL PRIMARY KEY,
    request_id    TEXT        NOT NULL,
    ts            TIMESTAMPTZ NOT NULL DEFAULT now(),
    node          TEXT        NOT NULL,
    method        TEXT,
    path          TEXT,
    -- Stored as TEXT (not INET): the source is a log field and must never fail ingestion on an
    -- odd value; IP-range queries are a follow-on, not a v1 need.
    client_ip     TEXT,
    decision      TEXT        NOT NULL,          -- 'blocked' | 'rejected'
    rule_id       TEXT,
    reason        TEXT,
    score         INTEGER     NOT NULL DEFAULT 0,
    contributions JSONB       NOT NULL DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_decision_events_ts         ON decision_events (ts DESC);
CREATE INDEX IF NOT EXISTS idx_decision_events_request_id ON decision_events (request_id);
CREATE INDEX IF NOT EXISTS idx_decision_events_rule_id    ON decision_events (rule_id);

-- Periodic snapshot of the per-decision counters scraped from a node's /metrics, for long-term
-- retention and time-series dashboards (Prometheus keeps only its own retention window). Latency
-- histogram buckets are added in Phase 2 when the scraper parses them.
CREATE TABLE IF NOT EXISTS metric_rollups (
    id       BIGSERIAL   PRIMARY KEY,
    ts       TIMESTAMPTZ NOT NULL DEFAULT now(),
    node     TEXT        NOT NULL,
    decision TEXT        NOT NULL,               -- allowed|blocked|rate_limited|bad_request|upstream_error|internal_error
    count    BIGINT      NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_metric_rollups_ts ON metric_rollups (ts DESC);
