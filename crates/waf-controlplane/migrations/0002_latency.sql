-- SPDX-FileCopyrightText: 2026 0x00spor3
-- SPDX-License-Identifier: BUSL-1.1
--
-- Latency histogram snapshots (Phase 3). Each /metrics scrape stores one row per
-- `waf_request_duration_seconds_bucket{le}` bound (cumulative count ≤ le), tagged with a common
-- (ts, node). The read API computes p50/p95/p99 from the latest snapshot per node.

CREATE TABLE IF NOT EXISTS latency_buckets (
    id    BIGSERIAL        PRIMARY KEY,
    ts    TIMESTAMPTZ      NOT NULL DEFAULT now(),
    node  TEXT             NOT NULL,
    -- Bucket upper bound in seconds; the `+Inf` bucket is stored as double-precision Infinity.
    le    DOUBLE PRECISION NOT NULL,
    -- Cumulative request count with latency ≤ le.
    count BIGINT           NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_latency_buckets_node_ts ON latency_buckets (node, ts DESC);
