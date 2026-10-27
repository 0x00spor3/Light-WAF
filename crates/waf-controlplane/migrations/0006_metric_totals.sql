-- SPDX-License-Identifier: Apache-2.0
--
-- Reset-aware lifetime totals. `waf_requests_total{decision}` and the latency histogram buckets are
-- Prometheus COUNTERS: cumulative since the WAF process started, and reset to zero when it restarts.
-- The raw metric_rollups/latency_buckets snapshots therefore drop back to ~0 after a WAF restart, so
-- a dashboard reading "the latest snapshot" loses its running totals.
--
-- These tables hold a persistent, reset-aware running total the scraper maintains on every scrape:
-- delta = (raw - last_raw) normally, or the raw value itself when a reset is detected (raw < last_raw,
-- i.e. the counter went backwards). The total lives in Postgres, so it survives BOTH a WAF restart
-- (reset detection) and a control-plane restart (state is read back from the row).

CREATE TABLE IF NOT EXISTS metric_totals (
    node       TEXT        NOT NULL,
    decision   TEXT        NOT NULL,
    cumulative BIGINT      NOT NULL DEFAULT 0,   -- reset-aware lifetime count for (node, decision)
    last_raw   BIGINT      NOT NULL DEFAULT 0,   -- last raw counter value seen (delta / reset detection)
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (node, decision)
);

CREATE TABLE IF NOT EXISTS latency_totals (
    node       TEXT             NOT NULL,
    le         DOUBLE PRECISION NOT NULL,        -- histogram bucket upper bound (+Inf → 'Infinity')
    cumulative BIGINT           NOT NULL DEFAULT 0,
    last_raw   BIGINT           NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ      NOT NULL DEFAULT now(),
    PRIMARY KEY (node, le)
);
