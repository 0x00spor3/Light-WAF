-- SPDX-License-Identifier: Apache-2.0
--
-- Request Capture (enterprise, optional). Full denied requests shipped by a node's request-capture
-- feature (`waf-capture`), joined to `decision_events` by `request_id` in the drill-down. This is
-- FORENSIC data: with raw capture it can contain sensitive request material (bodies/headers), so it
-- carries its OWN, typically shorter, retention (`[controlplane.captures].retention_hours`) enforced
-- by the retention reaper — independent of `retention_days` for the aggregate telemetry.
--
-- Redaction + truncation are applied NODE-SIDE before shipping; the control plane only persists what
-- it receives. The body is stored as BYTEA (the node ships it base64; the ingest decodes it).

CREATE TABLE IF NOT EXISTS request_captures (
    request_id     TEXT        NOT NULL,          -- correlates to decision_events.request_id
    node           TEXT        NOT NULL,
    captured_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    method         TEXT        NOT NULL,
    path           TEXT        NOT NULL,
    query          TEXT,
    http_version   TEXT        NOT NULL,
    headers        JSONB       NOT NULL,           -- [[name, value], ...] (redacted node-side)
    cookies        JSONB       NOT NULL,           -- [[name, value], ...] (redacted node-side)
    body           BYTEA       NOT NULL,           -- raw (redacted/truncated) body bytes
    body_size      BIGINT      NOT NULL,           -- original size before truncation
    body_truncated BOOLEAN     NOT NULL,
    redacted       JSONB       NOT NULL,           -- ["name", ...] redacted node-side (banner)
    -- One capture per request. A shipper retry that already succeeded is absorbed (ON CONFLICT).
    PRIMARY KEY (request_id)
);

-- Retention reaper deletes by age; index the age column.
CREATE INDEX IF NOT EXISTS request_captures_captured_at_idx ON request_captures (captured_at);
