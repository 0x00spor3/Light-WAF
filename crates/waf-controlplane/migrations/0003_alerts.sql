-- SPDX-FileCopyrightText: 2026 0x00spor3
-- SPDX-License-Identifier: Apache-2.0
--
-- Alerts (v2). One row per fired alert: the evaluator inserts a row when a rule's (per-group) count
-- of denied events crosses its threshold (deduped by cooldown). Read back via GET /api/alerts.

CREATE TABLE IF NOT EXISTS alerts (
    id        BIGSERIAL   PRIMARY KEY,
    rule_name TEXT        NOT NULL,
    -- The group value that fired (e.g. a client_ip / rule_id), or '' for an ungrouped rule.
    group_key TEXT        NOT NULL DEFAULT '',
    fired_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    severity  TEXT        NOT NULL,
    -- The observed count and the rule's threshold at fire time.
    value     BIGINT      NOT NULL,
    threshold BIGINT      NOT NULL,
    summary   TEXT        NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alerts_fired_at ON alerts (fired_at DESC);
-- Cooldown lookup: latest fire per (rule, group).
CREATE INDEX IF NOT EXISTS idx_alerts_rule_group ON alerts (rule_name, group_key, fired_at DESC);
