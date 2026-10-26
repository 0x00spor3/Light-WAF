-- SPDX-FileCopyrightText: 2026 0x00spor3
-- SPDX-License-Identifier: Apache-2.0
--
-- SIEM export cursors (§9). The forwarder PUSHes stored events (decision_events / gov_audit_log /
-- alerts) to configured SIEM sinks. Delivery is at-least-once: the cursor advances ONLY after a
-- whole batch is acked (HTTP 2xx); on failure it stays put and the batch is retransmitted. The
-- cursor is keyed by (destination, stream) so multiple sinks each track their own position
-- independently (multi-destination). The buffer is Postgres itself (bounded by retention) — no
-- in-memory queues.

CREATE TABLE IF NOT EXISTS siem_cursors (
    -- The configured SIEM destination name ([[controlplane.siem.destinations]].name).
    destination TEXT        NOT NULL,
    -- The event stream: 'decisions' (decision_events.id) | 'audit' (gov_audit_log.seq) | 'alerts'
    -- (alerts.id). The last exported id/seq for this (destination, stream).
    stream      TEXT        NOT NULL,
    last_id     BIGINT      NOT NULL DEFAULT 0,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (destination, stream)
);
