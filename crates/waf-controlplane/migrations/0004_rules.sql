-- SPDX-FileCopyrightText: 2026 0x00spor3
-- SPDX-License-Identifier: Apache-2.0
--
-- Rule management (§7 write-path, v3). The control plane versions ONE managed SecRule `.conf` file:
-- each publish appends an immutable row to `rule_versions`; the singleton `rule_current` selects which
-- version is live; rollback re-points `rule_current` to an older version. Per-node agents pull the
-- current version, pre-validate it, write it + reload their WAF, and report back into `node_rule_status`
-- (the convergence view). Zero-core: the WAF loads the managed file via `[modules.crs].files` and
-- reloads it on SIGHUP (validate-then-swap) — the agent never links the datapath's write path.

-- Immutable ruleset versions. `content` is the raw managed `.conf` text; never updated after insert.
CREATE TABLE IF NOT EXISTS rule_versions (
    id         BIGSERIAL   PRIMARY KEY,
    content    TEXT        NOT NULL,
    author     TEXT        NOT NULL,
    note       TEXT        NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rule_versions_created_at ON rule_versions (created_at DESC);

-- Singleton pointer to the live version (publish sets it; rollback re-points it). The `singleton`
-- CHECK + PK guarantees at most one row.
CREATE TABLE IF NOT EXISTS rule_current (
    singleton  BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
    version_id BIGINT  NOT NULL REFERENCES rule_versions (id)
);

-- Convergence: the version each node reports it has applied, plus the outcome of its last apply.
-- One row per node (upserted on each report). `applied_version` is NULL until the node reports one.
CREATE TABLE IF NOT EXISTS node_rule_status (
    node            TEXT        PRIMARY KEY,
    applied_version BIGINT,
    -- Free-form agent-reported outcome, e.g. 'applied' | 'rejected' | 'error'.
    status          TEXT        NOT NULL,
    detail          TEXT        NOT NULL DEFAULT '',
    reported_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
