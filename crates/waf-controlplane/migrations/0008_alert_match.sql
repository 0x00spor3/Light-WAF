-- SPDX-FileCopyrightText: 2026 0x00spor3
-- SPDX-License-Identifier: Apache-2.0
--
-- Alert evidence. A snapshot of the firing rule's match parameters (filters, grouping, window) as
-- they were at fire time, so the denied events behind an alert can be re-selected from
-- `decision_events` even after the rule is edited, renamed or removed from the config.
--
-- All columns are nullable: rows fired before this migration carry no snapshot (`match_window_seconds
-- IS NULL`) and are resolved against the currently configured rule of the same name, if any. The
-- filter columns are NULL when the rule had no such filter.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_window_seconds BIGINT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_group_by       TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_decision       TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_rule_id        TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS match_client_ip      TEXT;
