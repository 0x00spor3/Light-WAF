// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Postgres store for the control plane. Runtime queries (no compile-time `query!` macro) so the
//! crate builds with no database; only the env-gated integration test needs a live Postgres.

use base64::Engine as _;
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::types::Json;
use time::OffsetDateTime;

use crate::config::AlertRule;
use crate::error::{Error, Result};
use crate::model::{
    Alert, CapturedRequest, Contribution, DecisionEvent, MetricRollup, NodeRuleStatus, RuleVersion,
    RuleVersionMeta,
};
use crate::prometheus::{DecisionCount, LatencyBucket};

/// Optional filters for [`Store::search_events`]. A `None` field matches everything.
#[derive(Debug, Default, Clone)]
pub struct EventFilter {
    pub rule_id: Option<String>,
    pub decision: Option<String>,
    pub client_ip: Option<String>,
}

/// A pooled connection to the control-plane Postgres, plus the schema operations Phase 2/3 need.
#[derive(Clone)]
pub struct Store {
    pool: PgPool,
}

/// Row shape for `decision_events` reads — `contributions` comes back as JSONB decoded into the
/// typed model via `sqlx::types::Json`.
#[derive(sqlx::FromRow)]
struct EventRow {
    request_id: String,
    ts: OffsetDateTime,
    node: String,
    method: Option<String>,
    path: Option<String>,
    client_ip: Option<String>,
    decision: String,
    rule_id: Option<String>,
    reason: Option<String>,
    score: i32,
    contributions: Json<Vec<Contribution>>,
}

/// Row shape for the API-inventory aggregation (`api_inventory`): one observed `(method, path)` with
/// its hit count and first/last-seen.
#[derive(sqlx::FromRow)]
struct InventoryRow {
    method: String,
    path: String,
    hits: i64,
    first_seen: OffsetDateTime,
    last_seen: OffsetDateTime,
}

impl From<EventRow> for DecisionEvent {
    fn from(r: EventRow) -> Self {
        DecisionEvent {
            request_id: r.request_id,
            ts: r.ts,
            node: r.node,
            method: r.method,
            path: r.path,
            client_ip: r.client_ip,
            decision: r.decision,
            rule_id: r.rule_id,
            reason: r.reason,
            score: r.score,
            contributions: r.contributions.0,
        }
    }
}

/// Row shape for `request_captures` reads — JSONB columns decode into typed vecs; `body` is raw
/// `BYTEA` re-encoded to base64 on the way out to the DTO.
#[derive(sqlx::FromRow)]
struct CaptureRow {
    request_id: String,
    method: String,
    path: String,
    query: Option<String>,
    http_version: String,
    headers: Json<Vec<(String, String)>>,
    cookies: Json<Vec<(String, String)>>,
    body: Vec<u8>,
    body_size: i64,
    body_truncated: bool,
    redacted: Json<Vec<String>>,
}

impl From<CaptureRow> for CapturedRequest {
    fn from(r: CaptureRow) -> Self {
        CapturedRequest {
            request_id: r.request_id,
            method: r.method,
            path: r.path,
            query: r.query,
            http_version: r.http_version,
            headers: r.headers.0,
            cookies: r.cookies.0,
            body_b64: base64::engine::general_purpose::STANDARD.encode(&r.body),
            body_size: r.body_size.max(0) as u64,
            body_truncated: r.body_truncated,
            redacted: r.redacted.0,
        }
    }
}

/// Same as [`EventRow`] plus the row `id` — for the SIEM export (the cursor is the id).
#[derive(sqlx::FromRow)]
struct DecisionIdRow {
    id: i64,
    request_id: String,
    ts: OffsetDateTime,
    node: String,
    method: Option<String>,
    path: Option<String>,
    client_ip: Option<String>,
    decision: String,
    rule_id: Option<String>,
    reason: Option<String>,
    score: i32,
    contributions: Json<Vec<Contribution>>,
}

impl From<DecisionIdRow> for (i64, DecisionEvent) {
    fn from(r: DecisionIdRow) -> Self {
        (
            r.id,
            DecisionEvent {
                request_id: r.request_id,
                ts: r.ts,
                node: r.node,
                method: r.method,
                path: r.path,
                client_ip: r.client_ip,
                decision: r.decision,
                rule_id: r.rule_id,
                reason: r.reason,
                score: r.score,
                contributions: r.contributions.0,
            },
        )
    }
}

impl Store {
    /// Connect (bounded pool). The URL is a plain Postgres connection string.
    pub async fn connect(database_url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new().max_connections(8).connect(database_url).await?;
        Ok(Self { pool })
    }

    /// Apply the embedded migrations (`migrations/`). Idempotent — safe on every boot.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// The underlying pool — used by the governance layer (§8), which owns its own tables on the
    /// same database (see `gov_api`).
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Insert one denied-request event (ingestion, Phase 2).
    pub async fn insert_decision_event(&self, ev: &DecisionEvent) -> Result<()> {
        sqlx::query(
            "INSERT INTO decision_events \
             (request_id, ts, node, method, path, client_ip, decision, rule_id, reason, score, contributions) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(&ev.request_id)
        .bind(ev.ts)
        .bind(&ev.node)
        .bind(&ev.method)
        .bind(&ev.path)
        .bind(&ev.client_ip)
        .bind(&ev.decision)
        .bind(&ev.rule_id)
        .bind(&ev.reason)
        .bind(ev.score)
        .bind(Json(&ev.contributions))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The most recent event for a `request_id` (drill-down, Phase 3). `None` if unknown.
    pub async fn get_decision_event(&self, request_id: &str) -> Result<Option<DecisionEvent>> {
        let row: Option<EventRow> = sqlx::query_as::<_, EventRow>(
            "SELECT request_id, ts, node, method, path, client_ip, decision, rule_id, reason, score, contributions \
             FROM decision_events WHERE request_id = $1 ORDER BY ts DESC LIMIT 1",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// The `limit` most recent events (basic listing; richer search is [`Self::search_events`]).
    pub async fn recent_events(&self, limit: i64) -> Result<Vec<DecisionEvent>> {
        self.search_events(&EventFilter::default(), limit).await
    }

    /// Store one captured request (request-capture ingest). The node ships the body base64-encoded;
    /// it is decoded to raw `BYTEA` here. Idempotent: a re-delivered capture (shipper retry) with the
    /// same `request_id` is absorbed (`ON CONFLICT DO NOTHING`). A body that is not valid base64 is a
    /// malformed payload → `Error::Config`.
    pub async fn insert_capture(&self, node: &str, cap: &CapturedRequest) -> Result<()> {
        let body = base64::engine::general_purpose::STANDARD
            .decode(cap.body_b64.as_bytes())
            .map_err(|e| Error::Config(format!("capture body not valid base64: {e}")))?;
        sqlx::query(
            "INSERT INTO request_captures \
             (request_id, node, method, path, query, http_version, headers, cookies, body, body_size, body_truncated, redacted) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
             ON CONFLICT (request_id) DO NOTHING",
        )
        .bind(&cap.request_id)
        .bind(node)
        .bind(&cap.method)
        .bind(&cap.path)
        .bind(&cap.query)
        .bind(&cap.http_version)
        .bind(Json(&cap.headers))
        .bind(Json(&cap.cookies))
        .bind(&body)
        .bind(cap.body_size as i64)
        .bind(cap.body_truncated)
        .bind(Json(&cap.redacted))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The captured request for a `request_id`, if one was shipped (and not yet pruned). `None` when
    /// capture is off for the node, the request was not denied, or the capture has aged out.
    pub async fn get_capture(&self, request_id: &str) -> Result<Option<CapturedRequest>> {
        let row: Option<CaptureRow> = sqlx::query_as::<_, CaptureRow>(
            "SELECT request_id, method, path, query, http_version, headers, cookies, body, body_size, body_truncated, redacted \
             FROM request_captures WHERE request_id = $1",
        )
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(Into::into))
    }

    /// Search denied-request events with optional filters, newest first (drill-down list, Phase 3).
    /// Each filter is applied as `($n IS NULL OR col = $n)` so a `None` matches everything.
    pub async fn search_events(&self, f: &EventFilter, limit: i64) -> Result<Vec<DecisionEvent>> {
        let rows: Vec<EventRow> = sqlx::query_as::<_, EventRow>(
            "SELECT request_id, ts, node, method, path, client_ip, decision, rule_id, reason, score, contributions \
             FROM decision_events \
             WHERE ($1::text IS NULL OR rule_id = $1) \
               AND ($2::text IS NULL OR decision = $2) \
               AND ($3::text IS NULL OR client_ip = $3) \
             ORDER BY ts DESC LIMIT $4",
        )
        .bind(&f.rule_id)
        .bind(&f.decision)
        .bind(&f.client_ip)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// Aggregate the denied events into an API attack-surface inventory (§4-B pt3 discovery): one row
    /// per observed `(method, raw path)` with a hit count and first/last-seen. Path-templating and
    /// classification against the spec happen in [`crate::inventory`] (SQL cannot collapse per-id
    /// paths). `decision_events` holds only denied requests, so this is the attack surface, not all
    /// traffic. `limit` caps the DISTINCT raw paths aggregated.
    pub async fn api_inventory(&self, limit: i64) -> Result<Vec<crate::inventory::ObservedPath>> {
        let rows: Vec<InventoryRow> = sqlx::query_as::<_, InventoryRow>(
            "SELECT method, path, COUNT(*)::bigint AS hits, MIN(ts) AS first_seen, MAX(ts) AS last_seen \
             FROM decision_events \
             WHERE path IS NOT NULL AND method IS NOT NULL \
             GROUP BY method, path \
             ORDER BY hits DESC, path ASC \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| crate::inventory::ObservedPath {
                method: r.method,
                path: r.path,
                hits: r.hits,
                first_seen: r.first_seen,
                last_seen: r.last_seen,
            })
            .collect())
    }

    /// Denied-event counts bucketed in time since `since`, per `bucket_seconds` and decision (for
    /// the UI events-over-time chart). Aggregation is done in SQL — raw events never leave the DB.
    /// `bucket_seconds` is a caller-validated whitelisted value (never free-form) — a bad bucket
    /// would only make an odd chart, not a query injection (it is bound, not inlined).
    pub async fn events_series(
        &self,
        since: OffsetDateTime,
        bucket_seconds: i64,
    ) -> Result<Vec<(OffsetDateTime, String, i64)>> {
        let rows = sqlx::query_as::<_, (OffsetDateTime, String, i64)>(
            "SELECT to_timestamp(floor(extract(epoch from ts) / $2) * $2) AS t, decision, COUNT(*)::bigint \
             FROM decision_events WHERE ts >= $1 \
             GROUP BY t, decision ORDER BY t",
        )
        .bind(since)
        .bind(bucket_seconds)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Scraped nodes and the timestamp they were last seen (cluster status), from the reset-aware
    /// totals the scraper maintains (so a node stays listed across a WAF restart).
    pub async fn cluster_status(&self) -> Result<Vec<(String, OffsetDateTime)>> {
        let rows = sqlx::query_as::<_, (String, OffsetDateTime)>(
            "SELECT node, max(updated_at) FROM metric_totals GROUP BY node ORDER BY node",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Cumulative per-decision totals (dashboard volumes). Reads the reset-aware running totals the
    /// scraper accumulates, so the counts keep climbing across WAF restarts instead of dropping to
    /// the post-restart counter snapshot.
    pub async fn decision_totals(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT decision, SUM(cumulative)::bigint FROM metric_totals GROUP BY decision ORDER BY decision",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Nodes that have any latency samples.
    pub async fn latency_nodes(&self) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>("SELECT DISTINCT node FROM latency_totals ORDER BY node")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// The reset-aware LIFETIME latency histogram for `node`, sorted by `le` (for quantile
    /// computation). Unlike the latest raw snapshot, this survives WAF restarts (percentiles then
    /// reflect all observed traffic, not just since the last restart). Bucket monotonicity in `le`
    /// is preserved: a reset is process-wide, so every bucket drops on the same scrape.
    pub async fn lifetime_latency_buckets(&self, node: &str) -> Result<Vec<LatencyBucket>> {
        let rows = sqlx::query_as::<_, (f64, i64)>(
            "SELECT le, cumulative FROM latency_totals WHERE node = $1 ORDER BY le",
        )
        .bind(node)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(le, count)| LatencyBucket { le, count }).collect())
    }

    /// Fold one scrape's per-decision counters into the reset-aware `metric_totals`. For each
    /// (node, decision) the running total gains the delta since `last_raw`, or the raw value itself
    /// when the counter went backwards (a WAF restart), then records the new raw value.
    pub async fn accumulate_metric_totals(
        &self,
        node: &str,
        counts: &[DecisionCount],
        ts: OffsetDateTime,
    ) -> Result<()> {
        for c in counts {
            sqlx::query(
                "INSERT INTO metric_totals (node, decision, cumulative, last_raw, updated_at) \
                 VALUES ($1, $2, $3, $3, $4) \
                 ON CONFLICT (node, decision) DO UPDATE SET \
                   cumulative = metric_totals.cumulative + \
                     CASE WHEN $3 >= metric_totals.last_raw THEN $3 - metric_totals.last_raw ELSE $3 END, \
                   last_raw = $3, \
                   updated_at = $4",
            )
            .bind(node)
            .bind(&c.decision)
            .bind(c.count)
            .bind(ts)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Fold one scrape's latency histogram into the reset-aware `latency_totals` (same delta/reset
    /// rule as [`Store::accumulate_metric_totals`], keyed per bucket `le`).
    pub async fn accumulate_latency_totals(
        &self,
        node: &str,
        buckets: &[LatencyBucket],
        ts: OffsetDateTime,
    ) -> Result<()> {
        for b in buckets {
            sqlx::query(
                "INSERT INTO latency_totals (node, le, cumulative, last_raw, updated_at) \
                 VALUES ($1, $2, $3, $3, $4) \
                 ON CONFLICT (node, le) DO UPDATE SET \
                   cumulative = latency_totals.cumulative + \
                     CASE WHEN $3 >= latency_totals.last_raw THEN $3 - latency_totals.last_raw ELSE $3 END, \
                   last_raw = $3, \
                   updated_at = $4",
            )
            .bind(node)
            .bind(b.le)
            .bind(b.count)
            .bind(ts)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    /// Count denied events matching a rule's filters since `since`, grouped per the rule's
    /// `group_by` (one `("", n)` row when ungrouped). The grouped column is a fixed literal from
    /// the `GroupBy` enum — never user input — so inlining it in the SQL is injection-safe.
    pub async fn count_events_grouped(
        &self,
        rule: &AlertRule,
        since: OffsetDateTime,
    ) -> Result<Vec<(String, i64)>> {
        let (select_gk, group_clause) = match rule.group_by.column() {
            None => ("''::text".to_string(), String::new()),
            Some(c) => (format!("COALESCE({c}, '')"), format!(" GROUP BY {c}")),
        };
        let sql = format!(
            "SELECT {select_gk} AS gk, COUNT(*)::bigint AS n FROM decision_events \
             WHERE ts >= $1 \
               AND ($2::text IS NULL OR decision = $2) \
               AND ($3::text IS NULL OR rule_id = $3) \
               AND ($4::text IS NULL OR client_ip = $4){group_clause}"
        );
        let rows = sqlx::query_as::<_, (String, i64)>(&sql)
            .bind(since)
            .bind(&rule.decision)
            .bind(&rule.rule_id)
            .bind(&rule.client_ip)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// The most recent fire time for `(rule_name, group_key)` — the cooldown/dedup key. `None` if
    /// this pair has never fired.
    pub async fn last_alert_fired(
        &self,
        rule_name: &str,
        group_key: &str,
    ) -> Result<Option<OffsetDateTime>> {
        let row = sqlx::query_as::<_, (Option<OffsetDateTime>,)>(
            "SELECT max(fired_at) FROM alerts WHERE rule_name = $1 AND group_key = $2",
        )
        .bind(rule_name)
        .bind(group_key)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.0)
    }

    /// Record a fired alert.
    pub async fn insert_alert(&self, a: &Alert) -> Result<()> {
        sqlx::query(
            "INSERT INTO alerts (rule_name, group_key, fired_at, severity, value, threshold, summary) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&a.rule_name)
        .bind(&a.group_key)
        .bind(a.fired_at)
        .bind(&a.severity)
        .bind(a.value)
        .bind(a.threshold)
        .bind(&a.summary)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// The `limit` most recent fired alerts, newest first (`GET /api/alerts`).
    pub async fn recent_alerts(&self, limit: i64) -> Result<Vec<Alert>> {
        let rows = sqlx::query_as::<_, (String, String, OffsetDateTime, String, i64, i64, String)>(
            "SELECT rule_name, group_key, fired_at, severity, value, threshold, summary \
             FROM alerts ORDER BY fired_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(rule_name, group_key, fired_at, severity, value, threshold, summary)| Alert {
                rule_name,
                group_key,
                fired_at,
                severity,
                value,
                threshold,
                summary,
            })
            .collect())
    }

    /// Store one scrape's latency histogram (one row per bucket, common `ts`/`node`).
    pub async fn insert_latency_buckets(
        &self,
        node: &str,
        ts: OffsetDateTime,
        buckets: &[LatencyBucket],
    ) -> Result<()> {
        for b in buckets {
            sqlx::query("INSERT INTO latency_buckets (ts, node, le, count) VALUES ($1, $2, $3, $4)")
                .bind(ts)
                .bind(node)
                .bind(b.le)
                .bind(b.count)
                .execute(&self.pool)
                .await?;
        }
        Ok(())
    }

    /// Insert one scraped per-decision counter snapshot (metrics ingestion, Phase 2).
    pub async fn insert_metric_rollup(&self, r: &MetricRollup) -> Result<()> {
        sqlx::query("INSERT INTO metric_rollups (ts, node, decision, count) VALUES ($1, $2, $3, $4)")
            .bind(r.ts)
            .bind(&r.node)
            .bind(&r.decision)
            .bind(r.count)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // ── Rule management (§7 write-path, v3) ────────────────────────────────────────────────────

    /// Publish a new immutable ruleset version AND make it current, atomically (insert + re-point in
    /// one transaction). Returns the new version id.
    pub async fn publish_rule_version(&self, content: &str, author: &str, note: &str) -> Result<i64> {
        let mut tx = self.pool.begin().await?;
        let (id,): (i64,) = sqlx::query_as(
            "INSERT INTO rule_versions (content, author, note) VALUES ($1, $2, $3) RETURNING id",
        )
        .bind(content)
        .bind(author)
        .bind(note)
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO rule_current (singleton, version_id) VALUES (true, $1) \
             ON CONFLICT (singleton) DO UPDATE SET version_id = EXCLUDED.version_id",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Re-point `rule_current` to an existing version (rollback). Returns `false` (no change) if the
    /// version id does not exist.
    pub async fn set_current_rule_version(&self, version_id: i64) -> Result<bool> {
        let exists: Option<(i64,)> =
            sqlx::query_as("SELECT id FROM rule_versions WHERE id = $1")
                .bind(version_id)
                .fetch_optional(&self.pool)
                .await?;
        if exists.is_none() {
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO rule_current (singleton, version_id) VALUES (true, $1) \
             ON CONFLICT (singleton) DO UPDATE SET version_id = EXCLUDED.version_id",
        )
        .bind(version_id)
        .execute(&self.pool)
        .await?;
        Ok(true)
    }

    /// The current (live) ruleset version, or `None` if nothing has been published yet.
    pub async fn current_rule_version(&self) -> Result<Option<RuleVersion>> {
        let row = sqlx::query_as::<_, (i64, String, String, String, OffsetDateTime)>(
            "SELECT v.id, v.content, v.author, v.note, v.created_at \
             FROM rule_current c JOIN rule_versions v ON v.id = c.version_id WHERE c.singleton = true",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, content, author, note, created_at)| RuleVersion {
            id,
            content,
            author,
            note,
            created_at,
        }))
    }

    /// A single version by id (full content), or `None` if unknown.
    pub async fn get_rule_version(&self, id: i64) -> Result<Option<RuleVersion>> {
        let row = sqlx::query_as::<_, (i64, String, String, String, OffsetDateTime)>(
            "SELECT id, content, author, note, created_at FROM rule_versions WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(id, content, author, note, created_at)| RuleVersion {
            id,
            content,
            author,
            note,
            created_at,
        }))
    }

    /// The `limit` most recent versions (metadata only, newest first), each flagged whether it is the
    /// current/live one.
    pub async fn list_rule_versions(&self, limit: i64) -> Result<Vec<RuleVersionMeta>> {
        let rows = sqlx::query_as::<_, (i64, String, String, OffsetDateTime, bool)>(
            "SELECT v.id, v.author, v.note, v.created_at, COALESCE(c.version_id = v.id, false) AS current \
             FROM rule_versions v LEFT JOIN rule_current c ON c.singleton = true \
             ORDER BY v.id DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, author, note, created_at, current)| RuleVersionMeta {
                id,
                author,
                note,
                created_at,
                current,
            })
            .collect())
    }

    /// Record (upsert) a node's applied-version + apply outcome (convergence report from the agent).
    pub async fn record_node_rule_status(
        &self,
        node: &str,
        applied_version: Option<i64>,
        status: &str,
        detail: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO node_rule_status (node, applied_version, status, detail, reported_at) \
             VALUES ($1, $2, $3, $4, now()) \
             ON CONFLICT (node) DO UPDATE SET \
               applied_version = EXCLUDED.applied_version, \
               status = EXCLUDED.status, \
               detail = EXCLUDED.detail, \
               reported_at = now()",
        )
        .bind(node)
        .bind(applied_version)
        .bind(status)
        .bind(detail)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Every node's last-reported rule status (convergence view), ordered by node.
    pub async fn list_node_rule_status(&self) -> Result<Vec<NodeRuleStatus>> {
        let rows = sqlx::query_as::<_, (String, Option<i64>, String, String, OffsetDateTime)>(
            "SELECT node, applied_version, status, detail, reported_at FROM node_rule_status ORDER BY node",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(node, applied_version, status, detail, reported_at)| NodeRuleStatus {
                node,
                applied_version,
                status,
                detail,
                reported_at,
            })
            .collect())
    }

    // ── Compliance report period queries (§8) ──────────────────────────────────────────────────

    /// Denied-event counts by decision within `[from, to]` (period-accurate — every denied event has
    /// its own timestamped row). Allowed/total traffic is NOT here (only denied events are stored);
    /// the report reads cumulative counters for that, with a stated caveat.
    pub async fn decision_counts_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
    ) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT decision, COUNT(*)::bigint FROM decision_events \
             WHERE ts >= $1 AND ts <= $2 GROUP BY decision ORDER BY decision",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// The top `limit` `rule_id`s by denied-event count within `[from, to]` (most-triggered rules).
    pub async fn top_rules_between(
        &self,
        from: OffsetDateTime,
        to: OffsetDateTime,
        limit: i64,
    ) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT rule_id, COUNT(*)::bigint AS n FROM decision_events \
             WHERE ts >= $1 AND ts <= $2 AND rule_id IS NOT NULL \
             GROUP BY rule_id ORDER BY n DESC, rule_id LIMIT $3",
        )
        .bind(from)
        .bind(to)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Distinct nodes that reported metrics within `[from, to]` (coverage in the period).
    pub async fn nodes_between(&self, from: OffsetDateTime, to: OffsetDateTime) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>(
            "SELECT DISTINCT node FROM metric_rollups WHERE ts >= $1 AND ts <= $2 ORDER BY node",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// Fired alerts within `[from, to]`, newest first (incident evidence).
    pub async fn alerts_between(&self, from: OffsetDateTime, to: OffsetDateTime) -> Result<Vec<Alert>> {
        let rows = sqlx::query_as::<_, (String, String, OffsetDateTime, String, i64, i64, String)>(
            "SELECT rule_name, group_key, fired_at, severity, value, threshold, summary \
             FROM alerts WHERE fired_at >= $1 AND fired_at <= $2 ORDER BY fired_at DESC",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(rule_name, group_key, fired_at, severity, value, threshold, summary)| Alert {
                rule_name,
                group_key,
                fired_at,
                severity,
                value,
                threshold,
                summary,
            })
            .collect())
    }

    // ── SIEM export (§9): cursors + since-queries + stream heads ────────────────────────────────

    /// The last exported id/seq for `(destination, stream)` — `0` (nothing exported) if absent.
    pub async fn siem_get_cursor(&self, destination: &str, stream: &str) -> Result<i64> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT last_id FROM siem_cursors WHERE destination = $1 AND stream = $2")
                .bind(destination)
                .bind(stream)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v).unwrap_or(0))
    }

    /// Advance (upsert) the cursor for `(destination, stream)` — called ONLY after a whole batch is
    /// acked (at-least-once).
    pub async fn siem_set_cursor(&self, destination: &str, stream: &str, last_id: i64) -> Result<()> {
        sqlx::query(
            "INSERT INTO siem_cursors (destination, stream, last_id, updated_at) VALUES ($1, $2, $3, now()) \
             ON CONFLICT (destination, stream) DO UPDATE SET last_id = EXCLUDED.last_id, updated_at = now()",
        )
        .bind(destination)
        .bind(stream)
        .bind(last_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Denied events with `id > after`, ascending, capped at `limit` — one export batch (with their ids).
    pub async fn fetch_decisions_since(&self, after: i64, limit: i64) -> Result<Vec<(i64, DecisionEvent)>> {
        let rows: Vec<DecisionIdRow> = sqlx::query_as::<_, DecisionIdRow>(
            "SELECT id, request_id, ts, node, method, path, client_ip, decision, rule_id, reason, score, contributions \
             FROM decision_events WHERE id > $1 ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// The highest `decision_events.id` (0 if empty) — for the export lag.
    pub async fn decisions_max_id(&self) -> Result<i64> {
        let (m,): (i64,) = sqlx::query_as("SELECT COALESCE(max(id), 0) FROM decision_events")
            .fetch_one(&self.pool)
            .await?;
        Ok(m)
    }

    /// Fired alerts with `id > after`, ascending, capped at `limit` (with their ids).
    pub async fn fetch_alerts_since(&self, after: i64, limit: i64) -> Result<Vec<(i64, Alert)>> {
        let rows = sqlx::query_as::<_, (i64, String, String, OffsetDateTime, String, i64, i64, String)>(
            "SELECT id, rule_name, group_key, fired_at, severity, value, threshold, summary \
             FROM alerts WHERE id > $1 ORDER BY id LIMIT $2",
        )
        .bind(after)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(id, rule_name, group_key, fired_at, severity, value, threshold, summary)| {
                (id, Alert { rule_name, group_key, fired_at, severity, value, threshold, summary })
            })
            .collect())
    }

    /// The highest `alerts.id` (0 if empty).
    pub async fn alerts_max_id(&self) -> Result<i64> {
        let (m,): (i64,) =
            sqlx::query_as("SELECT COALESCE(max(id), 0) FROM alerts").fetch_one(&self.pool).await?;
        Ok(m)
    }

    /// Delete telemetry older than `days` (retention). `0` keeps everything. Returns rows removed.
    pub async fn prune_older_than_days(&self, days: u32) -> Result<u64> {
        if days == 0 {
            return Ok(0);
        }
        let interval = format!("{days} days");
        let a = sqlx::query("DELETE FROM decision_events WHERE ts < now() - $1::interval")
            .bind(&interval)
            .execute(&self.pool)
            .await?;
        let b = sqlx::query("DELETE FROM metric_rollups WHERE ts < now() - $1::interval")
            .bind(&interval)
            .execute(&self.pool)
            .await?;
        let c = sqlx::query("DELETE FROM latency_buckets WHERE ts < now() - $1::interval")
            .bind(&interval)
            .execute(&self.pool)
            .await?;
        let d = sqlx::query("DELETE FROM alerts WHERE fired_at < now() - $1::interval")
            .bind(&interval)
            .execute(&self.pool)
            .await?;
        Ok(a.rows_affected() + b.rows_affected() + c.rows_affected() + d.rows_affected())
    }

    /// Hard-delete captured requests older than `hours` (their own retention window — typically much
    /// shorter than the telemetry `retention_days`, since captures hold raw request material). `0`
    /// keeps everything. Returns rows removed.
    pub async fn prune_captures_older_than_hours(&self, hours: u32) -> Result<u64> {
        if hours == 0 {
            return Ok(0);
        }
        let interval = format!("{hours} hours");
        let r = sqlx::query("DELETE FROM request_captures WHERE captured_at < now() - $1::interval")
            .bind(&interval)
            .execute(&self.pool)
            .await?;
        Ok(r.rows_affected())
    }
}

// ── Env-gated integration test (needs a live Postgres) ────────────────────────────────────────
// Set WAF_CP_DATABASE_URL to run it (e.g. `docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=pw postgres:16`
// then WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost/postgres). Skipped (passes) when unset —
// mirrors the Redis integration tests' gating.
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event(request_id: &str) -> DecisionEvent {
        DecisionEvent {
            request_id: request_id.to_string(),
            ts: OffsetDateTime::now_utc(),
            node: "edge-1".to_string(),
            method: Some("GET".to_string()),
            path: Some("/".to_string()),
            client_ip: Some("203.0.113.7".to_string()),
            decision: "blocked".to_string(),
            rule_id: Some("sqli-union-select".to_string()),
            reason: Some("anomaly score exceeded".to_string()),
            score: 5,
            contributions: vec![Contribution {
                module: "sqli".to_string(),
                rule_id: "sqli-union-select".to_string(),
                severity: Some("critical".to_string()),
                points: 5,
            }],
        }
    }

    #[tokio::test]
    async fn store_roundtrip_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        // Unique id so repeated runs against the same DB don't collide.
        let rid = format!("req-test-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let ev = sample_event(&rid);
        store.insert_decision_event(&ev).await.expect("insert");

        let got = store.get_decision_event(&rid).await.expect("get").expect("present");
        assert_eq!(got.request_id, ev.request_id);
        assert_eq!(got.decision, "blocked");
        assert_eq!(got.contributions, ev.contributions, "JSONB contributions must round-trip typed");

        let recent = store.recent_events(10).await.expect("recent");
        assert!(recent.iter().any(|e| e.request_id == rid));

        // Rollup insert + a no-op prune (days=0) both succeed.
        store
            .insert_metric_rollup(&MetricRollup {
                ts: OffsetDateTime::now_utc(),
                node: "edge-1".to_string(),
                decision: "blocked".to_string(),
                count: 42,
            })
            .await
            .expect("rollup");
        assert_eq!(store.prune_older_than_days(0).await.expect("prune noop"), 0);
    }

    fn sample_capture(request_id: &str) -> CapturedRequest {
        CapturedRequest {
            request_id: request_id.to_string(),
            method: "POST".to_string(),
            path: "/login".to_string(),
            query: Some("next=/admin".to_string()),
            http_version: "HTTP/1.1".to_string(),
            headers: vec![("user-agent".to_string(), "curl/8".to_string())],
            cookies: vec![("sid".to_string(), "***REDACTED***".to_string())],
            // base64 of `{"user":"a"}`
            body_b64: base64::engine::general_purpose::STANDARD.encode(br#"{"user":"a"}"#),
            body_size: 12,
            body_truncated: false,
            redacted: vec!["sid".to_string()],
        }
    }

    #[tokio::test]
    async fn capture_store_roundtrip_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        let rid = format!("cap-test-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let cap = sample_capture(&rid);
        store.insert_capture("edge-1", &cap).await.expect("insert capture");
        // Idempotent re-delivery (shipper retry) is absorbed, not an error.
        store.insert_capture("edge-1", &cap).await.expect("re-insert absorbed");

        let got = store.get_capture(&rid).await.expect("get").expect("present");
        assert_eq!(got, cap, "capture must round-trip (body via BYTEA↔base64, JSONB headers/cookies)");
        assert!(got.redacted.contains(&"sid".to_string()));

        // No-op prune (hours=0 keeps everything); a huge window removes nothing recent.
        assert_eq!(store.prune_captures_older_than_hours(0).await.expect("noop"), 0);
        assert_eq!(store.prune_captures_older_than_hours(24 * 365).await.expect("wide"), 0);
    }

    #[tokio::test]
    async fn api_inventory_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        // A unique, non-numeric prefix so our rows don't collide with other tests' events and are
        // not themselves collapsed by templating.
        let nonce = format!("inv{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let prefix = format!("/api/{nonce}");
        let mk = |rid: &str, path: &str| {
            let mut ev = sample_event(rid);
            ev.path = Some(path.to_string());
            ev
        };
        // Two per-id paths (must fold) + one shadow endpoint, all denied (blocked).
        store.insert_decision_event(&mk(&format!("{nonce}-a"), &format!("{prefix}/users/5"))).await.unwrap();
        store.insert_decision_event(&mk(&format!("{nonce}-b"), &format!("{prefix}/users/6"))).await.unwrap();
        store.insert_decision_event(&mk(&format!("{nonce}-c"), &format!("{prefix}/secrets"))).await.unwrap();

        let observed = store.api_inventory(50_000).await.expect("inventory");

        // Classify against a spec declaring ONLY `<prefix>/users/{id}` (GET).
        let mut paths = serde_json::Map::new();
        paths.insert(format!("{prefix}/users/{{id}}"), serde_json::json!({ "get": {} }));
        let spec = serde_json::json!({
            "openapi": "3.0.3",
            "info": { "title": "t", "version": "1" },
            "paths": paths,
        })
        .to_string();
        let routes = crate::inventory::SpecRoutes::from_spec_json(&spec).unwrap();
        let inv = crate::inventory::build_inventory(observed, Some(&routes));

        let users = inv
            .iter()
            .find(|e| e.path == format!("{prefix}/users/{{}}"))
            .expect("the two per-id paths fold into one templated endpoint");
        assert_eq!(users.hits, 2, "GET /users/5 and /users/6 fold and their hits sum");
        assert_eq!(users.classification, crate::inventory::Classification::Documented);

        let secrets = inv
            .iter()
            .find(|e| e.path == format!("{prefix}/secrets"))
            .expect("undeclared endpoint present");
        assert_eq!(secrets.classification, crate::inventory::Classification::Shadow);
    }

    #[tokio::test]
    async fn phase3_queries_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let node = format!("q-node-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());

        // Search by filter finds an inserted event.
        let rid = format!("q-req-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let mut ev = sample_event(&rid);
        ev.node = node.clone();
        store.insert_decision_event(&ev).await.expect("insert");
        let hits = store
            .search_events(&EventFilter { rule_id: Some("sqli-union-select".into()), ..Default::default() }, 50)
            .await
            .expect("search");
        assert!(hits.iter().any(|e| e.request_id == rid));

        // Scrape accumulation → decision_totals + cluster_status see this node (reset-aware totals).
        store
            .accumulate_metric_totals(
                &node,
                &[DecisionCount { decision: "blocked".into(), count: 9 }],
                OffsetDateTime::now_utc(),
            )
            .await
            .expect("totals");
        assert!(store.cluster_status().await.expect("status").iter().any(|(n, _)| *n == node));
        assert!(store.decision_totals().await.expect("totals").iter().any(|(d, t)| d == "blocked" && *t >= 9));

        // Latency buckets → lifetime histogram round-trips and feeds the quantile.
        let buckets = vec![
            LatencyBucket { le: 0.001, count: 5 },
            LatencyBucket { le: 0.01, count: 9 },
            LatencyBucket { le: f64::INFINITY, count: 10 },
        ];
        store.accumulate_latency_totals(&node, &buckets, OffsetDateTime::now_utc()).await.expect("lat totals");
        assert!(store.latency_nodes().await.expect("nodes").contains(&node));
        let got = store.lifetime_latency_buckets(&node).await.expect("lifetime");
        assert_eq!(got.len(), 3);
        assert!(got.last().unwrap().le.is_infinite());

        // events_series: the event inserted above (decision=blocked) shows up in a recent bucket.
        let since = OffsetDateTime::now_utc() - time::Duration::seconds(3600);
        let series = store.events_series(since, 300).await.expect("series");
        assert!(
            series.iter().any(|(t, decision, count)| *decision == "blocked"
                && *count >= 1
                && *t >= since),
            "series must contain a recent blocked bucket, got {series:?}",
        );
    }

    // The reset-aware accumulation keeps climbing when the WAF counter restarts (the reason the
    // dashboard's Overview volumes must not drop to the post-restart snapshot).
    #[tokio::test]
    async fn metric_totals_reset_aware_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let node = format!("reset-node-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let now = OffsetDateTime::now_utc();

        // Counter climbs 100 → 150, the WAF restarts (drops to 5), then climbs to 20.
        for raw in [100_i64, 150, 5, 20] {
            store
                .accumulate_metric_totals(&node, &[DecisionCount { decision: "blocked".into(), count: raw }], now)
                .await
                .expect("acc");
        }
        // Reset-aware total = 150 + 5 + 15 = 170 (NOT the latest raw snapshot of 20).
        let cum: (i64,) = sqlx::query_as("SELECT cumulative FROM metric_totals WHERE node = $1 AND decision = 'blocked'")
            .bind(&node)
            .fetch_one(store.pool())
            .await
            .expect("read cumulative");
        assert_eq!(cum.0, 170, "reset-aware total = 150 + 5 + 15");

        // Latency histogram accumulates per bucket and stays monotonic in `le` across a reset.
        let h1 = vec![LatencyBucket { le: 0.01, count: 8 }, LatencyBucket { le: f64::INFINITY, count: 10 }];
        let h2 = vec![LatencyBucket { le: 0.01, count: 3 }, LatencyBucket { le: f64::INFINITY, count: 4 }]; // reset
        store.accumulate_latency_totals(&node, &h1, now).await.expect("l1");
        store.accumulate_latency_totals(&node, &h2, now).await.expect("l2");
        let life = store.lifetime_latency_buckets(&node).await.expect("life");
        assert_eq!(life.iter().find(|b| (b.le - 0.01).abs() < 1e-9).unwrap().count, 11); // 8 + 3
        assert_eq!(life.iter().find(|b| b.le.is_infinite()).unwrap().count, 14); // 10 + 4
        assert!(life.windows(2).all(|w| w[0].count <= w[1].count), "buckets stay monotonic in le");
    }

    #[tokio::test]
    async fn v2_alert_queries_env_gated() {
        use crate::config::{AlertRule, GroupBy};
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        // A unique rule_id isolates these events from any other rows in a shared test DB.
        let uniq = format!("test-rule-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let mut i = 0;
        for (ip, n) in [("9.9.9.9", 2usize), ("8.8.8.8", 1usize)] {
            for _ in 0..n {
                let mut ev = sample_event(&format!("v2-{uniq}-{i}"));
                ev.rule_id = Some(uniq.clone());
                ev.client_ip = Some(ip.to_string());
                store.insert_decision_event(&ev).await.expect("insert");
                i += 1;
            }
        }

        // Grouped count by client_ip, filtered to our unique rule_id → {9.9.9.9:2, 8.8.8.8:1}.
        let rule = AlertRule {
            name: "t".into(),
            decision: Some("blocked".into()),
            rule_id: Some(uniq.clone()),
            client_ip: None,
            group_by: GroupBy::ClientIp,
            window_seconds: 3600,
            threshold: 2,
            severity: "critical".into(),
            cooldown_seconds: 300,
        };
        let since = OffsetDateTime::now_utc() - time::Duration::seconds(3600);
        let counts = store.count_events_grouped(&rule, since).await.expect("count");
        assert_eq!(counts.iter().find(|(g, _)| g == "9.9.9.9").map(|(_, n)| *n), Some(2));
        assert_eq!(counts.iter().find(|(g, _)| g == "8.8.8.8").map(|(_, n)| *n), Some(1));

        // Alert insert + cooldown lookup + recent listing.
        assert!(store.last_alert_fired(&uniq, "9.9.9.9").await.expect("last").is_none());
        store
            .insert_alert(&Alert {
                rule_name: uniq.clone(),
                group_key: "9.9.9.9".into(),
                fired_at: OffsetDateTime::now_utc(),
                severity: "critical".into(),
                value: 2,
                threshold: 2,
                summary: "burst".into(),
            })
            .await
            .expect("insert alert");
        assert!(store.last_alert_fired(&uniq, "9.9.9.9").await.expect("last").is_some());
        assert!(store.recent_alerts(100).await.expect("recent").iter().any(|a| a.rule_name == uniq));
    }

    #[tokio::test]
    async fn rule_versions_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        // Publish v1 → it becomes current.
        let v1 = store.publish_rule_version("SecRule ARGS \"@rx v1\" \"id:1\"", "alice", "first").await.expect("publish v1");
        let cur = store.current_rule_version().await.expect("current").expect("some");
        assert_eq!(cur.id, v1);
        assert!(cur.content.contains("v1"));

        // Publish v2 → current moves to v2 (v1 stays immutable).
        let v2 = store.publish_rule_version("SecRule ARGS \"@rx v2\" \"id:2\"", "alice", "second").await.expect("publish v2");
        assert_eq!(store.current_rule_version().await.expect("current").unwrap().id, v2);
        assert!(store.get_rule_version(v1).await.expect("get v1").unwrap().content.contains("v1"));

        // Listing flags exactly the current version; both appear, newest first.
        let list = store.list_rule_versions(100).await.expect("list");
        let m1 = list.iter().find(|m| m.id == v1).expect("v1 listed");
        let m2 = list.iter().find(|m| m.id == v2).expect("v2 listed");
        assert!(!m1.current, "v1 not current after v2 publish");
        assert!(m2.current, "v2 is current");

        // Rollback = re-point current to v1; a non-existent version does nothing.
        assert!(store.set_current_rule_version(v1).await.expect("rollback"));
        assert_eq!(store.current_rule_version().await.expect("current").unwrap().id, v1);
        assert!(!store.set_current_rule_version(-1).await.expect("rollback to missing"));

        // Node convergence: upsert reports; the latest wins per node.
        let node = format!("rule-node-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        store.record_node_rule_status(&node, Some(v1), "applied", "").await.expect("status 1");
        store.record_node_rule_status(&node, Some(v2), "rejected", "parse error").await.expect("status 2");
        let statuses = store.list_node_rule_status().await.expect("list statuses");
        let s = statuses.iter().find(|s| s.node == node).expect("node status present");
        assert_eq!(s.applied_version, Some(v2));
        assert_eq!(s.status, "rejected");
        assert_eq!(s.detail, "parse error");
    }

    #[tokio::test]
    async fn compliance_period_queries_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let from = OffsetDateTime::now_utc() - time::Duration::minutes(5);

        // A unique rule id fires twice, another once → deterministic top-rules within the window.
        let hot = format!("hot-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let cold = format!("cold-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        for (rid, n) in [(&hot, 2), (&cold, 1)] {
            for i in 0..n {
                let mut ev = sample_event(&format!("cp-{rid}-{i}"));
                ev.rule_id = Some(rid.clone());
                store.insert_decision_event(&ev).await.expect("insert");
            }
        }
        let to = OffsetDateTime::now_utc() + time::Duration::minutes(5);

        // Denied counts in-period include our blocked events; a past-only window is empty.
        let counts = store.decision_counts_between(from, to).await.expect("counts");
        assert!(counts.iter().find(|(d, _)| d == "blocked").map(|(_, n)| *n).unwrap_or(0) >= 3);
        let empty = store
            .decision_counts_between(from - time::Duration::hours(2), from - time::Duration::hours(1))
            .await
            .expect("empty");
        assert!(empty.iter().all(|(_, n)| *n == 0) || empty.is_empty());

        // Top rules: hot (2) ranks above cold (1).
        let top = store.top_rules_between(from, to, 50).await.expect("top");
        let hp = top.iter().position(|(r, _)| *r == hot).expect("hot present");
        let cp = top.iter().position(|(r, _)| *r == cold).expect("cold present");
        assert!(hp < cp, "hot rule must rank above cold: {top:?}");
        assert_eq!(top.iter().find(|(r, _)| *r == hot).map(|(_, n)| *n), Some(2));

        // nodes_between + alerts_between round-trip within the window.
        let node = format!("cnode-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        store
            .insert_metric_rollup(&MetricRollup { ts: OffsetDateTime::now_utc(), node: node.clone(), decision: "blocked".into(), count: 1 })
            .await
            .expect("rollup");
        assert!(store.nodes_between(from, to).await.expect("nodes").contains(&node));

        let arule = format!("arule-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        store
            .insert_alert(&Alert {
                rule_name: arule.clone(),
                group_key: "1.2.3.4".into(),
                fired_at: OffsetDateTime::now_utc(),
                severity: "critical".into(),
                value: 5,
                threshold: 3,
                summary: "burst".into(),
            })
            .await
            .expect("alert");
        assert!(store.alerts_between(from, to).await.expect("alerts").iter().any(|a| a.rule_name == arule));
    }
}
