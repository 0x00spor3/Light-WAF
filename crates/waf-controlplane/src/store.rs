// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Postgres store for the control plane. Runtime queries (no compile-time `query!` macro) so the
//! crate builds with no database; only the env-gated integration test needs a live Postgres.

use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::types::Json;
use time::OffsetDateTime;

use crate::config::AlertRule;
use crate::error::Result;
use crate::model::{Alert, Contribution, DecisionEvent, MetricRollup};
use crate::prometheus::LatencyBucket;

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

    /// Scraped nodes and the timestamp of their most recent rollup (cluster status).
    pub async fn cluster_status(&self) -> Result<Vec<(String, OffsetDateTime)>> {
        let rows = sqlx::query_as::<_, (String, OffsetDateTime)>(
            "SELECT node, max(ts) FROM metric_rollups GROUP BY node ORDER BY node",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Current per-decision totals: the latest counter snapshot per (node, decision), summed by
    /// decision (dashboard volumes).
    pub async fn decision_totals(&self) -> Result<Vec<(String, i64)>> {
        let rows = sqlx::query_as::<_, (String, i64)>(
            "SELECT decision, SUM(count)::bigint FROM ( \
               SELECT DISTINCT ON (node, decision) node, decision, count \
               FROM metric_rollups ORDER BY node, decision, ts DESC \
             ) latest GROUP BY decision ORDER BY decision",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Nodes that have any latency samples.
    pub async fn latency_nodes(&self) -> Result<Vec<String>> {
        let rows = sqlx::query_as::<_, (String,)>("SELECT DISTINCT node FROM latency_buckets ORDER BY node")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|(n,)| n).collect())
    }

    /// The latest latency histogram snapshot for `node`, sorted by `le` (for quantile computation).
    pub async fn latest_latency_buckets(&self, node: &str) -> Result<Vec<LatencyBucket>> {
        let rows = sqlx::query_as::<_, (f64, i64)>(
            "SELECT le, count FROM latency_buckets \
             WHERE node = $1 AND ts = (SELECT max(ts) FROM latency_buckets WHERE node = $1) \
             ORDER BY le",
        )
        .bind(node)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(|(le, count)| LatencyBucket { le, count }).collect())
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

        // Rollups → decision_totals + cluster_status see this node.
        store
            .insert_metric_rollup(&MetricRollup { ts: OffsetDateTime::now_utc(), node: node.clone(), decision: "blocked".into(), count: 9 })
            .await
            .expect("rollup");
        assert!(store.cluster_status().await.expect("status").iter().any(|(n, _)| *n == node));
        assert!(store.decision_totals().await.expect("totals").iter().any(|(d, t)| d == "blocked" && *t >= 9));

        // Latency buckets → latest snapshot round-trips and feeds the quantile.
        let buckets = vec![
            LatencyBucket { le: 0.001, count: 5 },
            LatencyBucket { le: 0.01, count: 9 },
            LatencyBucket { le: f64::INFINITY, count: 10 },
        ];
        store.insert_latency_buckets(&node, OffsetDateTime::now_utc(), &buckets).await.expect("latency");
        assert!(store.latency_nodes().await.expect("nodes").contains(&node));
        let got = store.latest_latency_buckets(&node).await.expect("latest");
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
}
