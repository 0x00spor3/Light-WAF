// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Alert evaluator (v2). A background loop that, every `eval_interval`, evaluates each configured
//! rule against the stored `decision_events`: when a rule's (per-group) count of denied events in
//! its window reaches the threshold — and the `(rule, group)` is out of cooldown — it records an
//! alert and (optionally) POSTs it to a webhook.
//!
//! Reads only the control-plane store; it never touches the WAF (zero-datapath). Delivery/query
//! failures are logged and the loop continues — a flaky webhook or a slow query never wedges alerting.

use std::time::Duration;

use time::OffsetDateTime;
use tracing::{info, warn};

use crate::config::AlertRule;
use crate::error::Result;
use crate::model::Alert;
use crate::store::Store;
use crate::stream::{EventBus, StreamKind};

/// Pure firing decision: the count reached the threshold AND the `(rule, group)` is out of cooldown.
/// Kept side-effect-free so it is unit-testable without a database.
pub fn should_fire(
    count: i64,
    threshold: i64,
    last_fired: Option<OffsetDateTime>,
    now: OffsetDateTime,
    cooldown_seconds: u64,
) -> bool {
    if count < threshold {
        return false;
    }
    match last_fired {
        None => true,
        Some(prev) => (now - prev) >= Duration::from_secs(cooldown_seconds),
    }
}

/// Human-readable summary carried on the alert (and in the webhook payload).
fn summary(rule: &AlertRule, group_key: &str, count: i64) -> String {
    match rule.group_by.column() {
        Some(col) => {
            format!("{}: {count} events ≥ {} for {col}={group_key}", rule.name, rule.threshold)
        }
        None => format!("{}: {count} events ≥ {}", rule.name, rule.threshold),
    }
}

/// Run the evaluator forever (spawn as a background task). No-op if no rules are configured.
pub async fn run_evaluator(
    store: Store,
    rules: Vec<AlertRule>,
    webhook_url: Option<String>,
    interval_secs: u64,
    bus: EventBus,
) {
    if rules.is_empty() {
        info!("alerting: no [[controlplane.alerts]] rules; evaluator idle");
        return;
    }
    let client = reqwest::Client::builder().timeout(Duration::from_secs(10)).build().ok();
    if webhook_url.is_some() && client.is_none() {
        warn!("alerting: could not build the webhook HTTP client; alerts will be stored but not delivered");
    }
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    info!(rules = rules.len(), webhook = webhook_url.is_some(), interval_s = interval_secs, "alerting: evaluator started");
    loop {
        ticker.tick().await;
        evaluate_once(&store, &rules, webhook_url.as_deref(), client.as_ref(), &bus).await;
    }
}

/// Run ONE evaluation pass over all rules (used by the loop and by tests). A per-rule error is
/// logged, not propagated, so one bad rule or a slow query never aborts the whole cycle.
pub async fn evaluate_once(
    store: &Store,
    rules: &[AlertRule],
    webhook_url: Option<&str>,
    client: Option<&reqwest::Client>,
    bus: &EventBus,
) {
    for rule in rules {
        if let Err(e) = evaluate_rule(store, rule, webhook_url, client, bus).await {
            warn!(rule = %rule.name, error = %e, "alert rule evaluation failed (skipping this cycle)");
        }
    }
}

/// Evaluate one rule against the current store state, firing (store + optional webhook) each group
/// that crosses the threshold and is out of cooldown.
async fn evaluate_rule(
    store: &Store,
    rule: &AlertRule,
    webhook_url: Option<&str>,
    client: Option<&reqwest::Client>,
    bus: &EventBus,
) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let since = now - Duration::from_secs(rule.window_seconds);
    for (group_key, count) in store.count_events_grouped(rule, since).await? {
        if count < rule.threshold {
            continue;
        }
        let last = store.last_alert_fired(&rule.name, &group_key).await?;
        if !should_fire(count, rule.threshold, last, now, rule.cooldown_seconds) {
            continue;
        }
        let alert = Alert {
            rule_name: rule.name.clone(),
            group_key: group_key.clone(),
            fired_at: now,
            severity: rule.severity.clone(),
            value: count,
            threshold: rule.threshold,
            summary: summary(rule, &group_key, count),
        };
        store.insert_alert(&alert).await?;
        warn!(rule = %rule.name, group = %group_key, value = count, threshold = rule.threshold, "ALERT fired");
        // Push a live notice so connected dashboards refresh the Alerts view immediately.
        bus.notify(StreamKind::Alerts);
        if let (Some(url), Some(client)) = (webhook_url, client) {
            deliver_webhook(client, url, &alert).await;
        }
    }
    Ok(())
}

/// POST the alert as JSON to the webhook. Failures are logged, never propagated (delivery is
/// best-effort; the alert is already persisted and readable via the API).
async fn deliver_webhook(client: &reqwest::Client, url: &str, alert: &Alert) {
    match client.post(url).json(alert).send().await {
        Ok(resp) if resp.status().is_success() => {}
        Ok(resp) => warn!(status = %resp.status(), rule = %alert.rule_name, "alert webhook returned non-2xx"),
        Err(e) => warn!(error = %e, rule = %alert.rule_name, "alert webhook delivery failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs_ago: i64) -> OffsetDateTime {
        OffsetDateTime::now_utc() - Duration::from_secs(secs_ago.max(0) as u64)
    }

    #[test]
    fn should_fire_below_threshold_is_false() {
        assert!(!should_fire(4, 5, None, OffsetDateTime::now_utc(), 300));
    }

    #[test]
    fn should_fire_at_threshold_never_fired_is_true() {
        assert!(should_fire(5, 5, None, OffsetDateTime::now_utc(), 300));
    }

    #[test]
    fn should_fire_within_cooldown_is_false() {
        // Last fired 60s ago, cooldown 300s → still cooling down.
        assert!(!should_fire(10, 5, Some(t(60)), OffsetDateTime::now_utc(), 300));
    }

    #[test]
    fn should_fire_after_cooldown_is_true() {
        // Last fired 600s ago, cooldown 300s → may fire again.
        assert!(should_fire(10, 5, Some(t(600)), OffsetDateTime::now_utc(), 300));
    }

    #[test]
    fn summary_includes_group_column_when_grouped() {
        use crate::config::GroupBy;
        let rule = AlertRule {
            name: "r".into(),
            decision: None,
            rule_id: None,
            client_ip: None,
            group_by: GroupBy::ClientIp,
            window_seconds: 60,
            threshold: 5,
            severity: "warning".into(),
            cooldown_seconds: 300,
        };
        let s = summary(&rule, "1.2.3.4", 7);
        assert!(s.contains("client_ip=1.2.3.4"), "{s}");
        assert!(s.contains('7'));
    }

    #[tokio::test]
    async fn evaluator_fires_then_cooldown_env_gated() {
        use crate::config::GroupBy;
        use crate::model::DecisionEvent;
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");

        // Unique rule_id + rule name isolate this run from any other rows in a shared test DB.
        let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
        let uniq_rule_id = format!("evrule-{nanos}");
        let uniq_name = format!("evtest-{nanos}");
        for i in 0..3 {
            let ev = DecisionEvent {
                request_id: format!("ev-{nanos}-{i}"),
                ts: OffsetDateTime::now_utc(),
                node: "n".into(),
                method: Some("GET".into()),
                path: Some("/".into()),
                client_ip: Some("7.7.7.7".into()),
                decision: "blocked".into(),
                rule_id: Some(uniq_rule_id.clone()),
                reason: None,
                score: 5,
                contributions: vec![],
            };
            store.insert_decision_event(&ev).await.expect("insert event");
        }

        let rule = AlertRule {
            name: uniq_name.clone(),
            decision: Some("blocked".into()),
            rule_id: Some(uniq_rule_id.clone()),
            client_ip: None,
            group_by: GroupBy::ClientIp,
            window_seconds: 3600,
            threshold: 3,
            severity: "critical".into(),
            cooldown_seconds: 3600,
        };

        // First cycle: 3 blocks from 7.7.7.7 reach threshold 3 → one alert fires (no webhook).
        let bus = EventBus::new();
        evaluate_rule(&store, &rule, None, None, &bus).await.expect("cycle 1");
        let fired = |alerts: Vec<Alert>| alerts.iter().filter(|a| a.rule_name == uniq_name).count();
        assert_eq!(fired(store.recent_alerts(500).await.unwrap()), 1, "one alert on first cycle");

        // Second cycle immediately: still over threshold, but cooldown (3600s) blocks a re-fire.
        evaluate_rule(&store, &rule, None, None, &bus).await.expect("cycle 2");
        assert_eq!(fired(store.recent_alerts(500).await.unwrap()), 1, "cooldown prevents a second fire");
    }
}
