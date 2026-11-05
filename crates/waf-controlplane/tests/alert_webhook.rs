// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Alerting webhook e2e (v2, V2-4): a rule crossing its threshold → the evaluator stores an alert
//! AND POSTs it to the configured webhook. A local axum receiver captures the POST, so the whole
//! store→evaluate→deliver path is proven against a real Postgres + a real HTTP delivery.
//!
//! Env-gated on `WAF_CP_DATABASE_URL` (skipped when unset).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::Value;
use time::OffsetDateTime;
use waf_controlplane::config::{AlertRule, GroupBy, WebhookFormat};
use waf_controlplane::model::{Alert, DecisionEvent};
use waf_controlplane::{evaluate_once, Store};

/// Start an axum receiver that captures every POSTed JSON body into a shared vec. Returns its addr.
async fn start_webhook_receiver() -> (SocketAddr, Arc<Mutex<Vec<Value>>>) {
    let received: Arc<Mutex<Vec<Value>>> = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::clone(&received);
    let app = Router::new()
        .route(
            "/hook",
            post(|State(rx): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>| async move {
                rx.lock().unwrap().push(body);
                "ok"
            }),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, received)
}

fn blocked_event(request_id: &str, rule_id: &str, client_ip: &str) -> DecisionEvent {
    DecisionEvent {
        request_id: request_id.to_string(),
        ts: OffsetDateTime::now_utc(),
        node: "n".into(),
        method: Some("GET".into()),
        path: Some("/x".into()),
        client_ip: Some(client_ip.into()),
        decision: "blocked".into(),
        rule_id: Some(rule_id.into()),
        reason: None,
        score: 5,
        contributions: vec![],
    }
}

/// 3 blocks from one IP against a threshold-3 rule, one evaluation pass with the webhook in
/// `format`. Returns the store, the rule's unique name and the captured webhook bodies.
async fn fire_one_alert(format: WebhookFormat, tag: &str) -> Option<(Store, String, Vec<Value>)> {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return None;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();

    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Unique rule_id + name isolate this run in a shared DB. 3 blocks from one IP → threshold 3.
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let uniq_rule_id = format!("{tag}rule-{nanos}");
    let uniq_name = format!("{tag}test-{nanos}");
    for i in 0..3 {
        store
            .insert_decision_event(&blocked_event(&format!("{tag}-{nanos}-{i}"), &uniq_rule_id, "6.6.6.6"))
            .await
            .expect("insert");
    }

    let (addr, received) = start_webhook_receiver().await;
    let webhook = format!("http://{addr}/hook");
    let client = reqwest::Client::new();

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

    // One evaluation pass with the webhook configured.
    let bus = waf_controlplane::EventBus::new();
    evaluate_once(&store, std::slice::from_ref(&rule), Some(&webhook), format, Some(&client), &bus).await;

    // Give the async POST a moment to reach the receiver.
    for _ in 0..50 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let bodies = received.lock().unwrap().clone();
    Some((store, uniq_name, bodies))
}

#[tokio::test]
async fn alert_fires_and_delivers_webhook_env_gated() {
    let Some((store, uniq_name, bodies)) = fire_one_alert(WebhookFormat::Generic, "wh").await else {
        return;
    };

    // Stored AND delivered, with the right group + value.
    let stored = store.recent_alerts(500).await.unwrap();
    let sa = stored.iter().find(|a| a.rule_name == uniq_name).expect("alert stored");
    assert_eq!(sa.group_key, "6.6.6.6");
    assert_eq!(sa.value, 3);

    let got: Vec<Alert> =
        bodies.into_iter().map(|b| serde_json::from_value(b).expect("generic body is an Alert")).collect();
    let wa = got.iter().find(|a| a.rule_name == uniq_name).expect("alert delivered to webhook");
    assert_eq!(wa.group_key, "6.6.6.6");
    assert_eq!(wa.value, 3);
    assert_eq!(wa.severity, "critical");
}

#[tokio::test]
async fn alert_delivers_slack_text_env_gated() {
    let Some((_store, uniq_name, bodies)) = fire_one_alert(WebhookFormat::Slack, "sl").await else {
        return;
    };

    assert_eq!(bodies.len(), 1, "one alert, one POST: {bodies:?}");
    let want = format!("[critical] {uniq_name}: 3 events in 3600s (threshold 3), client_ip=6.6.6.6");
    assert_eq!(bodies[0], serde_json::json!({ "text": want }));
}
