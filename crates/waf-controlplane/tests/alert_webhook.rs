// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

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
use time::OffsetDateTime;
use waf_controlplane::config::{AlertRule, GroupBy};
use waf_controlplane::model::{Alert, DecisionEvent};
use waf_controlplane::{evaluate_once, Store};

/// Start an axum receiver that captures every POSTed `Alert` into a shared vec. Returns its addr.
async fn start_webhook_receiver() -> (SocketAddr, Arc<Mutex<Vec<Alert>>>) {
    let received: Arc<Mutex<Vec<Alert>>> = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::clone(&received);
    let app = Router::new()
        .route(
            "/hook",
            post(|State(rx): State<Arc<Mutex<Vec<Alert>>>>, Json(a): Json<Alert>| async move {
                rx.lock().unwrap().push(a);
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

#[tokio::test]
async fn alert_fires_and_delivers_webhook_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();

    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Unique rule_id + name isolate this run in a shared DB. 3 blocks from one IP → threshold 3.
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let uniq_rule_id = format!("whrule-{nanos}");
    let uniq_name = format!("whtest-{nanos}");
    for i in 0..3 {
        store
            .insert_decision_event(&blocked_event(&format!("wh-{nanos}-{i}"), &uniq_rule_id, "6.6.6.6"))
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
    evaluate_once(&store, std::slice::from_ref(&rule), Some(&webhook), Some(&client), &bus).await;

    // Give the async POST a moment to reach the receiver.
    for _ in 0..50 {
        if !received.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    // Stored AND delivered, with the right group + value.
    let stored = store.recent_alerts(500).await.unwrap();
    let sa = stored.iter().find(|a| a.rule_name == uniq_name).expect("alert stored");
    assert_eq!(sa.group_key, "6.6.6.6");
    assert_eq!(sa.value, 3);

    let got = received.lock().unwrap();
    let wa = got.iter().find(|a| a.rule_name == uniq_name).expect("alert delivered to webhook");
    assert_eq!(wa.group_key, "6.6.6.6");
    assert_eq!(wa.value, 3);
    assert_eq!(wa.severity, "critical");
}
