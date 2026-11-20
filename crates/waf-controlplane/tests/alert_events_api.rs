// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Alert evidence over HTTP: events cross a rule's threshold → the evaluator fires an alert with its
//! match snapshot → `GET /api/alerts/{id}` and `GET /api/alerts/{id}/events` return exactly the denied
//! events behind it — still after the configured rule has changed. Rows without a snapshot fall back
//! to the configured rule of the same name, or report the events unavailable.
//!
//! Env-gated on `WAF_CP_DATABASE_URL` (skipped when unset).

use std::net::SocketAddr;
use std::sync::Arc;

use serde_json::Value;
use time::OffsetDateTime;
use waf_controlplane::config::{AlertRule, GroupBy};
use waf_controlplane::model::{Alert, DecisionEvent};
use waf_controlplane::{app, evaluate_once, AppState, Delivery, Ingestor, Store};

const TOKEN: &str = "alert-events-token";

fn blocked(request_id: String, rule_id: &str, client_ip: &str) -> DecisionEvent {
    DecisionEvent {
        request_id,
        ts: OffsetDateTime::now_utc(),
        node: "n".into(),
        method: Some("GET".into()),
        path: Some("/login".into()),
        client_ip: Some(client_ip.into()),
        decision: "blocked".into(),
        rule_id: Some(rule_id.into()),
        reason: None,
        score: 5,
        contributions: vec![],
    }
}

fn rule(name: &str, rule_id: &str) -> AlertRule {
    AlertRule {
        name: name.into(),
        decision: Some("blocked".into()),
        rule_id: Some(rule_id.into()),
        client_ip: None,
        group_by: GroupBy::ClientIp,
        window_seconds: 3600,
        threshold: 2,
        severity: "critical".into(),
        cooldown_seconds: 3600,
    }
}

async fn serve(store: Store, alert_rules: Vec<AlertRule>) -> String {
    let state = Arc::new(AppState {
        ingestor: Ingestor::new(store.clone()),
        store,
        alert_rules,
        ui_dir: None,
        api_token: Some(TOKEN.into()),
        governance: None,
        siem: None,
        bus: waf_controlplane::EventBus::new(),
        api_routes: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app(state)).await;
    });
    format!("http://{addr}")
}

async fn get(client: &reqwest::Client, url: String) -> (u16, Value) {
    let resp = client.get(url).bearer_auth(TOKEN).send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap();
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

/// The id of the newest listed alert named `name`.
async fn alert_id(client: &reqwest::Client, base: &str, name: &str) -> i64 {
    let (status, list) = get(client, format!("{base}/api/alerts?limit=1000")).await;
    assert_eq!(status, 200);
    list.as_array().unwrap().iter().find(|a| a["rule_name"] == name).expect("alert listed")["id"]
        .as_i64()
        .expect("listed alerts carry their id")
}

fn request_ids(events: &Value) -> Vec<String> {
    let mut ids: Vec<String> =
        events["events"].as_array().unwrap().iter().map(|e| e["request_id"].as_str().unwrap().to_string()).collect();
    ids.sort();
    ids
}

#[tokio::test]
async fn alert_events_api_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // Two blocks from 10.0.0.1 (fires at threshold 2) and one from 10.0.0.2 (does not).
    let nanos = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let name = format!("evapi-{nanos}");
    let rule_id = format!("evapi-rule-{nanos}");
    for (i, ip) in ["10.0.0.1", "10.0.0.1", "10.0.0.2"].into_iter().enumerate() {
        store.insert_decision_event(&blocked(format!("{name}-{i}"), &rule_id, ip)).await.expect("insert");
    }
    let fired_rule = rule(&name, &rule_id);
    let bus = waf_controlplane::EventBus::new();
    evaluate_once(&store, std::slice::from_ref(&fired_rule), Delivery::default(), None, &bus).await;

    // The rule is then edited (its filter now matches nothing): the snapshot must still resolve the
    // events the alert fired on, not the edited rule's.
    let edited = rule(&name, "edited-to-match-nothing");
    let legacy_configured = format!("{name}-legacy");
    let base = serve(store.clone(), vec![edited, rule(&legacy_configured, &rule_id)]).await;
    let client = reqwest::Client::new();

    let id = alert_id(&client, &base, &name).await;
    let (status, detail) = get(&client, format!("{base}/api/alerts/{id}")).await;
    assert_eq!(status, 200, "{detail}");
    assert_eq!(detail["id"], id);
    assert_eq!(detail["group_key"], "10.0.0.1");
    assert_eq!(detail["match_source"], "snapshot");
    assert_eq!(detail["match"]["rule_id"], rule_id.as_str());
    assert_eq!(detail["match"]["group_by"], "client_ip");
    assert_eq!(detail["match"]["window_seconds"], 3600);
    assert!(detail["window_start"].is_string());
    // Still ongoing: the fired group's 2 events are in the window ending now (threshold 2).
    assert_eq!(detail["current"]["count"], 2, "{detail}");
    assert_eq!(detail["current"]["above_threshold"], true);
    assert!(detail["current"]["since"].is_string());

    let (status, events) = get(&client, format!("{base}/api/alerts/{id}/events")).await;
    assert_eq!(status, 200, "{events}");
    assert_eq!(events["match_source"], "snapshot");
    assert_eq!(events["total"], 2);
    assert_eq!(request_ids(&events), vec![format!("{name}-0"), format!("{name}-1")], "only the fired group");
    // Paging.
    let (_, page) = get(&client, format!("{base}/api/alerts/{id}/events?limit=1&offset=1")).await;
    assert_eq!(page["total"], 2);
    assert_eq!(page["events"].as_array().unwrap().len(), 1);

    // A row without a snapshot resolves through the configured rule of the same name…
    let legacy = |rule_name: &str| Alert {
        rule_name: rule_name.into(),
        group_key: "10.0.0.2".into(),
        fired_at: OffsetDateTime::now_utc(),
        severity: "warning".into(),
        value: 1,
        threshold: 1,
        summary: String::new(),
    };
    store.insert_alert(&legacy(&legacy_configured)).await.unwrap();
    let lid = alert_id(&client, &base, &legacy_configured).await;
    let (_, detail) = get(&client, format!("{base}/api/alerts/{lid}")).await;
    assert_eq!(detail["match_source"], "current_config");
    let (status, events) = get(&client, format!("{base}/api/alerts/{lid}/events")).await;
    assert_eq!(status, 200, "{events}");
    assert_eq!(events["match_source"], "current_config");
    assert_eq!(request_ids(&events), vec![format!("{name}-2")]);

    // …and is unavailable when no rule of that name is configured.
    let orphan = format!("{name}-orphan");
    store.insert_alert(&legacy(&orphan)).await.unwrap();
    let oid = alert_id(&client, &base, &orphan).await;
    let (_, detail) = get(&client, format!("{base}/api/alerts/{oid}")).await;
    assert_eq!(detail["match_source"], "unavailable");
    assert!(detail["match"].is_null());
    assert!(detail["current"].is_null());
    let (status, _) = get(&client, format!("{base}/api/alerts/{oid}/events")).await;
    assert_eq!(status, 404);

    // Unknown / malformed ids; the static `/api/alerts/rules` route still wins over `{id}`.
    assert_eq!(get(&client, format!("{base}/api/alerts/{}", i64::MAX)).await.0, 404);
    assert_eq!(get(&client, format!("{base}/api/alerts/{}/events", i64::MAX)).await.0, 404);
    assert_eq!(get(&client, format!("{base}/api/alerts/not-a-number")).await.0, 400);
    let (status, rules) = get(&client, format!("{base}/api/alerts/rules")).await;
    assert_eq!(status, 200);
    assert!(rules.is_array());

    // The evidence is behind the same auth as the rest of the read API.
    let anon = client.get(format!("{base}/api/alerts/{id}/events")).send().await.unwrap();
    assert_eq!(anon.status().as_u16(), 401);
}

#[tokio::test]
async fn events_time_bounds_are_validated_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let base = serve(store, Vec::new()).await;
    let client = reqwest::Client::new();

    assert_eq!(get(&client, format!("{base}/api/events?since=yesterday")).await.0, 400);
    assert_eq!(get(&client, format!("{base}/api/events?until=2026-13-01T00:00:00Z")).await.0, 400);
    let (status, _) =
        get(&client, format!("{base}/api/events?since=2026-01-01T00:00:00Z&until=2026-01-02T00:00:00Z")).await;
    assert_eq!(status, 200);
}
