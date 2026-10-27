// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SIEM forwarder e2e (§9, S2): the forwarder pushes stored decision events to a SIEM sink and only
//! advances the cursor on a 2xx ack — so a failing sink loses NOTHING (at-least-once).
//!
//!   seed decision_events → forward_once → an in-test HTTP receiver captures the normalized NDJSON +
//!   the cursor advances; then the receiver returns 500 → forward_once → the cursor does NOT advance;
//!   then it returns 200 again → forward_once → the held-back events are (re)delivered and the cursor
//!   catches up.
//!
//! Env-gated on `WAF_CP_DATABASE_URL` (skipped when unset).

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use time::OffsetDateTime;
use waf_controlplane::config::{SiemConfig, SiemDestination, SiemFormat, SiemStream};
use waf_controlplane::model::{Alert, Contribution, DecisionEvent};
use waf_controlplane::{app, AppState, Ingestor, SiemForwarder, Store};

/// A receiver that records each POST body, or returns 500 when `fail` is set.
#[derive(Clone)]
struct Receiver {
    bodies: Arc<Mutex<Vec<String>>>,
    fail: Arc<AtomicBool>,
}

async fn collect(State(r): State<Receiver>, body: String) -> StatusCode {
    if r.fail.load(Ordering::SeqCst) {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    r.bodies.lock().unwrap().push(body);
    StatusCode::OK
}

async fn start_receiver(r: Receiver) -> SocketAddr {
    let app = Router::new().route("/", post(collect)).with_state(r);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

fn sample(request_id: &str, rule: &str) -> DecisionEvent {
    DecisionEvent {
        request_id: request_id.into(),
        ts: OffsetDateTime::now_utc(),
        node: "edge-1".into(),
        method: Some("GET".into()),
        path: Some("/x".into()),
        client_ip: Some("203.0.113.9".into()),
        decision: "blocked".into(),
        rule_id: Some(rule.into()),
        reason: Some("anomaly".into()),
        score: 6,
        contributions: vec![Contribution {
            module: "sqli".into(),
            rule_id: rule.into(),
            severity: Some("critical".into()),
            points: 6,
        }],
    }
}

#[tokio::test]
async fn siem_forward_at_least_once_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    // reqwest is built with `rustls-no-provider`; install the process ring provider (mirrors the
    // other e2e tests) so the HTTP client can be constructed.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    let dest = format!("dest-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());

    // Isolate this run: start the cursor at the current head, so we only export OUR rows.
    let start = store.decisions_max_id().await.expect("max");
    store.siem_set_cursor(&dest, "decisions", start).await.expect("seed cursor");
    for i in 0..3 {
        store.insert_decision_event(&sample(&format!("{dest}-{i}"), "sqli-union")).await.expect("insert");
    }

    let recv = Receiver { bodies: Arc::new(Mutex::new(Vec::new())), fail: Arc::new(AtomicBool::new(false)) };
    let addr = start_receiver(recv.clone()).await;

    let config = SiemConfig {
        enabled: true,
        flush_interval_seconds: 1,
        batch_size: 1000,
        destinations: vec![SiemDestination {
            name: dest.clone(),
            endpoint: format!("http://{addr}/"),
            auth_header: Some("Splunk test-token".into()),
            format: SiemFormat::Ecs,
            streams: vec![SiemStream::Decisions],
        }],
    };
    let fwd = SiemForwarder::new(store.clone(), config);

    // 1) Success: batch delivered, cursor advances past the start.
    fwd.forward_once().await;
    let cursor1 = store.siem_get_cursor(&dest, "decisions").await.expect("cursor1");
    assert!(cursor1 > start, "cursor must advance on a 2xx ack");
    let text1 = recv.bodies.lock().unwrap().concat();
    assert!(text1.contains("waf-decision-"), "normalized NDJSON delivered");
    let first_line = text1.lines().next().expect("a line");
    let v: serde_json::Value = serde_json::from_str(first_line).unwrap();
    assert_eq!(v["version"], 1, "versioned schema");
    assert_eq!(v["event"]["category"][1], "intrusion_detection");
    assert!(v["source"]["ip"].is_string());

    // 2) Failure: the sink returns 500 → new events are NOT lost, the cursor does NOT advance.
    recv.fail.store(true, Ordering::SeqCst);
    for i in 3..5 {
        store.insert_decision_event(&sample(&format!("{dest}-{i}"), "xss")).await.expect("insert");
    }
    fwd.forward_once().await;
    let cursor_fail = store.siem_get_cursor(&dest, "decisions").await.expect("cursor fail");
    assert_eq!(cursor_fail, cursor1, "cursor must NOT advance when delivery fails (at-least-once)");

    // 3) Recovery: the sink is healthy again → the held-back events are delivered, cursor catches up.
    recv.fail.store(false, Ordering::SeqCst);
    fwd.forward_once().await;
    let cursor2 = store.siem_get_cursor(&dest, "decisions").await.expect("cursor2");
    assert!(cursor2 > cursor_fail, "cursor advances after recovery");
    let text2 = recv.bodies.lock().unwrap().concat();
    assert!(
        text2.matches("waf-decision-").count() >= 5,
        "all 5 seeded events delivered across cycles; got:\n{text2}"
    );
    // The Authorization header path was exercised (the receiver 200'd the authenticated POSTs).
}

#[tokio::test]
async fn siem_all_streams_and_status_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");

    // A separate pool for the governance schema + audit seeding (Store::pool is crate-private).
    let pool = sqlx::postgres::PgPool::connect(&url).await.expect("pool");
    waf_governance::store::apply_schema(&pool).await.expect("gov schema");
    let signer = waf_governance::audit::AuditSigner::from_hex_seed(
        "0909090909090909090909090909090909090909090909090909090909090909",
    )
    .unwrap();

    let dest = format!("all-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());

    // Isolate every stream: start each cursor at the current head.
    let d0 = store.decisions_max_id().await.unwrap();
    let a0 = store.alerts_max_id().await.unwrap();
    let g0 = waf_governance::store::audit_max_seq(&pool).await.unwrap();
    store.siem_set_cursor(&dest, "decisions", d0).await.unwrap();
    store.siem_set_cursor(&dest, "alerts", a0).await.unwrap();
    store.siem_set_cursor(&dest, "audit", g0).await.unwrap();

    // One event in each stream.
    store.insert_decision_event(&sample(&format!("{dest}-d"), "sqli-union")).await.unwrap();
    store
        .insert_alert(&Alert {
            rule_name: format!("{dest}-rule"),
            group_key: "9.9.9.9".into(),
            fired_at: OffsetDateTime::now_utc(),
            severity: "critical".into(),
            value: 9,
            threshold: 3,
            summary: "burst".into(),
        })
        .await
        .unwrap();
    let audit_entry = waf_governance::model::NewAudit::new(
        "admin",
        "rule.publish",
        Some(format!("{dest}-v")),
        &serde_json::json!({ "note": "siem" }),
    );
    waf_governance::store::append_audit(&pool, &signer, &audit_entry).await.unwrap();

    let recv = Receiver { bodies: Arc::new(std::sync::Mutex::new(Vec::new())), fail: Arc::new(std::sync::atomic::AtomicBool::new(false)) };
    let addr = start_receiver(recv.clone()).await;

    let config = SiemConfig {
        enabled: true,
        flush_interval_seconds: 1,
        batch_size: 1000,
        destinations: vec![SiemDestination {
            name: dest.clone(),
            endpoint: format!("http://{addr}/"),
            auth_header: None,
            format: SiemFormat::Ecs,
            streams: vec![SiemStream::Decisions, SiemStream::Audit, SiemStream::Alerts],
        }],
    };
    let fwd = SiemForwarder::new(store.clone(), config.clone());
    let siem_status = fwd.status();
    fwd.forward_once().await;

    // All three normalized streams reached the sink, each with a stable event id.
    let text = recv.bodies.lock().unwrap().concat();
    assert!(text.contains("waf-decision-"), "decisions stream delivered");
    assert!(text.contains(&format!("waf-audit-{}", g0 + 1)), "audit stream delivered");
    assert!(text.contains("waf-alert-"), "alerts stream delivered");

    // The status API exposes the per-(destination, stream) cursor + lag + last delivery.
    let state = Arc::new(AppState {
        ingestor: Ingestor::new(store.clone()),
        store: store.clone(),
        alert_rules: Vec::new(),
        ui_dir: None,
        api_token: Some("t".into()),
        governance: None,
        siem: Some((config, siem_status)),
        bus: waf_controlplane::EventBus::new(),
        api_routes: None,
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app(state)).await;
    });

    let status: serde_json::Value = reqwest::Client::new()
        .get(format!("{base}/api/siem/status"))
        .header("Authorization", "Bearer t")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["enabled"], true);
    let streams = status["streams"].as_array().unwrap();
    // The audit stream reports its advanced cursor + a delivery.
    let audit = streams
        .iter()
        .find(|s| s["destination"] == dest && s["stream"] == "audit")
        .expect("audit stream in status");
    assert!(audit["cursor"].as_i64().unwrap() > g0, "audit cursor advanced past seed");
    assert!(audit["last_delivered"].as_u64().unwrap() >= 1);
    assert!(audit["lag"].as_i64().unwrap() >= 0);
}
