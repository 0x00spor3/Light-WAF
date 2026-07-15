// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! End-to-end bite-test for the §7 write-path (R3-1): a rule published in the control plane reaches a
//! REAL WAF node through the agent and starts blocking.
//!
//!   real Proxy (blocking + CRS, managed file) → benign request 200 → publish a blocking rule via the
//!   REAL control-plane API → the AGENT's poll_once (pull → pre-validate → write the managed .conf) →
//!   reload IN-PROCESS via `reloader.reload_from` (simulating the SIGHUP the reload_command sends) →
//!   the SAME request now 403, and the node reports convergence. Then an INVALID version is published
//!   → the agent rejects it (level-1 fail-safe) and the WAF is left untouched (still 403).
//!
//! Env-gated on `WAF_CP_DATABASE_URL` (skipped when unset). SIGHUP is Unix; in-process `reload_from`
//! exercises the exact same reload path cross-platform.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use waf_controlplane::{app, AppState, Ingestor, Store};
use waf_core::{Config, WafMode};
use waf_node_agent::{poll_once, AgentClient, PollOutcome};
use waf_proxy::Proxy;

const BEARER: &str = "svc-token-e2e";
/// A token no native module matches — only the imported CRS rule can block it.
const ATTACK: &str = "wafnodeagenttoken";

/// Always-200 backend.
async fn start_backend() -> SocketAddr {
    let app = axum::Router::new().fallback(|| async { "ok" });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    addr
}

async fn attack_status(client: &reqwest::Client, waf: SocketAddr) -> u16 {
    client
        .get(format!("http://{waf}/?q={ATTACK}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Publish a version via the control-plane manage API (bearer = admin under governance-off).
async fn publish(client: &reqwest::Client, cp: &str, content: &str, note: &str) -> i64 {
    let resp = client
        .post(format!("{cp}/api/rules/versions"))
        .header("Authorization", format!("Bearer {BEARER}"))
        .json(&serde_json::json!({ "content": content, "note": note }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 201, "publish must return 201");
    let body: serde_json::Value = resp.json().await.unwrap();
    body["id"].as_i64().expect("published version id")
}

#[tokio::test]
async fn rule_publish_reaches_waf_via_agent_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();

    // ── A temp workspace: the managed .conf the WAF loads + the config file the reload re-reads ──
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let dir = std::env::temp_dir().join(format!("waf-agent-e2e-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    let managed: PathBuf = dir.join("managed.conf");
    // Start empty (comment-only): the WAF boots with zero imported rules.
    std::fs::write(&managed, "# managed by waf-node-agent\n").unwrap();
    let managed_str = managed.to_string_lossy().into_owned();

    // ── A REAL WAF node: blocking + CRS enabled, pointed at the managed file ────────────────────
    let backend = start_backend().await;
    let mut cfg = Config::default();
    cfg.proxy.listen = "127.0.0.1:0".parse().unwrap();
    cfg.proxy.backend = format!("http://{backend}");
    cfg.waf.mode = WafMode::Blocking;
    cfg.modules.crs.enabled = true;
    cfg.modules.crs.files = vec![managed_str.clone()];
    let proxy = Proxy::bind(&cfg).await.unwrap();
    let waf_addr = proxy.local_addr().unwrap();
    let reloader = proxy.reloader();
    tokio::spawn(proxy.run());

    // The config file the reload re-reads (single-quoted TOML literal so Windows backslashes are safe).
    let config_path = dir.join("waf.toml");
    let config_toml = format!(
        "[proxy]\nlisten = \"127.0.0.1:0\"\nbackend = \"http://{backend}\"\n[waf]\nmode = \"blocking\"\n[modules.crs]\nenabled = true\nfiles = ['{managed_str}']\n"
    );
    std::fs::write(&config_path, config_toml).unwrap();

    let http = reqwest::Client::new();
    // Baseline: no rule yet → the attack token is forwarded → 200.
    assert_eq!(attack_status(&http, waf_addr).await, 200, "no rule yet → forwarded");

    // ── The REAL control plane (governance off → static bearer), on the same Postgres ───────────
    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let state = Arc::new(AppState {
        ingestor: Ingestor::new(store.clone()),
        store,
        alert_rules: Vec::new(),
        ui_dir: None,
        api_token: Some(BEARER.to_string()),
        governance: None,
        siem: None,
        bus: waf_controlplane::EventBus::new(),
        api_routes: None,
    });
    let cp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cp_addr = cp_listener.local_addr().unwrap();
    let cp = format!("http://{cp_addr}");
    tokio::spawn(async move {
        let _ = axum::serve(cp_listener, app(state)).await;
    });

    // ── Publish a blocking rule → the agent pulls, validates, writes, reloads ───────────────────
    let rule = format!(
        "SecRule ARGS \"@rx (?i){ATTACK}\" \"id:9001,phase:2,severity:CRITICAL,block,msg:'e2e block'\""
    );
    let v1 = publish(&http, &cp, &rule, "block the token").await;

    let node = "edge-agent-e2e";
    let agent = AgentClient::new(cp.clone(), Some(BEARER.to_string()));
    let cfg_path = config_path.clone();
    let rl = reloader.clone();
    let outcome = poll_once(&agent, node, &managed, None, || async move {
        rl.reload_from(&cfg_path).map_err(|e| e.to_string())
    })
    .await;
    assert_eq!(outcome, PollOutcome::Applied(v1), "agent applies v1; got {outcome:?}");

    // The managed file now holds the published rule, and the SAME request is blocked.
    assert_eq!(std::fs::read_to_string(&managed).unwrap(), rule);
    // A tiny beat so the reloaded pipeline is fully live before the next request.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(attack_status(&http, waf_addr).await, 403, "after apply → blocked");

    // Convergence view reflects the node applying v1.
    let nodes: serde_json::Value = http
        .get(format!("{cp}/api/rules/nodes"))
        .header("Authorization", format!("Bearer {BEARER}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        nodes.as_array().unwrap().iter().any(|n| n["node"] == node
            && n["applied_version"] == v1
            && n["status"] == "applied"),
        "convergence must show {node} applied v1; got {nodes}",
    );

    // ── Level-1 fail-safe: publish an INVALID version → the agent rejects it, WAF untouched ─────
    // The manage API stores content verbatim (server-side dry-run is a declared follow-on), so an
    // out-of-subset rule (missing id) becomes current; the agent's pre-validation must catch it.
    let bad_rule = format!("SecRule ARGS \"@rx (?i){ATTACK}broken\" \"phase:2,block\"");
    let v2 = publish(&http, &cp, &bad_rule, "invalid: missing id").await;
    let cfg_path2 = config_path.clone();
    let rl2 = reloader.clone();
    let outcome2 = poll_once(&agent, node, &managed, Some(v1), || async move {
        rl2.reload_from(&cfg_path2).map_err(|e| e.to_string())
    })
    .await;
    assert!(matches!(outcome2, PollOutcome::Rejected { version, .. } if version == v2), "agent rejects v2; got {outcome2:?}");

    // The WAF was never touched: the managed file still holds v1 and the request is still blocked.
    assert_eq!(std::fs::read_to_string(&managed).unwrap(), rule, "managed file unchanged after reject");
    assert_eq!(attack_status(&http, waf_addr).await, 403, "still blocked by v1 after a rejected v2");

    // The node reports the rejection while its applied_version stays truthful (still v1).
    let nodes2: serde_json::Value = http
        .get(format!("{cp}/api/rules/nodes"))
        .header("Authorization", format!("Bearer {BEARER}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        nodes2.as_array().unwrap().iter().any(|n| n["node"] == node
            && n["applied_version"] == v1
            && n["status"] == "rejected"),
        "convergence must show {node} rejected v2 while still on v1; got {nodes2}",
    );

    let _ = std::fs::remove_dir_all(&dir);
}
