// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! End-to-end bite-test for governance (§8, G8-3): the real control-plane router with governance
//! enabled, driven over HTTP.
//!
//!   boot → bootstrap admin → login (bad→401 / good→session cookie) → bearer still = admin →
//!   RBAC (a viewer reads the observability API but is 403 on user-management / audit) →
//!   the signed audit chain records the actions and `/api/audit/verify` passes → tampering a
//!   stored record makes verification fail.
//!
//! Env-gated on `WAF_CP_DATABASE_URL` (skipped when unset). Its own binary; it sets the governance
//! env secrets in-process and truncates the governance tables for a deterministic bootstrap + chain.

use std::net::SocketAddr;
use std::sync::Arc;

use waf_controlplane::gov_api::setup_governance;
use waf_controlplane::{app, AppState, ControlPlaneConfig, Ingestor, Store};

const AUDIT_KEY: &str = "0505050505050505050505050505050505050505050505050505050505050505";
const ADMIN_PW: &str = "adminpw-e2e";

/// Pull the session id out of a `set-cookie` response header.
fn session_from_set_cookie(resp: &reqwest::Response) -> Option<String> {
    let raw = resp.headers().get("set-cookie")?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some(v) = part.trim().strip_prefix("waf_cp_session=") {
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

async fn get_status(client: &reqwest::Client, base: &str, cookie: Option<&str>, bearer: Option<&str>) -> u16 {
    let mut req = client.get(format!("{base}/api/cluster/status"));
    if let Some(c) = cookie {
        req = req.header("Cookie", format!("waf_cp_session={c}"));
    }
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    req.send().await.unwrap().status().as_u16()
}

async fn login(client: &reqwest::Client, base: &str, user: &str, pw: &str) -> reqwest::Response {
    client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({ "username": user, "password": pw }))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn governance_e2e_env_gated() {
    let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
        eprintln!("skipping: WAF_CP_DATABASE_URL not set");
        return;
    };
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Governance reads these two secrets from the environment at setup.
    std::env::set_var("WAF_CP_AUDIT_KEY", AUDIT_KEY);
    std::env::set_var("WAF_CP_BOOTSTRAP_ADMIN_PASSWORD", ADMIN_PW);

    // Clean the governance tables so the bootstrap runs and the audit chain starts at genesis.
    let pool = sqlx::postgres::PgPool::connect(&url).await.expect("pool");
    waf_governance::store::apply_schema(&pool).await.expect("schema");
    sqlx::query("TRUNCATE gov_audit_log").execute(&pool).await.expect("truncate audit");
    sqlx::query("TRUNCATE gov_sessions, gov_users, gov_tokens CASCADE").execute(&pool).await.expect("truncate");

    // Build the control plane with governance ON (http dev → cookie_secure=false), and the bearer
    // service token still valid.
    let mut config = ControlPlaneConfig::default();
    config.governance.enabled = true;
    config.governance.login_max_failures = 3; // keep the throttle assertion quick
    config.governance.cookie_secure = false;
    config.governance.bootstrap_admin = Some("admin".into());
    config.api_token = Some("svc-token".into());

    let store = Store::connect(&url).await.expect("connect");
    store.migrate().await.expect("migrate");
    let governance = setup_governance(&config, &store).await.expect("governance setup").expect("enabled");

    let state = Arc::new(AppState {
        ingestor: Ingestor::new(store.clone()),
        store,
        alert_rules: Vec::new(),
        ui_dir: None,
        api_token: config.api_token.clone(),
        governance: Some(governance),
        siem: None,
        bus: waf_controlplane::EventBus::new(),
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app(state)).await;
    });

    let client = reqwest::Client::new();

    // ── Public auth-config: the UI reads this to pick its login flow (session vs token) ──────────
    let cfg: serde_json::Value = client.get(format!("{base}/api/auth/config")).send().await.unwrap().json().await.unwrap();
    assert_eq!(cfg["governance"], true, "governance is on");
    assert_eq!(cfg["oidc"], false, "no oidc configured in this test");

    // ── AuthN: no auth 401; bearer = admin 200 ──────────────────────────────────────────────────
    assert_eq!(get_status(&client, &base, None, None).await, 401, "no auth → 401");
    assert_eq!(get_status(&client, &base, None, Some("svc-token")).await, 200, "bearer = admin → 200");

    // ── Login: bad password rejected, good password sets a session cookie ────────────────────────
    let bad = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username": "admin", "password": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status().as_u16(), 401, "bad password → 401");

    let ok = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username": "admin", "password": ADMIN_PW}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status().as_u16(), 200, "good password → 200");
    let admin_sid = session_from_set_cookie(&ok).expect("login sets a session cookie");

    // /api/me reflects the admin session.
    let me: serde_json::Value = client
        .get(format!("{base}/api/me"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["role"], "admin");
    assert_eq!(me["via"], "session");
    assert_eq!(get_status(&client, &base, Some(&admin_sid), None).await, 200, "admin session reads → 200");

    // ── Admin creates a viewer; RBAC then restricts the viewer ───────────────────────────────────
    let created = client
        .post(format!("{base}/api/users"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .json(&serde_json::json!({"username": "alice", "password": "alicepw", "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status().as_u16(), 201, "admin creates user → 201");

    let alice_login = client
        .post(format!("{base}/api/login"))
        .json(&serde_json::json!({"username": "alice", "password": "alicepw"}))
        .send()
        .await
        .unwrap();
    let alice_sid = session_from_set_cookie(&alice_login).expect("alice session");

    assert_eq!(get_status(&client, &base, Some(&alice_sid), None).await, 200, "viewer reads observability → 200");
    let viewer_users = client
        .get(format!("{base}/api/users"))
        .header("Cookie", format!("waf_cp_session={alice_sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(viewer_users.status().as_u16(), 403, "viewer on user-management → 403");
    let viewer_audit = client
        .get(format!("{base}/api/audit"))
        .header("Cookie", format!("waf_cp_session={alice_sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(viewer_audit.status().as_u16(), 403, "viewer on audit → 403");

    // ── Signed audit chain: verify passes, then tampering makes it fail ─────────────────────────
    let verify: serde_json::Value = client
        .get(format!("{base}/api/audit/verify"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify["ok"], true, "clean chain must verify; got {verify}");
    assert!(verify["count"].as_i64().unwrap() >= 4, "bootstrap + logins + user.create recorded");

    // ── §7 rule management (write-path v3): RBAC + publish/current/versions/rollback + convergence ─
    let admin_cookie = format!("waf_cp_session={admin_sid}");
    let alice_cookie = format!("waf_cp_session={alice_sid}");

    // A viewer cannot publish (ManageRules is operator-and-up).
    let viewer_publish = client
        .post(format!("{base}/api/rules/versions"))
        .header("Cookie", &alice_cookie)
        .json(&serde_json::json!({ "content": "SecRule ARGS \"@rx x\" \"id:9\"", "note": "nope" }))
        .send()
        .await
        .unwrap();
    assert_eq!(viewer_publish.status().as_u16(), 403, "viewer cannot publish rules → 403");

    // Admin publishes v1 → it becomes current.
    let pub1: serde_json::Value = client
        .post(format!("{base}/api/rules/versions"))
        .header("Cookie", &admin_cookie)
        .json(&serde_json::json!({ "content": "SecRule ARGS \"@rx attack1\" \"id:100\"", "note": "v1" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let v1 = pub1["id"].as_i64().expect("v1 id");
    let cur1: serde_json::Value = client
        .get(format!("{base}/api/rules/current"))
        .header("Cookie", &admin_cookie)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cur1["version"], v1, "current == v1 after first publish");
    assert!(cur1["content"].as_str().unwrap().contains("attack1"));

    // Admin publishes v2 → current moves to v2.
    let pub2: serde_json::Value = client
        .post(format!("{base}/api/rules/versions"))
        .header("Cookie", &admin_cookie)
        .json(&serde_json::json!({ "content": "SecRule ARGS \"@rx attack2\" \"id:101\"", "note": "v2" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let v2 = pub2["id"].as_i64().expect("v2 id");
    let cur2: serde_json::Value =
        client.get(format!("{base}/api/rules/current")).header("Cookie", &admin_cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(cur2["version"], v2, "current == v2 after second publish");

    // The versions list flags exactly the current one.
    let versions: serde_json::Value =
        client.get(format!("{base}/api/rules/versions")).header("Cookie", &admin_cookie).send().await.unwrap().json().await.unwrap();
    let arr = versions.as_array().unwrap();
    assert!(arr.iter().any(|m| m["id"] == v2 && m["current"] == true), "v2 flagged current");
    assert!(arr.iter().any(|m| m["id"] == v1 && m["current"] == false), "v1 not current");

    // Rollback re-points current to v1; a bogus version 404s.
    let rb = client
        .post(format!("{base}/api/rules/rollback"))
        .header("Cookie", &admin_cookie)
        .json(&serde_json::json!({ "version": v1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(rb.status().as_u16(), 200, "admin rollback → 200");
    let cur3: serde_json::Value =
        client.get(format!("{base}/api/rules/current")).header("Cookie", &admin_cookie).send().await.unwrap().json().await.unwrap();
    assert_eq!(cur3["version"], v1, "current == v1 after rollback");
    let rb_bad = client
        .post(format!("{base}/api/rules/rollback"))
        .header("Cookie", &admin_cookie)
        .json(&serde_json::json!({ "version": -1 }))
        .send()
        .await
        .unwrap();
    assert_eq!(rb_bad.status().as_u16(), 404, "rollback to unknown version → 404");

    // Agent-facing routes are ReadObservability: a viewer CAN read current, and report status.
    let viewer_current =
        client.get(format!("{base}/api/rules/current")).header("Cookie", &alice_cookie).send().await.unwrap();
    assert_eq!(viewer_current.status().as_u16(), 200, "viewer reads current (ReadObs) → 200");

    // A node reports it applied v1 → convergence view reflects it.
    let report = client
        .post(format!("{base}/api/rules/status"))
        .header("Cookie", &admin_cookie)
        .json(&serde_json::json!({ "node": "edge-e2e", "version": v1, "status": "applied", "detail": "" }))
        .send()
        .await
        .unwrap();
    assert_eq!(report.status().as_u16(), 200, "node status report → 200");
    let nodes: serde_json::Value =
        client.get(format!("{base}/api/rules/nodes")).header("Cookie", &admin_cookie).send().await.unwrap().json().await.unwrap();
    assert!(
        nodes.as_array().unwrap().iter().any(|n| n["node"] == "edge-e2e"
            && n["applied_version"] == v1
            && n["status"] == "applied"),
        "convergence view shows edge-e2e applied v1; got {nodes}",
    );

    // ── v2: service tokens (role-bound + revoke) ────────────────────────────────────────────────
    let created_tok: serde_json::Value = client
        .post(format!("{base}/api/tokens"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .json(&serde_json::json!({ "name": "ci-bot", "role": "operator" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token_secret = created_tok["token"].as_str().expect("plaintext token returned once").to_string();
    let token_id = created_tok["id"].as_i64().expect("token id");
    // The named token (operator) reads observability but is 403 on admin-only user management.
    assert_eq!(get_status(&client, &base, None, Some(&token_secret)).await, 200, "token reads → 200");
    let tok_users = client
        .get(format!("{base}/api/users"))
        .header("Authorization", format!("Bearer {token_secret}"))
        .send()
        .await
        .unwrap();
    assert_eq!(tok_users.status().as_u16(), 403, "operator token on /users → 403 (role-bound)");
    // Revoke → the token no longer authenticates.
    let revoke = client
        .delete(format!("{base}/api/tokens/{token_id}"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status().as_u16(), 200);
    assert_eq!(get_status(&client, &base, None, Some(&token_secret)).await, 401, "revoked token → 401");

    // ── v2: session management (list + revoke) ──────────────────────────────────────────────────
    let admin_sid2 = session_from_set_cookie(&login(&client, &base, "admin", ADMIN_PW).await).unwrap();
    let sessions: serde_json::Value = client
        .get(format!("{base}/api/sessions"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(sessions.as_array().unwrap().len() >= 2, "at least two sessions listed");
    let del = client
        .delete(format!("{base}/api/sessions/{admin_sid2}"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status().as_u16(), 200);
    assert_eq!(get_status(&client, &base, Some(&admin_sid2), None).await, 401, "revoked session → 401");

    // ── v2: password change (revokes other sessions; old pw stops working) ──────────────────────
    let admin_sid3 = session_from_set_cookie(&login(&client, &base, "admin", ADMIN_PW).await).unwrap();
    let pw_change = client
        .post(format!("{base}/api/me/password"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .json(&serde_json::json!({ "old_password": ADMIN_PW, "new_password": "adminpw-v2" }))
        .send()
        .await
        .unwrap();
    assert_eq!(pw_change.status().as_u16(), 200);
    assert_eq!(get_status(&client, &base, Some(&admin_sid3), None).await, 401, "other session revoked on pw change");
    assert_eq!(get_status(&client, &base, Some(&admin_sid), None).await, 200, "current session kept");
    assert_eq!(login(&client, &base, "admin", ADMIN_PW).await.status().as_u16(), 401, "old password rejected");
    assert_eq!(login(&client, &base, "admin", "adminpw-v2").await.status().as_u16(), 200, "new password works");

    // ── v2: login brute-force throttle (max_failures = 3) ───────────────────────────────────────
    for _ in 0..3 {
        assert_eq!(login(&client, &base, "ghost", "x").await.status().as_u16(), 401);
    }
    assert_eq!(login(&client, &base, "ghost", "x").await.status().as_u16(), 429, "locked out after 3 failures");

    // ── §8 compliance report: generate (admin) → self-verify → tamper fails → RBAC ───────────────
    let report: serde_json::Value = client
        .get(format!("{base}/api/compliance/report"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // Shape: a signed bundle with the four sections + the SOC2/PCI control annotations.
    assert_eq!(report["report_version"], 1);
    assert!(report["signature"].as_str().is_some(), "bundle is signed");
    assert!(report["sections"]["access_control"]["total_users"].as_i64().unwrap() >= 1);
    assert!(report["sections"]["access_control"]["controls"].as_array().unwrap().iter().any(|c| c == "PCI 8.1"));
    // The whole audit chain is still intact here (the tamper below happens AFTER) → attested ok.
    assert_eq!(report["sections"]["audit_integrity"]["chain_ok"], true, "chain intact at report time");
    // The generation itself is audited.
    assert!(report["sections"]["audit_integrity"]["events_in_period"]["total_in_period"].as_i64().unwrap() >= 1);

    // The verify endpoint accepts the freshly generated bundle.
    let verified: serde_json::Value = client
        .post(format!("{base}/api/compliance/verify"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .json(&report)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified["ok"], true, "a freshly signed bundle must verify");

    // Tampering any body field breaks verification (the signature covers the content hash).
    let mut tampered = report.clone();
    tampered["generated_by"] = serde_json::json!("attacker");
    let verified2: serde_json::Value = client
        .post(format!("{base}/api/compliance/verify"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .json(&tampered)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verified2["ok"], false, "a mutated bundle must fail verification");

    // RBAC: a viewer cannot generate a compliance report (ViewAudit is admin-only).
    let viewer_report = client
        .get(format!("{base}/api/compliance/report"))
        .header("Cookie", format!("waf_cp_session={alice_sid}"))
        .send()
        .await
        .unwrap();
    assert_eq!(viewer_report.status().as_u16(), 403, "viewer on compliance report → 403");

    // Tamper with a stored record directly, then re-verify → must be detected.
    sqlx::query("UPDATE gov_audit_log SET details = '{\"tampered\":true}' WHERE seq = 1")
        .execute(&pool)
        .await
        .expect("tamper");
    let verify2: serde_json::Value = client
        .get(format!("{base}/api/audit/verify"))
        .header("Cookie", format!("waf_cp_session={admin_sid}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(verify2["ok"], false, "tampered chain must fail verification; got {verify2}");
    assert_eq!(verify2["broken_seq"], 1, "the tampered record's seq is reported");
}
