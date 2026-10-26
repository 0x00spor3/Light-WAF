// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! STEP-0 datapath bite-test (§4-A): the bot-detection module, loaded as a `WafModule`, BLOCKS a
//! browser-impersonation request on the REAL pipeline — and the SAME request WITH the browser's
//! `sec-fetch-*` headers passes (control). Also proves the fail-safe: a non-browser client and
//! default-off are inert. Exercises the `Phase::Headers` + `structural()` path.

use waf_core::{Bytes, Config, Normalized, RequestContext, WafMode, WafModule};
use waf_modules_premium::{rules, BotDetectionModule};
use waf_pipeline::{Pipeline, PipelineVerdict};

const CHROME: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like \
                      Gecko) Chrome/120.0.0.0 Safari/537.36";

fn blocking_config() -> Config {
    let mut c = Config::default();
    c.waf.mode = WafMode::Blocking;
    c.waf.block_threshold = 5; // a single Critical impersonation hit (severity 6) crosses this
    c
}

fn request(headers: &[(&str, &str)]) -> RequestContext {
    let owned: Vec<(String, String)> =
        headers.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let normalized = Normalized { headers: owned.clone(), path: "/".to_string(), ..Default::default() };
    RequestContext {
        client_ip: "203.0.113.10".parse().unwrap(),
        request_id: "bite".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: owned,
        cookies: vec![],
        body: Bytes::new(),
        normalized,
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn impersonation_blocks_on_the_pipeline_but_a_real_browser_passes() {
    let config = blocking_config();

    // Chrome UA but NO sec-fetch-* → impersonation → blocked.
    let module = BotDetectionModule::new(true);
    let pipe = Pipeline::new(&config, vec![Box::new(module)]);
    let mut ctx = request(&[("user-agent", CHROME)]);
    let verdict = pipe.run(&mut ctx);
    assert!(
        !matches!(verdict, PipelineVerdict::Allow),
        "browser-impersonation must block on the datapath (got {verdict:?})"
    );
    assert!(
        ctx.score_contributions.iter().any(|c| c.rule_id == rules::BOT_BROWSER_IMPERSONATION.id()),
        "the block must be attributed to the bot rule"
    );

    // Control: the SAME Chrome UA but WITH a sec-fetch header → a real browser → passes.
    let pipe2 = Pipeline::new(&config, vec![Box::new(BotDetectionModule::new(true))]);
    let mut ctx2 = request(&[("user-agent", CHROME), ("sec-fetch-site", "none")]);
    assert!(
        matches!(pipe2.run(&mut ctx2), PipelineVerdict::Allow),
        "a real browser (sends Sec-Fetch) must pass"
    );
}

#[test]
fn non_browser_client_passes() {
    let config = blocking_config();
    let pipe = Pipeline::new(&config, vec![Box::new(BotDetectionModule::new(true))]);
    // curl advertises no browser → not flagged (even without sec-fetch).
    let mut ctx = request(&[("user-agent", "curl/8.4.0")]);
    assert!(matches!(pipe.run(&mut ctx), PipelineVerdict::Allow), "curl must pass (no FP)");
}

#[test]
fn default_off_never_contributes() {
    let config = blocking_config();
    let pipe = Pipeline::new(&config, vec![Box::new(BotDetectionModule::new(false))]);
    let mut ctx = request(&[("user-agent", CHROME)]);
    assert!(
        matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "disabled module must be inert even on an impersonation request"
    );
}

#[test]
fn legit_clients_pass_through_the_pipeline() {
    // FP-guard end-to-end (module ON, blocking): none of these must be flagged.
    let config = blocking_config();
    let firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0";
    let edge = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) \
                Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0";
    let safari = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like \
                  Gecko) Version/17.0 Safari/605.1.15";
    let old_chrome = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) \
                      Chrome/79.0.3945.88 Safari/537.36";

    let legit: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("chrome + sec-fetch", vec![("user-agent", CHROME), ("sec-fetch-site", "none")]),
        ("firefox + sec-fetch", vec![("user-agent", firefox), ("sec-fetch-mode", "navigate")]),
        ("edge + sec-fetch", vec![("user-agent", edge), ("sec-fetch-dest", "document")]),
        ("curl (no browser)", vec![("user-agent", "curl/8.4.0")]),
        ("python-requests", vec![("user-agent", "python-requests/2.31.0")]),
        ("old chrome (2-digit, below floor)", vec![("user-agent", old_chrome)]),
        ("safari (excluded v1)", vec![("user-agent", safari)]),
        ("no user-agent", vec![("accept", "*/*")]),
    ];

    for (name, headers) in legit {
        let pipe = Pipeline::new(&config, vec![Box::new(BotDetectionModule::new(true))]);
        let mut ctx = request(&headers);
        assert!(
            matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
            "legit client must pass (no FP): {name}"
        );
    }
}

#[test]
fn module_is_structural() {
    assert!(BotDetectionModule::new(true).structural());
}
