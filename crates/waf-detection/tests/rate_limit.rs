// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, ProxyConfig, RateLimitAction,
    RateLimitConfig, RateLimitKey, RequestContext, WafConfig, WafMode, WafModule,
};
use waf_pipeline::{Pipeline, PipelineVerdict};

use waf_detection::rate_limit::{ManualClock, RateLimitModule};

// ── helpers ───────────────────────────────────────────────────────────────────

fn config(requests: u32, window: u64, burst: u32, action: RateLimitAction, mode: WafMode) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode,
            block_threshold: 5,
            paranoia_level: 1,
            severity_scores: Default::default(),
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig::default(),
        rate_limit: RateLimitConfig {
            enabled: true,
            key: RateLimitKey::ClientIp,
            requests,
            window_seconds: window,
            burst: Some(burst),
            action,
            score: 5,
            max_tracked_keys: 1000,
        },
        network: Default::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

fn ctx_ip(ip: &str) -> RequestContext {
    RequestContext {
        client_ip: ip.parse().unwrap(),
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

fn module(clock: Arc<ManualClock>, cfg: &Config) -> RateLimitModule {
    let mut m = RateLimitModule::with_clock(clock);
    m.init(cfg);
    m
}

fn is_reject_429(d: &Decision) -> bool {
    matches!(d, Decision::Reject { status: 429, .. })
}

// ── token bucket behaviour ─────────────────────────────────────────────────────

#[test]
fn rl_allows_within_limit_then_rejects() {
    let clock = Arc::new(ManualClock::new());
    let cfg = config(2, 1, 2, RateLimitAction::Block, WafMode::Blocking);
    let m = module(clock, &cfg);
    let ctx = ctx_ip("203.0.113.7");

    assert!(matches!(m.inspect(&ctx), Decision::Allow)); // 2 -> 1
    assert!(matches!(m.inspect(&ctx), Decision::Allow)); // 1 -> 0
    assert!(is_reject_429(&m.inspect(&ctx)), "3rd request must be rejected"); // 0 -> reject
}

#[test]
fn rl_bucket_refills_over_time() {
    let clock = Arc::new(ManualClock::new());
    let cfg = config(2, 1, 2, RateLimitAction::Block, WafMode::Blocking); // refill 2/s
    let m = module(clock.clone(), &cfg);
    let ctx = ctx_ip("203.0.113.8");

    assert!(matches!(m.inspect(&ctx), Decision::Allow));
    assert!(matches!(m.inspect(&ctx), Decision::Allow));
    assert!(is_reject_429(&m.inspect(&ctx)));

    // After one full window the bucket is back to capacity.
    clock.advance(Duration::from_secs(1));
    assert!(matches!(m.inspect(&ctx), Decision::Allow), "should allow after refill");
    assert!(matches!(m.inspect(&ctx), Decision::Allow));
    assert!(is_reject_429(&m.inspect(&ctx)));
}

#[test]
fn rl_burst_capacity_then_throttle() {
    let clock = Arc::new(ManualClock::new());
    // High capacity (5), slow refill (1/60s) — allows a burst of 5, then throttles.
    let cfg = config(1, 60, 5, RateLimitAction::Block, WafMode::Blocking);
    let m = module(clock, &cfg);
    let ctx = ctx_ip("203.0.113.9");

    for i in 0..5 {
        assert!(matches!(m.inspect(&ctx), Decision::Allow), "burst request {i} should pass");
    }
    assert!(is_reject_429(&m.inspect(&ctx)), "6th request beyond burst must be rejected");
}

#[test]
fn rl_keys_are_isolated() {
    let clock = Arc::new(ManualClock::new());
    let cfg = config(1, 60, 1, RateLimitAction::Block, WafMode::Blocking);
    let m = module(clock, &cfg);

    let a = ctx_ip("198.51.100.1");
    let b = ctx_ip("198.51.100.2");

    assert!(matches!(m.inspect(&a), Decision::Allow));
    assert!(is_reject_429(&m.inspect(&a)), "A is now throttled");
    assert!(matches!(m.inspect(&b), Decision::Allow), "B must be unaffected by A");
}

#[test]
fn rl_retry_after_is_present_and_positive() {
    let clock = Arc::new(ManualClock::new());
    let cfg = config(1, 60, 1, RateLimitAction::Block, WafMode::Blocking);
    let m = module(clock, &cfg);
    let ctx = ctx_ip("203.0.113.10");

    assert!(matches!(m.inspect(&ctx), Decision::Allow));
    match m.inspect(&ctx) {
        Decision::Reject { status: 429, retry_after, .. } => {
            assert!(retry_after.unwrap() >= 1, "retry-after must be >= 1s");
        }
        other => panic!("expected 429 reject, got {other:?}"),
    }
}

// ── score action ──────────────────────────────────────────────────────────────

#[test]
fn rl_score_action_emits_score_not_reject() {
    let clock = Arc::new(ManualClock::new());
    let cfg = config(1, 60, 1, RateLimitAction::Score, WafMode::Blocking);
    let m = module(clock, &cfg);
    let ctx = ctx_ip("203.0.113.11");

    assert!(matches!(m.inspect(&ctx), Decision::Allow));
    match m.inspect(&ctx) {
        Decision::Score { ref rule_id, points } => {
            assert_eq!(rule_id, "rate-limit-exceeded");
            assert_eq!(points, 5);
        }
        other => panic!("expected Score, got {other:?}"),
    }
}

// ── disabled ──────────────────────────────────────────────────────────────────

#[test]
fn rl_disabled_allows_everything() {
    let clock = Arc::new(ManualClock::new());
    let mut cfg = config(1, 60, 1, RateLimitAction::Block, WafMode::Blocking);
    cfg.rate_limit.enabled = false;
    let m = module(clock, &cfg);
    let ctx = ctx_ip("203.0.113.12");
    for _ in 0..10 {
        assert!(matches!(m.inspect(&ctx), Decision::Allow));
    }
}

// ── eviction ──────────────────────────────────────────────────────────────────

#[test]
fn rl_idle_buckets_are_evicted_at_cap() {
    let clock = Arc::new(ManualClock::new());
    let mut cfg = config(2, 1, 2, RateLimitAction::Block, WafMode::Blocking); // full-refill = 1s
    cfg.rate_limit.max_tracked_keys = 2;
    let m = module(clock.clone(), &cfg);

    m.inspect(&ctx_ip("10.0.0.1"));
    m.inspect(&ctx_ip("10.0.0.2"));
    assert_eq!(m.tracked_keys(), 2);

    // Advance past the full-refill window so the two buckets are "full"/idle,
    // then a third key triggers the cap sweep.
    clock.advance(Duration::from_secs(5));
    m.inspect(&ctx_ip("10.0.0.3"));
    assert_eq!(m.tracked_keys(), 1, "idle buckets should have been swept");
}

// ── pipeline integration (mode semantics) ──────────────────────────────────────

#[test]
fn rl_pipeline_rejects_in_blocking_mode() {
    // requests=1 over a 60s window: 2nd request within the window is over budget.
    let cfg = config(1, 60, 1, RateLimitAction::Block, WafMode::Blocking);
    let pipeline = Pipeline::new(&cfg, vec![Box::new(RateLimitModule::new())]);
    let mut ctx = ctx_ip("192.0.2.1");

    assert!(matches!(pipeline.run_connection(&mut ctx), PipelineVerdict::Allow));
    let mut ctx2 = ctx_ip("192.0.2.1");
    assert!(matches!(
        pipeline.run_connection(&mut ctx2),
        PipelineVerdict::Reject { status: 429, .. }
    ));
}

#[test]
fn rl_pipeline_detection_only_logs_but_allows() {
    let cfg = config(1, 60, 1, RateLimitAction::Block, WafMode::DetectionOnly);
    let pipeline = Pipeline::new(&cfg, vec![Box::new(RateLimitModule::new())]);

    let mut ctx1 = ctx_ip("192.0.2.2");
    assert!(matches!(pipeline.run_connection(&mut ctx1), PipelineVerdict::Allow));
    // Over budget, but detection-only never rejects.
    let mut ctx2 = ctx_ip("192.0.2.2");
    assert!(matches!(pipeline.run_connection(&mut ctx2), PipelineVerdict::Allow));
}
