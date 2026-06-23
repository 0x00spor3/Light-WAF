use std::sync::{Arc, Mutex};

use waf_core::{
    Bytes, Config, Decision, LimitsConfig, ModulesConfig, Normalized, Phase, ProxyConfig,
    RequestContext, ScoreItem, Severity, SeverityScores, WafConfig, WafMode, WafModule,
};
use waf_pipeline::{Pipeline, PipelineVerdict};

// ── helpers ─────────────────────────────────────────────────────────────────

/// A configurable module that records invocation order and returns a fixed Decision.
struct RecordingModule {
    id: &'static str,
    phase: Phase,
    decision: Decision,
    call_log: Arc<Mutex<Vec<&'static str>>>,
}

impl WafModule for RecordingModule {
    fn id(&self) -> &str {
        self.id
    }
    fn phase(&self) -> Phase {
        self.phase
    }
    fn init(&mut self, _: &Config) {}
    fn inspect(&self, _: &RequestContext) -> Decision {
        self.call_log.lock().unwrap().push(self.id);
        self.decision.clone()
    }
}

fn test_ctx() -> RequestContext {
    RequestContext {
        client_ip: "127.0.0.1".parse().unwrap(),
        request_id: "test-req".to_string(),
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

fn cfg(mode: WafMode, threshold: u32) -> Config {
    cfg_full(mode, threshold, SeverityScores::default())
}

fn cfg_full(mode: WafMode, threshold: u32, severity_scores: SeverityScores) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().unwrap(),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode,
            block_threshold: threshold,
            paranoia_level: 1,
            severity_scores,
        },
        limits: LimitsConfig::default(),
        modules: ModulesConfig::default(),
        rate_limit: Default::default(),
        network: Default::default(),
        resilience: Default::default(),
        tls: Default::default(),
    }
}

/// A module whose `inspect` always panics — exercises Pillar-2 panic isolation.
struct PanicModule {
    phase: Phase,
}

impl WafModule for PanicModule {
    fn id(&self) -> &str {
        "panic_mod"
    }
    fn phase(&self) -> Phase {
        self.phase
    }
    fn init(&mut self, _: &Config) {}
    fn inspect(&self, _: &RequestContext) -> Decision {
        panic!("boom: simulated module defect");
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

#[test]
fn pipeline_runs_modules_in_phase_order() {
    let log: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(vec![]));
    // Inserted in reversed phase order — pipeline must reorder them.
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(RecordingModule {
            id: "rl_mod",
            phase: Phase::RequestLine,
            decision: Decision::Allow,
            call_log: Arc::clone(&log),
        }),
        Box::new(RecordingModule {
            id: "conn_mod",
            phase: Phase::Connection,
            decision: Decision::Allow,
            call_log: Arc::clone(&log),
        }),
        Box::new(RecordingModule {
            id: "hdr_mod",
            phase: Phase::Headers,
            decision: Decision::Allow,
            call_log: Arc::clone(&log),
        }),
    ];

    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 100), modules);
    let verdict = pipeline.run(&mut test_ctx());

    assert!(matches!(verdict, PipelineVerdict::Allow));
    assert_eq!(
        *log.lock().unwrap(),
        vec!["conn_mod", "rl_mod", "hdr_mod"]
    );
}

#[test]
fn detection_only_does_not_block_on_block_decision() {
    let modules: Vec<Box<dyn WafModule>> = vec![Box::new(RecordingModule {
        id: "blocker",
        phase: Phase::RequestLine,
        decision: Decision::Block {
            rule_id: "r001".to_string(),
            reason: "test block".to_string(),
        },
        call_log: Arc::new(Mutex::new(vec![])),
    })];

    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 100), modules);
    assert!(matches!(pipeline.run(&mut test_ctx()), PipelineVerdict::Allow));
}

#[test]
fn blocking_mode_stops_on_block_decision() {
    let log: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(vec![]));
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(RecordingModule {
            id: "blocker",
            phase: Phase::RequestLine,
            decision: Decision::Block {
                rule_id: "r001".to_string(),
                reason: "test block".to_string(),
            },
            call_log: Arc::clone(&log),
        }),
        Box::new(RecordingModule {
            // later phase — must NOT be called
            id: "should_not_run",
            phase: Phase::Headers,
            decision: Decision::Allow,
            call_log: Arc::clone(&log),
        }),
    ];

    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 100), modules);
    let verdict = pipeline.run(&mut test_ctx());

    assert!(matches!(verdict, PipelineVerdict::Block { .. }));
    assert_eq!(*log.lock().unwrap(), vec!["blocker"]);
}

#[test]
fn score_accumulates_across_modules_and_phases() {
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(RecordingModule {
            id: "scorer_a",
            phase: Phase::RequestLine,
            decision: Decision::Score {
                rule_id: "r1".to_string(),
                points: 5,
            },
            call_log: Arc::new(Mutex::new(vec![])),
        }),
        Box::new(RecordingModule {
            id: "scorer_b",
            phase: Phase::Headers,
            decision: Decision::Score {
                rule_id: "r2".to_string(),
                points: 5,
            },
            call_log: Arc::new(Mutex::new(vec![])),
        }),
    ];

    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 100), modules);
    let mut ctx = test_ctx();
    pipeline.run(&mut ctx);

    assert_eq!(ctx.score, 10);
}

#[test]
fn score_at_threshold_blocks_in_blocking_mode() {
    let modules: Vec<Box<dyn WafModule>> = vec![Box::new(RecordingModule {
        id: "heavy_scorer",
        phase: Phase::RequestLine,
        decision: Decision::Score {
            rule_id: "r1".to_string(),
            points: 10,
        },
        call_log: Arc::new(Mutex::new(vec![])),
    })];

    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 10), modules);
    assert!(matches!(
        pipeline.run(&mut test_ctx()),
        PipelineVerdict::Block { .. }
    ));
}

#[test]
fn score_at_threshold_allows_in_detection_only() {
    let modules: Vec<Box<dyn WafModule>> = vec![Box::new(RecordingModule {
        id: "heavy_scorer",
        phase: Phase::RequestLine,
        decision: Decision::Score {
            rule_id: "r1".to_string(),
            points: 10,
        },
        call_log: Arc::new(Mutex::new(vec![])),
    })];

    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 10), modules);
    assert!(matches!(
        pipeline.run(&mut test_ctx()),
        PipelineVerdict::Allow
    ));
}

#[test]
fn monitor_decision_does_not_block_in_any_mode() {
    for mode in [WafMode::DetectionOnly, WafMode::Blocking] {
        let modules: Vec<Box<dyn WafModule>> = vec![Box::new(RecordingModule {
            id: "monitor_mod",
            phase: Phase::RequestLine,
            decision: Decision::Monitor {
                rule_id: "m1".to_string(),
            },
            call_log: Arc::new(Mutex::new(vec![])),
        })];
        let pipeline = Pipeline::new(&cfg(mode, 5), modules);
        assert!(matches!(pipeline.run(&mut test_ctx()), PipelineVerdict::Allow));
    }
}

#[test]
fn score_accumulates_but_late_phase_modules_still_run_in_detection_only() {
    // Even after score >= threshold, detection-only continues running all modules.
    let log: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(vec![]));
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(RecordingModule {
            id: "early_scorer",
            phase: Phase::RequestLine,
            decision: Decision::Score {
                rule_id: "r1".to_string(),
                points: 100,
            },
            call_log: Arc::clone(&log),
        }),
        Box::new(RecordingModule {
            id: "late_mod",
            phase: Phase::Headers,
            decision: Decision::Allow,
            call_log: Arc::clone(&log),
        }),
    ];

    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 5), modules);
    let verdict = pipeline.run(&mut test_ctx());

    assert!(matches!(verdict, PipelineVerdict::Allow));
    assert_eq!(*log.lock().unwrap(), vec!["early_scorer", "late_mod"]);
}

// ── Decision::Scores (cumulative, severity-based) ──────────────────────────────

fn scores_module(id: &'static str, items: Vec<(&'static str, Severity)>) -> Box<dyn WafModule> {
    Box::new(RecordingModule {
        id,
        phase: Phase::Body,
        decision: Decision::Scores(
            items
                .into_iter()
                .map(|(rule_id, severity)| ScoreItem {
                    rule_id: rule_id.to_string(),
                    severity,
                })
                .collect(),
        ),
        call_log: Arc::new(Mutex::new(vec![])),
    })
}

#[test]
fn scores_variant_sums_every_matched_rule_within_a_module() {
    // Three Notice matches must weigh more than one — CRS-style intra-module sum.
    let modules = vec![scores_module(
        "multi",
        vec![
            ("r-notice-1", Severity::Notice),
            ("r-notice-2", Severity::Notice),
            ("r-notice-3", Severity::Notice),
        ],
    )];
    // notice = 2 by default → 3 * 2 = 6
    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 100), modules);
    let mut ctx = test_ctx();
    pipeline.run(&mut ctx);
    assert_eq!(ctx.score, 6);
    assert_eq!(ctx.score_contributions.len(), 3);
}

#[test]
fn score_contributions_record_module_rule_severity_and_points() {
    let modules = vec![scores_module(
        "sqli",
        vec![("sqli-union-select", Severity::Critical)],
    )];
    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 100), modules);
    let mut ctx = test_ctx();
    pipeline.run(&mut ctx);

    assert_eq!(ctx.score_contributions.len(), 1);
    let c = &ctx.score_contributions[0];
    assert_eq!(c.module, "sqli");
    assert_eq!(c.rule_id, "sqli-union-select");
    assert_eq!(c.severity, Some(Severity::Critical));
    assert_eq!(c.points, 6); // default critical (Fase 7/P2 config C2: 5 -> 6)
}

#[test]
fn severity_scores_are_configurable() {
    let items = vec![("r1", Severity::Warning)];
    // default warning = 3 → below threshold 5 → allow
    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 5), vec![scores_module("m", items.clone())]);
    assert!(matches!(pipeline.run(&mut test_ctx()), PipelineVerdict::Allow));

    // bump warning to 5 → now a single warning reaches the threshold → block
    let custom = SeverityScores { critical: 5, error: 4, warning: 5, notice: 2 };
    let pipeline = Pipeline::new(
        &cfg_full(WafMode::Blocking, 5, custom),
        vec![scores_module("m", items)],
    );
    assert!(matches!(pipeline.run(&mut test_ctx()), PipelineVerdict::Block { .. }));
}

#[test]
fn single_high_severity_match_blocks_alone() {
    // One Critical (= 6, default C2 / Fase7-P2, see ARCHITECTURE §7) >= threshold
    // (5) blocks on its own.
    let modules = vec![scores_module("m", vec![("crit", Severity::Critical)])];
    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 5), modules);
    assert!(matches!(pipeline.run(&mut test_ctx()), PipelineVerdict::Block { .. }));
}

#[test]
fn multiple_low_severity_matches_block_when_summed() {
    // Two Warning matches across two modules: 3 + 3 = 6 >= 5 → block,
    // while a single Warning (3) alone stays below the threshold.
    let one = vec![scores_module("a", vec![("wa", Severity::Warning)])];
    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 5), one);
    assert!(matches!(pipeline.run(&mut test_ctx()), PipelineVerdict::Allow));

    let two = vec![
        scores_module("a", vec![("wa", Severity::Warning)]),
        scores_module("b", vec![("wb", Severity::Warning)]),
    ];
    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 5), two);
    let mut ctx = test_ctx();
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Block { .. }));
    assert_eq!(ctx.score, 6);
}

#[test]
fn scores_over_threshold_logged_but_allowed_in_detection_only() {
    let modules = vec![scores_module(
        "m",
        vec![("c1", Severity::Critical), ("c2", Severity::Critical)],
    )];
    // 6 + 6 = 12 >= threshold 5 (default critical = 6, Fase 7/P2), but
    // detection-only never blocks.
    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 5), modules);
    let mut ctx = test_ctx();
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
    assert_eq!(ctx.score, 12);
}

// ── phase split: run_connection / run_inspection ───────────────────────────────

fn recording(id: &'static str, phase: Phase, decision: Decision, log: Arc<Mutex<Vec<&'static str>>>) -> Box<dyn WafModule> {
    Box::new(RecordingModule { id, phase, decision, call_log: log })
}

#[test]
fn run_connection_runs_only_connection_phase() {
    let log: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(vec![]));
    let modules = vec![
        recording("conn", Phase::Connection, Decision::Allow, Arc::clone(&log)),
        recording("body", Phase::Body, Decision::Allow, Arc::clone(&log)),
    ];
    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 100), modules);
    let mut ctx = test_ctx();

    assert!(matches!(pipeline.run_connection(&mut ctx), PipelineVerdict::Allow));
    assert_eq!(*log.lock().unwrap(), vec!["conn"], "only the connection phase runs");

    assert!(matches!(pipeline.run_inspection(&mut ctx), PipelineVerdict::Allow));
    assert_eq!(*log.lock().unwrap(), vec!["conn", "body"], "inspection runs the rest");
}

#[test]
fn reject_decision_yields_reject_verdict_in_blocking() {
    let modules = vec![recording(
        "rl",
        Phase::Connection,
        Decision::Reject {
            rule_id: "rate-limit".to_string(),
            reason: "rate limit exceeded".to_string(),
            status: 429,
            retry_after: Some(7),
        },
        Arc::new(Mutex::new(vec![])),
    )];
    let pipeline = Pipeline::new(&cfg(WafMode::Blocking, 100), modules);
    let mut ctx = test_ctx();
    match pipeline.run_connection(&mut ctx) {
        PipelineVerdict::Reject { status, retry_after, .. } => {
            assert_eq!(status, 429);
            assert_eq!(retry_after, Some(7));
        }
        _ => panic!("expected Reject verdict"),
    }
}

#[test]
fn reject_decision_does_not_reject_in_detection_only() {
    let modules = vec![recording(
        "rl",
        Phase::Connection,
        Decision::Reject {
            rule_id: "rate-limit".to_string(),
            reason: "rate limit exceeded".to_string(),
            status: 429,
            retry_after: Some(7),
        },
        Arc::new(Mutex::new(vec![])),
    )];
    let pipeline = Pipeline::new(&cfg(WafMode::DetectionOnly, 100), modules);
    let mut ctx = test_ctx();
    assert!(matches!(pipeline.run_connection(&mut ctx), PipelineVerdict::Allow));
}

// ── panic isolation (Fase 6 / Pillar 2) ────────────────────────────────────────

fn cfg_internal(policy: waf_core::FailMode) -> Config {
    let mut c = cfg(WafMode::Blocking, 100);
    c.resilience.on_internal_error = policy;
    c
}

#[test]
fn panicking_module_fail_open_is_caught_and_request_proceeds() {
    // The panic must NOT propagate (the test process stays alive) and, with
    // fail_open, the verdict is Allow (the faulty module is skipped).
    let modules: Vec<Box<dyn WafModule>> =
        vec![Box::new(PanicModule { phase: Phase::RequestLine })];
    let pipeline = Pipeline::new(&cfg_internal(waf_core::FailMode::FailOpen), modules);
    let mut ctx = test_ctx();
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
}

#[test]
fn panicking_module_fail_closed_blocks_in_blocking_mode() {
    let modules: Vec<Box<dyn WafModule>> =
        vec![Box::new(PanicModule { phase: Phase::RequestLine })];
    let pipeline = Pipeline::new(&cfg_internal(waf_core::FailMode::FailClosed), modules);
    let mut ctx = test_ctx();
    match pipeline.run(&mut ctx) {
        PipelineVerdict::Block { rule_id, .. } => assert_eq!(rule_id, "internal-error"),
        other => panic!("expected Block from fail_closed panic, got {other:?}"),
    }
}

#[test]
fn panic_is_isolated_other_modules_still_run() {
    // After a module panics (fail_open → skipped), a later module in the chain
    // must still run and contribute — the panic doesn't poison the pipeline.
    let log: Arc<Mutex<Vec<&str>>> = Arc::new(Mutex::new(vec![]));
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(PanicModule { phase: Phase::RequestLine }),
        recording("after", Phase::Body, Decision::Allow, Arc::clone(&log)),
    ];
    let pipeline = Pipeline::new(&cfg_internal(waf_core::FailMode::FailOpen), modules);
    let mut ctx = test_ctx();
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
    assert_eq!(*log.lock().unwrap(), vec!["after"], "module after the panic still ran");
}

#[test]
fn panicking_module_fail_closed_only_logs_in_detection_only() {
    // Mode semantics intact: detection-only never blocks, even on fail_closed.
    let mut c = cfg(WafMode::DetectionOnly, 100);
    c.resilience.on_internal_error = waf_core::FailMode::FailClosed;
    let modules: Vec<Box<dyn WafModule>> =
        vec![Box::new(PanicModule { phase: Phase::RequestLine })];
    let pipeline = Pipeline::new(&c, modules);
    let mut ctx = test_ctx();
    assert!(matches!(pipeline.run(&mut ctx), PipelineVerdict::Allow));
}
