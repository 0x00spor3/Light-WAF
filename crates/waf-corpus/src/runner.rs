// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The case runner: build a fresh raw context, run the real pipeline exactly as
//! the proxy does, and report what fired.
//!
//! Flow (mirrors `waf-proxy`): `run_connection` (pre-normalization framing /
//! smuggling) → `Normalizer::normalize` → `run_inspection` (content modules).
//!
//! Pipeline configuration, fixed for the corpus:
//! - **Blocking mode** so a Connection-phase `Reject` (request smuggling → 400) is
//!   observable as a verdict;
//! - **block_threshold = u32::MAX** so the anomaly threshold never short-circuits
//!   inspection — every matched rule is recorded and the full cumulative score is
//!   available to Pilastro 2;
//! - **rate limiter omitted** (neutralized) so a shared `client_ip` across
//!   sequential cases never produces a spurious 429;
//! - **all detection modules enabled** at the requested paranoia level.

use waf_core::testkit::Request;
use waf_core::{
    Config, GraphqlConfig, GrpcConfig, LimitsConfig, ModulesConfig, NetworkConfig, ProxyConfig,
    RateLimitConfig, RequestContext, ResilienceConfig, ScoreContribution, SeverityScores,
    WafConfig, WafMode, WafModule,
};
use waf_detection::ContentPrefilter;
use waf_detection::graphql::GraphqlModule;
use waf_detection::grpc::GrpcModule;
use waf_detection::header_injection::HeaderInjectionModule;
use waf_detection::ldap::LdapModule;
use waf_detection::lfi_rfi::LfiRfiModule;
use waf_detection::mail::MailModule;
use waf_detection::nosql::NosqlModule;
use waf_detection::path_traversal::PathTraversalModule;
use waf_detection::rce::RceModule;
use waf_detection::request_smuggling::RequestSmugglingModule;
use waf_detection::scanner::ScannerModule;
use waf_detection::sqli::SqliModule;
use waf_detection::ssi::SsiModule;
use waf_detection::ssrf::SsrfModule;
use waf_detection::ssti::SstiModule;
use waf_detection::xss::XssModule;
use waf_detection::xxe::XxeModule;
use waf_normalizer::Normalizer;
use waf_pipeline::{Pipeline, PipelineVerdict};

use crate::{Case, Field};

/// Worst-case paranoia: the highest level any shipped rule declares, so every rule
/// is active. Conservative baseline for the anti-regression guard.
pub const BASELINE_PARANOIA: u8 = waf_detection::HIGHEST_RULE_PARANOIA;

/// Simplified verdict mirror (decoupled from `PipelineVerdict`'s payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Block,
    Reject,
}

/// Outcome of attempting to run a case at a given execution paranoia level.
#[derive(Debug, Clone)]
pub enum RunResult {
    /// `execution_pl < case.min_pl`: the targeted rule is not active, so the case
    /// is not counted (neither recall nor false positive).
    Skipped,
    /// The case ran through the pipeline.
    Ran(CaseOutcome),
}

/// What a single case produced when run through the pipeline.
#[derive(Debug, Clone)]
pub struct CaseOutcome {
    /// At least one rule fired (content match, smuggling reject, or parser limit).
    pub triggered: bool,
    /// Cumulative anomaly score (feeds Pilastro 2). Zero for smuggling/parser-limit
    /// rejections, which do not accumulate score.
    pub score: u32,
    /// rule_ids that fired, in order (diagnostic + "at least one of" assertions).
    pub matched_rules: Vec<String>,
    /// Per-match score breakdown (`module` / `rule_id` / `severity` / `points`)
    /// under the run's `severity_scores`. Lets Pilastro 2 compute the **own-merit**
    /// score (sum of points whose `module` == case.module) separately from the
    /// total (overlaps included). Empty for smuggling/parser-limit rejections.
    pub contributions: Vec<ScoreContribution>,
    /// Final verdict observed.
    pub verdict: Verdict,
    /// True when normalization itself failed (a defensive-limit / parser rejection,
    /// equivalent to a 400). Counts as a trigger.
    pub normalization_failed: bool,
    /// True when the Pilastro 3 fast-path bypassed CONTENT inspection AND the outcome
    /// was a clean Allow (the prefilter proved no content rule could match). False on
    /// the full path, and false when a STRUCTURAL module (e.g. graphql) still acted on
    /// the skip path — that is a decision, not an avoided-work skip.
    pub fastpath_skipped: bool,
}

/// Run one case at the given execution paranoia level under the **default** (CRS)
/// severity weights. Returns [`RunResult::Skipped`] when `execution_pl <
/// case.min_pl`. Used by Pilastro 1 (detection recall, threshold = MAX).
pub fn run_case(case: &Case, execution_pl: u8) -> RunResult {
    run_case_with(case, execution_pl, SeverityScores::default())
}

/// Run one case under arbitrary `severity_scores` — Pilastro 2's seam for tuning.
/// The run keeps `block_threshold = u32::MAX` so the full cumulative score is
/// captured uncut; blocking against a candidate threshold is computed offline from
/// `score` / `contributions`. Each run builds a **fresh** context and pipeline —
/// no state crosses cases.
pub fn run_case_with(case: &Case, execution_pl: u8, severity: SeverityScores) -> RunResult {
    run_inner(case, execution_pl, severity, false)
}

/// Pilastro 3: same as [`run_case_with`] but with the content **fast-path** active.
/// After normalization the [`ContentPrefilter`] is consulted; when it proves no
/// content rule can match, inspection is skipped and the outcome is Allow with
/// `fastpath_skipped = true`. Otherwise it delegates to the identical full path.
pub fn run_case_fast(case: &Case, execution_pl: u8, severity: SeverityScores) -> RunResult {
    run_inner(case, execution_pl, severity, true)
}

fn run_inner(case: &Case, execution_pl: u8, severity: SeverityScores, fast: bool) -> RunResult {
    if execution_pl < case.min_pl {
        return RunResult::Skipped;
    }
    let config = corpus_config(execution_pl, severity);
    let pipeline = build_pipeline(&config);
    let mut ctx = build_ctx(&case.field);

    // 1. Connection phase (pre-normalization): request smuggling framing checks.
    match pipeline.run_connection(&mut ctx) {
        PipelineVerdict::Reject { rule_id, .. } => {
            return RunResult::Ran(reject_outcome(rule_id, ctx.score, Verdict::Reject));
        }
        PipelineVerdict::Block { rule_id, .. } => {
            return RunResult::Ran(reject_outcome(rule_id, ctx.score, Verdict::Block));
        }
        PipelineVerdict::Allow => {}
    }

    // 2. Normalize. A failure here is a defensive-limit / parser rejection (≈400).
    let normalizer = Normalizer::new(&config.limits);
    if normalizer.normalize(&mut ctx).is_err() {
        return RunResult::Ran(CaseOutcome {
            triggered: true,
            score: ctx.score,
            matched_rules: vec!["normalization-error".to_string()],
            contributions: Vec::new(),
            verdict: Verdict::Block,
            normalization_failed: true,
            fastpath_skipped: false,
        });
    }

    // 3. Inspection phase, through the SAME gate the proxy uses (Pilastro 3): when
    // `fast`, the prefilter decides whether to inspect; `run_inspection_gated` is the
    // single shared gating point, so the oracle tests the production code path.
    let inspect = !fast || ContentPrefilter::new(execution_pl).is_candidate(&ctx);
    let inspection = pipeline.run_inspection_gated(&mut ctx, inspect);
    // A genuine fast-path skip = CONTENT inspection was bypassed AND the outcome was a
    // clean Allow. When inspection is skipped a STRUCTURAL module (e.g. graphql) still
    // runs and may Block/Reject — that is NOT a skip (no work was avoided, a decision
    // was made), so the security fail-safe (a skip must never hide a block) still holds.
    let fastpath_skipped = !inspect && matches!(inspection, PipelineVerdict::Allow);

    let mut matched: Vec<String> = ctx
        .score_contributions
        .iter()
        .map(|c| c.rule_id.clone())
        .collect();
    let verdict = match inspection {
        PipelineVerdict::Allow => Verdict::Allow,
        PipelineVerdict::Block { rule_id, .. } => {
            if !matched.contains(&rule_id) {
                matched.push(rule_id);
            }
            Verdict::Block
        }
        PipelineVerdict::Reject { rule_id, .. } => {
            matched.push(rule_id);
            Verdict::Reject
        }
    };

    RunResult::Ran(CaseOutcome {
        triggered: !matched.is_empty() || verdict != Verdict::Allow,
        score: ctx.score,
        matched_rules: matched,
        contributions: ctx.score_contributions.clone(),
        verdict,
        normalization_failed: false,
        fastpath_skipped,
    })
}

fn reject_outcome(rule_id: String, score: u32, verdict: Verdict) -> CaseOutcome {
    CaseOutcome {
        triggered: true,
        score,
        matched_rules: vec![rule_id],
        contributions: Vec::new(),
        verdict,
        normalization_failed: false,
        fastpath_skipped: false,
    }
}

/// Build the raw (pre-normalization) context from the case's injection point.
fn build_ctx(field: &Field) -> RequestContext {
    let req = Request::new();
    match *field {
        Field::Query { name, value } => req.query(name, value).build(),
        Field::RawQuery(qs) => req.raw_query(qs).build(),
        Field::FormBody(raw) => req.method("POST").form_body(raw).build(),
        Field::JsonBody(raw) => req.method("POST").json_body(raw).build(),
        Field::RawBody { content_type, body } => {
            req.method("POST").body(body.as_bytes().to_vec(), content_type).build()
        }
        Field::Post { path, content_type, body } => {
            req.method("POST").path(path).body(body.as_bytes().to_vec(), content_type).build()
        }
        Field::Get { path, query } => req.method("GET").path(path).raw_query(query).build(),
        Field::Grpc { value } => req
            .method("POST")
            .path("/grpc.Svc/Call")
            .body(grpc_frame(&grpc_len_field(1, value.as_bytes())), "application/grpc")
            .build(),
        Field::GrpcNested { depth, leaf } => req
            .method("POST")
            .path("/grpc.Svc/Call")
            .body(grpc_frame(&grpc_nested(depth, leaf)), "application/grpc")
            .build(),
        Field::MultipartFile { field, filename, content } => {
            const BOUNDARY: &str = "----corpusFieldCoverage";
            let disposition = match filename {
                Some(fname) => format!("name=\"{field}\"; filename=\"{fname}\""),
                None => format!("name=\"{field}\""),
            };
            let body = format!(
                "--{BOUNDARY}\r\nContent-Disposition: form-data; {disposition}\r\n\
                 Content-Type: application/octet-stream\r\n\r\n{content}\r\n--{BOUNDARY}--\r\n"
            );
            req.method("POST")
                .body(body.into_bytes(), &format!("multipart/form-data; boundary={BOUNDARY}"))
                .build()
        }
        Field::Cookie(raw) => req.cookie_header(raw).build(),
        Field::Header { name, value } => req.header(name, value).build(),
        Field::Path(path) => req.path(path).build(),
        Field::Smuggling(headers) => {
            let mut req = req.method("POST");
            for (name, value) in headers {
                req = req.header(name, value);
            }
            req.build()
        }
    }
}

// ── gRPC body encoders (for `Field::Grpc*`) ─────────────────────────────────────

fn grpc_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

/// A length-delimited (wire-type 2) protobuf field carrying `data`.
fn grpc_len_field(field: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    grpc_varint((field << 3) | 2, &mut out);
    grpc_varint(data.len() as u64, &mut out);
    out.extend_from_slice(data);
    out
}

/// A varint (wire-type 0) field — used to force NON-UTF-8 bytes so a wrapping sub-message
/// is recursed (not mistaken for a string leaf).
fn grpc_varint_field(field: u64, value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    grpc_varint(field << 3, &mut out);
    grpc_varint(value, &mut out);
    out
}

/// `depth` nested sub-messages (each wraps a varint → non-UTF-8 → recursion) with a
/// benign `leaf` string at the bottom.
fn grpc_nested(depth: u32, leaf: &str) -> Vec<u8> {
    let mut inner = grpc_varint_field(2, 300);
    inner.extend_from_slice(&grpc_len_field(15, leaf.as_bytes()));
    for _ in 0..depth {
        let mut wrap = grpc_varint_field(2, 300);
        wrap.extend_from_slice(&grpc_len_field(1, &inner));
        inner = wrap;
    }
    inner
}

/// Wrap a protobuf message in one uncompressed gRPC frame `[0][len:4 BE][msg]`.
fn grpc_frame(msg: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8];
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// All detection modules except the rate limiter (neutralized). Mirrors the
/// proxy's `build_modules` ordering: smuggling first (Connection), then content.
fn build_pipeline(config: &Config) -> Pipeline {
    let modules: Vec<Box<dyn WafModule>> = vec![
        Box::new(RequestSmugglingModule::new()),
        Box::new(SqliModule::new()),
        Box::new(XssModule::new()),
        Box::new(PathTraversalModule::new()),
        Box::new(RceModule::new()),
        Box::new(LfiRfiModule::new()),
        Box::new(SsrfModule::new()),
        Box::new(LdapModule::new()),
        Box::new(NosqlModule::new()),
        Box::new(MailModule::new()),
        Box::new(SstiModule::new()),
        Box::new(ScannerModule::new()),
        Box::new(SsiModule::new()),
        Box::new(XxeModule::new()),
        Box::new(HeaderInjectionModule::new()),
        Box::new(GraphqlModule::new()),
        Box::new(GrpcModule::new()),
    ];
    Pipeline::new(config, modules)
}

// ── bench seams (Pilastro 3) ───────────────────────────────────────────────────

/// A corpus pipeline at `(pl, severity)` — public so `examples/fastpath_bench.rs`
/// can build it once and time inspection in isolation.
pub fn corpus_pipeline(pl: u8, severity: SeverityScores) -> Pipeline {
    build_pipeline(&corpus_config(pl, severity))
}

/// Build + run the connection phase + normalize a context for `field` (no content
/// inspection). Returns `None` when the connection phase already rejects (request
/// smuggling) — those cases have no inspection to benchmark. Public for benches.
pub fn prepared_ctx(field: &Field, pl: u8, severity: SeverityScores) -> Option<RequestContext> {
    let config = corpus_config(pl, severity);
    let pipeline = build_pipeline(&config);
    let mut ctx = build_ctx(field);
    if !matches!(pipeline.run_connection(&mut ctx), PipelineVerdict::Allow) {
        return None;
    }
    Normalizer::new(&config.limits).normalize(&mut ctx).ok()?;
    Some(ctx)
}

/// Fixed corpus pipeline config (see module docs for the rationale). `severity` is
/// the only scoring knob the caller varies; the threshold stays at MAX so the run
/// captures the full uncut score regardless of the candidate threshold.
fn corpus_config(paranoia: u8, severity: SeverityScores) -> Config {
    Config {
        proxy: ProxyConfig {
            listen: "127.0.0.1:8080".parse().expect("valid loopback addr"),
            backend: "http://localhost:3000".to_string(),
        },
        waf: WafConfig {
            mode: WafMode::Blocking,
            // Never let the anomaly threshold short-circuit inspection: we want
            // every matched rule + the full cumulative score for every case.
            block_threshold: u32::MAX,
            paranoia_level: paranoia,
            severity_scores: severity,
        },
        limits: LimitsConfig::default(),
        // All modules enabled. GraphQL and gRPC are OFF in production by default (opt-in),
        // so the corpus harness turns them ON (graphql with introspection-blocking) to
        // exercise the structural cases; default caps apply.
        modules: ModulesConfig {
            graphql: GraphqlConfig { enabled: true, block_introspection: true, ..Default::default() },
            grpc: GrpcConfig { enabled: true, ..Default::default() },
            ..Default::default()
        },
        rate_limit: RateLimitConfig::default(), // enabled = false → neutralized
        network: NetworkConfig::default(),
        resilience: ResilienceConfig::default(),
        tls: Default::default(),
    }
}


