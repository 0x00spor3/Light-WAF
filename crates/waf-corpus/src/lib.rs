//! Validation corpus for the WAF (Fase 7 / Pilastro 1).
//!
//! A single, versioned, reproducible set of cases — malicious (must trigger) and
//! benign (must not), including the known false-positive traps — run against the
//! **real** pipeline (`run_connection` → `normalize` → `run_inspection`). Detection
//! is frozen: the corpus *measures* what exists, it does not change rules.
//!
//! This crate is a library on purpose: the same corpus becomes the evidence base
//! for Pilastro 2 (threshold tuning, via the per-case score) and the equivalence
//! oracle for Pilastro 3 (fast-path).
//!
//! Design invariants (see [`runner`]):
//! - **fresh context per case** — every case starts from `score = 0` and a new
//!   `RequestContext`; no state is shared between cases;
//! - **rate-limit neutralized** — the pipeline is built without the rate limiter
//!   so a shared `client_ip` across sequential cases never yields a spurious 429;
//! - **paranoia is a runner parameter** — baseline [`runner::BASELINE_PARANOIA`]
//!   (worst case), but Pilastro 2 can re-run at other levels.

pub mod cases;
pub mod metrics;
pub mod runner;

pub use metrics::{Aggregate, BlockingReport, ModuleMetrics, Report, ScoringConfig};
pub use runner::{
    corpus_pipeline, prepared_ctx, run_case, run_case_fast, run_case_with, BASELINE_PARANOIA,
    CaseOutcome, RunResult, Verdict,
};

use waf_core::SeverityScores;

// ── Fase 7 / Pilastro 2: recommended scoring config (C2) ───────────────────────
//
// CRS weights with **Critical raised 5 → 6** so a single high-confidence rule
// blocks with own-merit margin ≥ 1 (the robustness CRS-default 5/T5 lacks), while
// weak signals stay sub-threshold so they only block in accumulation (anti-FP, see
// ARCHITECTURE §7 and the rfi-remote-url FP-prone rationale). Chosen over CRS-pure
// (C0), threshold-lowering (C1 → 2×Notice would block, mass FP in production) and a
// wide rescale (C3 → drops Warning+Notice accumulation, lowers blocking recall) on
// the corpus evidence. The sweep verified C2 has the SAME blocking set as C0 with
// benign-blocking 0 at every PL. Validated by `tests/validation.rs`.

/// Recommended severity→points weights (C2).
pub const RECOMMENDED_SEVERITY: SeverityScores =
    SeverityScores { critical: 6, error: 4, warning: 3, notice: 2 };

/// Recommended anomaly `block_threshold` (unchanged from CRS default).
pub const RECOMMENDED_THRESHOLD: u32 = 5;

/// The recommended config as a [`ScoringConfig`] for corpus evaluation.
pub const RECOMMENDED_CONFIG: ScoringConfig = ScoringConfig {
    label: "C2 recommended (6/4/3/2, T5)",
    severity: RECOMMENDED_SEVERITY,
    threshold: RECOMMENDED_THRESHOLD,
};

/// Detection module a case targets. Also the bucket key for aggregate metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Module {
    Sqli,
    Xss,
    PathTraversal,
    Rce,
    LfiRfi,
    Ssrf,
    Ldap,
    Nosql,
    Mail,
    Ssti,
    Scanner,
    Ssi,
    Xxe,
    HeaderInjection,
    RequestSmuggling,
    Graphql,
}

impl Module {
    /// Stable lowercase identifier, matching the module `id()` and the ARCHITECTURE
    /// naming (`sqli`, `path_traversal`, …).
    pub fn name(self) -> &'static str {
        match self {
            Module::Sqli => "sqli",
            Module::Xss => "xss",
            Module::PathTraversal => "path_traversal",
            Module::Rce => "rce",
            Module::LfiRfi => "lfi_rfi",
            Module::Ssrf => "ssrf",
            Module::Ldap => "ldap",
            Module::Nosql => "nosql",
            Module::Mail => "mail",
            Module::Ssti => "ssti",
            Module::Scanner => "scanner",
            Module::Ssi => "ssi",
            Module::Xxe => "xxe",
            Module::HeaderInjection => "header_injection",
            Module::RequestSmuggling => "request_smuggling",
            Module::Graphql => "graphql",
        }
    }
}

/// Where a case injects its payload. Carries the raw payload; the runner builds the
/// pre-normalization `RequestContext` from it and runs the real normalizer.
#[derive(Debug, Clone, Copy)]
pub enum Field {
    /// `name=value` query parameter; the value is minimally encoded so the
    /// normalizer decodes it back exactly (see `testkit::Request::query`).
    Query { name: &'static str, value: &'static str },
    /// Verbatim raw query string — for self-encoded payloads (double-encoding,
    /// literal `+`).
    RawQuery(&'static str),
    /// Raw `application/x-www-form-urlencoded` body (`a=b&c=d`).
    FormBody(&'static str),
    /// Raw JSON body text.
    JsonBody(&'static str),
    /// Raw POST body with an explicit Content-Type the parser does NOT structure
    /// (e.g. `application/graphql`) → `ParsedBody::Raw`. Exercises the raw-body
    /// canonicalization channel (Phase-11 transport coverage).
    RawBody { content_type: &'static str, body: &'static str },
    /// POST to a specific `path` with an explicit Content-Type and body — for cases
    /// that depend on the request path (e.g. GraphQL endpoint gating). (Phase 11.)
    Post { path: &'static str, content_type: &'static str, body: &'static str },
    /// GET to a specific `path` with a raw query string — for path-dependent GET cases
    /// (e.g. GraphQL over GET `?query=`). (Phase 11.)
    Get { path: &'static str, query: &'static str },
    /// A single `multipart/form-data` part. The runner assembles the raw multipart
    /// body (fixed boundary) from the form field `name`, an optional `filename`
    /// and the part `content`, so field-coverage cases can target the name /
    /// filename / value without hand-writing boundaries. `filename: None` omits the
    /// `filename=` attribute entirely (the gotestwaf name-only shape). (10b-cont.)
    MultipartFile {
        field: &'static str,
        filename: Option<&'static str>,
        content: &'static str,
    },
    /// Raw `Cookie` header value (`name=value; …`).
    Cookie(&'static str),
    /// A single raw header.
    Header { name: &'static str, value: &'static str },
    /// Request path (sets `raw_path`; the normalizer resolves it into
    /// `normalized.path`).
    Path(&'static str),
    /// Raw headers for request-smuggling framing cases (e.g. CL + TE).
    Smuggling(&'static [(&'static str, &'static str)]),
}

/// The explicit expectation for a case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Malicious: at least one rule must fire (and one of `rules`, if specified).
    Triggers,
    /// Benign / trap: nothing must fire.
    Clean,
    /// A documented detection gap. Tracked in metrics, never gates recall — but the
    /// deferral is **machine-checkable**: `until_phase` says WHEN it must close.
    /// - `Some("10c")` — a gap a future phase WILL fix (e.g. a Base64Flat payload that
    ///   only fires once §6 base64-decodes). Once [`CURRENT_PHASE`] reaches it, the
    ///   oracle FLIPS expectation: it must now trigger, or the build fails.
    /// - `None` — a permanent documented limit (e.g. an encoding §6 deliberately does
    ///   not handle). Never expected to close.
    ///
    /// Either way, a gap that fires *ahead* of its phase is a good regression to promote.
    ExpectedMiss { until_phase: Option<&'static str> },
}

/// The phase the corpus is currently validated at. `ExpectedMiss { until_phase }` rows
/// whose phase is `<=` this MUST be caught (the oracle enforces the flip). Bump this when
/// a phase lands, so its deferred gaps become required triggers.
pub const CURRENT_PHASE: &str = "10c";

/// Has `until_phase` been reached at `current`? Phases in the `10x` family order by their
/// string (`"10a" < "10b" < "10c"`), which is the only family `until_phase` uses.
pub fn phase_reached(until_phase: &str, current: &str) -> bool {
    current >= until_phase
}

/// One corpus case. The payload lives in [`Field`]; `desc` carries the reason.
#[derive(Debug, Clone, Copy)]
pub struct Case {
    /// Stable unique id, e.g. `sqli-union-query-01`.
    pub id: &'static str,
    /// Module the case targets (metrics bucket).
    pub module: Module,
    /// Injection point + payload.
    pub field: Field,
    /// Minimum paranoia level at which this case is meaningful: for a `Triggers`
    /// case, the `paranoia` of the rule it targets; for a `Clean` trap, the PL of
    /// the pattern that must NOT fire. The runner **skips** the case when
    /// `execution_pl < min_pl` so a `Triggers` miss is never an artefact of running
    /// below the rule's activation, and Pilastro 2 can group cases by PL without
    /// re-deriving the rule→PL mapping.
    pub min_pl: u8,
    /// Expected outcome.
    pub expect: Expect,
    /// Asserted **only when non-empty**, as "at least one of" (DECISIONE 4): used
    /// where the specific rule_id is the point (FP-narrowing regressions, declared
    /// overlaps, module boundaries). Otherwise diagnostic only.
    pub rules: &'static [&'static str],
    /// Human description / reason the expectation holds.
    pub desc: &'static str,
}

/// Result of checking a case against its expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseResult {
    Pass,
    Fail { reason: String },
    /// Not run because `execution_pl < case.min_pl` — counts as neither recall nor
    /// false positive.
    Skipped,
}

/// Compare a case's [`RunResult`] against its [`Expect`] (and `rules`, when set).
/// A [`RunResult::Skipped`] maps straight to [`CaseResult::Skipped`].
pub fn evaluate(case: &Case, result: &RunResult) -> CaseResult {
    let outcome = match result {
        RunResult::Skipped => return CaseResult::Skipped,
        RunResult::Ran(outcome) => outcome,
    };
    match case.expect {
        Expect::Triggers => {
            if !outcome.triggered {
                return CaseResult::Fail {
                    reason: format!("expected a trigger, none fired (score {})", outcome.score),
                };
            }
            if !case.rules.is_empty()
                && !case
                    .rules
                    .iter()
                    .any(|r| outcome.matched_rules.iter().any(|m| m == r))
            {
                return CaseResult::Fail {
                    reason: format!(
                        "expected at least one of {:?}, matched {:?}",
                        case.rules, outcome.matched_rules
                    ),
                };
            }
            CaseResult::Pass
        }
        Expect::Clean => {
            if outcome.triggered {
                CaseResult::Fail {
                    reason: format!(
                        "false positive: matched {:?} (score {})",
                        outcome.matched_rules, outcome.score
                    ),
                }
            } else {
                CaseResult::Pass
            }
        }
        // Documented gap: never gates recall here. The phase-flip is enforced by the
        // dedicated oracle test (`expected_miss_phase_deferrals_honored`).
        Expect::ExpectedMiss { .. } => CaseResult::Pass,
    }
}
