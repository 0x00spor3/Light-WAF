pub mod noop_logger;
pub use noop_logger::NoopLogger;

use std::panic::{catch_unwind, AssertUnwindSafe};

use tracing::{debug, error, info, warn};
use waf_core::{
    Config, Decision, FailMode, Phase, RequestContext, ScoreContribution, Severity, SeverityScores,
    WafMode, WafModule,
};

#[derive(Debug)]
pub enum PipelineVerdict {
    Allow,
    Block {
        rule_id: String,
        reason: String,
    },
    /// Direct rejection with an explicit HTTP status (e.g. 429 from rate
    /// limiting), carrying an optional `Retry-After` in seconds.
    Reject {
        rule_id: String,
        reason: String,
        status: u16,
        retry_after: Option<u64>,
    },
}

/// Canonical order in which phases are executed.
const PHASE_ORDER: &[Phase] = &[
    Phase::Connection,
    Phase::RequestLine,
    Phase::Headers,
    Phase::Body,
    Phase::Response,
];

/// Phases that run *after* normalization (Fase 2). The Connection phase runs
/// before normalization (see `run_connection`), so it is excluded here.
const INSPECTION_PHASES: &[Phase] = &[
    Phase::RequestLine,
    Phase::Headers,
    Phase::Body,
    Phase::Response,
];

pub struct Pipeline {
    modules: Vec<Box<dyn WafModule>>,
    block_threshold: u32,
    mode: WafMode,
    /// severity -> points policy; the pipeline is the only place that maps a
    /// `Decision::Scores` severity to a concrete weight.
    severity_scores: SeverityScores,
    /// What to do when a module panics (Fase 6 / Pillar 2).
    on_internal_error: FailMode,
}

impl Pipeline {
    /// Builds the pipeline and calls `init` on every module.
    pub fn new(config: &Config, mut modules: Vec<Box<dyn WafModule>>) -> Self {
        for m in &mut modules {
            m.init(config);
        }
        Self {
            modules,
            block_threshold: config.waf.block_threshold,
            mode: config.waf.mode,
            severity_scores: config.waf.severity_scores,
            on_internal_error: config.resilience.on_internal_error,
        }
    }

    /// Accumulate one contribution into the context: add points, record the
    /// breakdown for audit, and log it. Returns the running total. This is the
    /// single chokepoint for mutating `ctx.score`.
    fn accumulate(
        &self,
        ctx: &mut RequestContext,
        module: &str,
        rule_id: String,
        severity: Option<Severity>,
        points: u32,
    ) {
        ctx.score += points;
        info!(
            request_id = %ctx.request_id,
            module = module,
            rule_id = %rule_id,
            severity = ?severity,
            points = points,
            score = ctx.score,
            decision = "score",
            "scoring contribution"
        );
        ctx.score_contributions.push(ScoreContribution {
            module: module.to_string(),
            rule_id,
            severity,
            points,
        });
    }

    /// Runs all modules in phase order, accumulates score, and returns the verdict.
    ///
    /// Scoring model (CRS-inspired):
    /// - `Decision::Scores` contributes one weighted point per matched rule;
    /// - `Decision::Score` contributes explicit points (high-confidence rules);
    /// - the request blocks when `ctx.score >= block_threshold`;
    /// - `Decision::Block` is a direct short-circuit that blocks regardless of
    ///   the accumulated score (reserved for very-high-confidence rules).
    ///
    /// In blocking mode: the first Block/Reject, or score crossing the threshold,
    /// short-circuits the chain. In detection-only: all modules always run and
    /// the verdict is always Allow (threshold crossings are logged only).
    ///
    /// Runs every phase. The proxy instead uses `run_connection` (before
    /// normalization) + `run_inspection` (after) to short-circuit rate-limited
    /// traffic before parsing; `run` is kept for in-process/whole-pipeline use.
    pub fn run(&self, ctx: &mut RequestContext) -> PipelineVerdict {
        let verdict = self.run_phases(ctx, PHASE_ORDER);
        self.log_decision(ctx, &verdict);
        verdict
    }

    /// Runs only the `Connection` phase (e.g. rate limiting). Meant to be called
    /// **before** normalization so flood traffic is rejected without parsing.
    /// Logs a final decision only when it actually rejects/blocks.
    pub fn run_connection(&self, ctx: &mut RequestContext) -> PipelineVerdict {
        let verdict = self.run_phases(ctx, &[Phase::Connection]);
        if !matches!(verdict, PipelineVerdict::Allow) {
            self.log_decision(ctx, &verdict);
        }
        verdict
    }

    /// Runs the post-normalization phases (`RequestLine`..`Response`). The score
    /// accumulated by `run_connection` on the same `ctx` carries over.
    pub fn run_inspection(&self, ctx: &mut RequestContext) -> PipelineVerdict {
        let verdict = self.run_phases(ctx, INSPECTION_PHASES);
        self.log_decision(ctx, &verdict);
        verdict
    }

    /// Core executor over an arbitrary set of phases. Accumulates score and
    /// returns the verdict; does not emit the final decision log (callers do).
    fn run_phases(&self, ctx: &mut RequestContext, phases: &[Phase]) -> PipelineVerdict {
        let mut block_verdict: Option<PipelineVerdict> = None;

        'pipeline: for &phase in phases {
            for module in self.modules.iter().filter(|m| m.phase() == phase) {
                let module_id = module.id().to_string();

                // Panic isolation (Fase 6 / Pillar 2): a bug in a module (panic,
                // pathological regex) must not abort the worker or other clients.
                // `inspect` takes `&RequestContext` (read-only), so a panic cannot
                // leave `ctx` partially mutated → `AssertUnwindSafe` is sound.
                let decision = match catch_unwind(AssertUnwindSafe(|| module.inspect(ctx))) {
                    Ok(d) => d,
                    Err(_) => {
                        error!(
                            request_id = %ctx.request_id,
                            module = %module_id,
                            policy = ?self.on_internal_error,
                            decision = "internal_error",
                            "module panicked; applying on_internal_error policy"
                        );
                        match self.on_internal_error {
                            // Skip the faulty module; the request proceeds.
                            FailMode::FailOpen => Decision::Allow,
                            // Surface a synthetic block (enforced in blocking mode,
                            // logged-only in detection-only — mode semantics intact).
                            FailMode::FailClosed => Decision::Block {
                                rule_id: "internal-error".to_string(),
                                reason: format!("module {module_id} panicked"),
                            },
                        }
                    }
                };

                match decision {
                    Decision::Allow => {
                        debug!(
                            request_id = %ctx.request_id,
                            module = %module_id,
                            phase = ?phase,
                            "allow"
                        );
                    }

                    Decision::Monitor { rule_id } => {
                        info!(
                            request_id = %ctx.request_id,
                            module = %module_id,
                            rule_id = %rule_id,
                            score = ctx.score,
                            decision = "monitor",
                            "module triggered"
                        );
                    }

                    Decision::Score { rule_id, points } => {
                        self.accumulate(ctx, &module_id, rule_id.clone(), None, points);
                        if let Some(verdict) = self.threshold_check(ctx, &rule_id) {
                            block_verdict = Some(verdict);
                            break 'pipeline;
                        }
                    }

                    Decision::Scores(items) => {
                        let mut last_rule_id = String::new();
                        for item in items {
                            let points = self.severity_scores.points_for(item.severity);
                            self.accumulate(
                                ctx,
                                &module_id,
                                item.rule_id.clone(),
                                Some(item.severity),
                                points,
                            );
                            last_rule_id = item.rule_id;
                        }
                        if let Some(verdict) = self.threshold_check(ctx, &last_rule_id) {
                            block_verdict = Some(verdict);
                            break 'pipeline;
                        }
                    }

                    Decision::Block { rule_id, reason } => {
                        warn!(
                            request_id = %ctx.request_id,
                            module = %module_id,
                            rule_id = %rule_id,
                            reason = %reason,
                            score = ctx.score,
                            decision = "block",
                            "module triggered"
                        );
                        if self.mode == WafMode::Blocking {
                            block_verdict = Some(PipelineVerdict::Block { rule_id, reason });
                            break 'pipeline;
                        }
                    }

                    Decision::Reject { rule_id, reason, status, retry_after } => {
                        warn!(
                            request_id = %ctx.request_id,
                            module = %module_id,
                            rule_id = %rule_id,
                            reason = %reason,
                            status = status,
                            decision = "reject",
                            "module triggered"
                        );
                        if self.mode == WafMode::Blocking {
                            block_verdict = Some(PipelineVerdict::Reject {
                                rule_id,
                                reason,
                                status,
                                retry_after,
                            });
                            break 'pipeline;
                        }
                    }
                }
            }
        }

        match self.mode {
            WafMode::Blocking => block_verdict.unwrap_or(PipelineVerdict::Allow),
            WafMode::DetectionOnly => PipelineVerdict::Allow,
        }
    }

    /// Returns a Block verdict if the score reached the threshold *and* we are in
    /// blocking mode; otherwise `None`. Detection-only logs the crossing only.
    fn threshold_check(&self, ctx: &RequestContext, rule_id: &str) -> Option<PipelineVerdict> {
        if ctx.score < self.block_threshold {
            return None;
        }
        warn!(
            request_id = %ctx.request_id,
            score = ctx.score,
            threshold = self.block_threshold,
            mode = ?self.mode,
            "anomaly score threshold reached"
        );
        if self.mode == WafMode::Blocking {
            Some(PipelineVerdict::Block {
                rule_id: rule_id.to_string(),
                reason: format!(
                    "anomaly score {} >= threshold {}",
                    ctx.score, self.block_threshold
                ),
            })
        } else {
            None
        }
    }

    /// Final structured decision log: total score, threshold, mode and the full
    /// per-rule contribution breakdown.
    fn log_decision(&self, ctx: &RequestContext, verdict: &PipelineVerdict) {
        let decision = match verdict {
            PipelineVerdict::Block { .. } => "block",
            PipelineVerdict::Reject { .. } => "reject",
            PipelineVerdict::Allow => "allow",
        };
        info!(
            request_id = %ctx.request_id,
            decision = decision,
            score = ctx.score,
            threshold = self.block_threshold,
            mode = ?self.mode,
            contributions = ?ctx.score_contributions,
            "pipeline decision"
        );
    }
}
