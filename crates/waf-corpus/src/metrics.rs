//! Aggregation of corpus runs into objective metrics (Fase 7 / Pilastro 1).
//!
//! Two separate books, by design (they answer different questions):
//! - **recall / FP-rate** are attributed to `case.module` only. A malicious case
//!   counts as detected when its [`crate::evaluate`] passes (verdict coherent with
//!   `Triggers` AND, when `rules` is set, at least one expected rule fired). Extra
//!   rule_ids that fired by declared overlap do NOT inflate the target module.
//! - **score-distribution** reports the **real cumulative `ctx.score`** (every
//!   match, overlaps included) — exactly what the pipeline would produce in
//!   production and what Pilastro 2 needs to tune `block_threshold`.
//!
//! Overlaps are kept visible in their own list; `ExpectedMiss` gaps are counted
//! apart (neither recall nor FP).

use waf_core::SeverityScores;

use crate::{cases, evaluate, run_case, run_case_with, CaseResult, Expect, Module, RunResult, Verdict};

/// Per-module recall / false-positive tally (attribution by `case.module`).
#[derive(Debug, Clone)]
pub struct ModuleMetrics {
    pub module: Module,
    /// Malicious (`Triggers`) cases that actually ran (not skipped by min_pl).
    pub malicious_total: usize,
    /// ...of which correctly detected (evaluate == Pass).
    pub malicious_detected: usize,
    /// Benign (`Clean`) cases that ran.
    pub benign_total: usize,
    /// ...of which produced a false positive.
    pub benign_fp: usize,
    /// Cases skipped because `execution_pl < min_pl`.
    pub skipped: usize,
    /// ids of malicious cases that failed to trigger / matched no expected rule.
    pub trigger_failures: Vec<String>,
    /// (id, matched_rules) of benign cases that wrongly triggered.
    pub false_positives: Vec<(String, Vec<String>)>,
}

impl ModuleMetrics {
    fn empty(module: Module) -> Self {
        Self {
            module,
            malicious_total: 0,
            malicious_detected: 0,
            benign_total: 0,
            benign_fp: 0,
            skipped: 0,
            trigger_failures: Vec::new(),
            false_positives: Vec::new(),
        }
    }

    /// Recall over the malicious cases that ran. 1.0 when there are none.
    pub fn recall(&self) -> f64 {
        if self.malicious_total == 0 {
            1.0
        } else {
            self.malicious_detected as f64 / self.malicious_total as f64
        }
    }

    /// False-positive rate over the benign cases that ran. 0.0 when there are none.
    pub fn fp_rate(&self) -> f64 {
        if self.benign_total == 0 {
            0.0
        } else {
            self.benign_fp as f64 / self.benign_total as f64
        }
    }
}

/// One malicious case's real cumulative score (overlaps included) — Pilastro 2 input.
#[derive(Debug, Clone)]
pub struct ScorePoint {
    pub case_id: String,
    pub module: Module,
    pub score: u32,
    pub matched_rules: Vec<String>,
}

/// A case where rules beyond the expected set fired (declared §8 overlap).
#[derive(Debug, Clone)]
pub struct Overlap {
    pub case_id: String,
    pub module: Module,
    pub expected: Vec<String>,
    pub extra: Vec<String>,
}

/// Status of a documented gap (`ExpectedMiss`): true when still uncaught.
#[derive(Debug, Clone)]
pub struct ExpectedMissStatus {
    pub case_id: String,
    pub still_missed: bool,
    /// `Some(phase)` = must close by that phase; `None` = permanent documented limit.
    pub until_phase: Option<&'static str>,
}

/// A full corpus run at a given execution paranoia level.
#[derive(Debug, Clone)]
pub struct Report {
    pub execution_pl: u8,
    pub modules: Vec<ModuleMetrics>,
    pub score_points: Vec<ScorePoint>,
    pub overlaps: Vec<Overlap>,
    pub expected_miss: Vec<ExpectedMissStatus>,
}

impl Report {
    /// Run the whole corpus at `execution_pl` and aggregate.
    pub fn run(execution_pl: u8) -> Self {
        let mut modules = Vec::new();
        let mut score_points = Vec::new();
        let mut overlaps = Vec::new();
        let mut expected_miss = Vec::new();

        for table in cases::MODULE_TABLES {
            // Each table is one module by construction.
            let module = table[0].module;
            let mut m = ModuleMetrics::empty(module);

            for case in *table {
                let result = run_case(case, execution_pl);
                let outcome = match &result {
                    RunResult::Skipped => {
                        m.skipped += 1;
                        continue;
                    }
                    RunResult::Ran(outcome) => outcome,
                };

                // Overlap bookkeeping: rule_ids that fired beyond the expected set.
                if !case.rules.is_empty() {
                    let extra: Vec<String> = outcome
                        .matched_rules
                        .iter()
                        .filter(|r| !case.rules.contains(&r.as_str()))
                        .cloned()
                        .collect();
                    if !extra.is_empty() {
                        overlaps.push(Overlap {
                            case_id: case.id.to_string(),
                            module,
                            expected: case.rules.iter().map(|r| r.to_string()).collect(),
                            extra,
                        });
                    }
                }

                match case.expect {
                    Expect::Triggers => {
                        m.malicious_total += 1;
                        score_points.push(ScorePoint {
                            case_id: case.id.to_string(),
                            module,
                            score: outcome.score,
                            matched_rules: outcome.matched_rules.clone(),
                        });
                        match evaluate(case, &result) {
                            CaseResult::Pass => m.malicious_detected += 1,
                            _ => m.trigger_failures.push(case.id.to_string()),
                        }
                    }
                    Expect::Clean => {
                        m.benign_total += 1;
                        if outcome.triggered {
                            m.false_positives
                                .push((case.id.to_string(), outcome.matched_rules.clone()));
                        }
                    }
                    Expect::ExpectedMiss { until_phase } => {
                        expected_miss.push(ExpectedMissStatus {
                            case_id: case.id.to_string(),
                            still_missed: !outcome.triggered,
                            until_phase,
                        });
                    }
                }
            }

            m.benign_fp = m.false_positives.len();
            modules.push(m);
        }

        Report { execution_pl, modules, score_points, overlaps, expected_miss }
    }

    /// Aggregate detected/total over malicious and fp/total over benign.
    pub fn aggregate(&self) -> Aggregate {
        let mut a = Aggregate::default();
        for m in &self.modules {
            a.malicious_total += m.malicious_total;
            a.malicious_detected += m.malicious_detected;
            a.benign_total += m.benign_total;
            a.benign_fp += m.benign_fp;
            a.skipped += m.skipped;
        }
        a
    }

    /// How many `ExpectedMiss` cases are still uncaught vs total.
    pub fn expected_miss_still_missed(&self) -> (usize, usize) {
        let still = self.expected_miss.iter().filter(|e| e.still_missed).count();
        (still, self.expected_miss.len())
    }
}

/// Corpus-wide totals.
#[derive(Debug, Clone, Default)]
pub struct Aggregate {
    pub malicious_total: usize,
    pub malicious_detected: usize,
    pub benign_total: usize,
    pub benign_fp: usize,
    pub skipped: usize,
}

impl Aggregate {
    pub fn recall(&self) -> f64 {
        if self.malicious_total == 0 {
            1.0
        } else {
            self.malicious_detected as f64 / self.malicious_total as f64
        }
    }

    pub fn fp_rate(&self) -> f64 {
        if self.benign_total == 0 {
            0.0
        } else {
            self.benign_fp as f64 / self.benign_total as f64
        }
    }
}

// ── Pilastro 2: blocking analysis (severity_scores × block_threshold) ──────────
//
// P1 measured DETECTION recall (a rule matched) with threshold = MAX. P2 measures
// BLOCKING recall (score >= threshold) for a candidate scoring config. The run
// keeps threshold = MAX (full uncut score) and blocking is decided offline, so the
// per-match contributions are never truncated. Two books are kept:
//   - total blocking  = ctx.score (overlaps included) >= threshold;
//   - own-merit blocking = sum of points from the case's OWN module >= threshold.
// The gap between them quantifies the §8 overlap-masking; `masked` names the cases.

/// A candidate tuning configuration to evaluate against the corpus.
#[derive(Debug, Clone, Copy)]
pub struct ScoringConfig {
    pub label: &'static str,
    pub severity: SeverityScores,
    pub threshold: u32,
}

/// Per-module blocking tally under a candidate config (attribution by `case.module`).
#[derive(Debug, Clone)]
pub struct BlockingModuleMetrics {
    pub module: Module,
    /// Malicious cases that ran (not skipped by min_pl).
    pub malicious_total: usize,
    /// ...that block on the total score (overlaps included) or via smuggling Reject.
    pub blocked_total: usize,
    /// ...that block on the own-module score alone (or via smuggling Reject).
    pub blocked_own: usize,
    /// Benign cases that ran.
    pub benign_total: usize,
    /// ...that wrongly block (expected 0; benign all score 0).
    pub benign_blocked: usize,
}

/// A malicious case that blocks only thanks to cross-module overlap (own-module
/// score is below threshold) — the §8 overlap-masking made explicit.
#[derive(Debug, Clone)]
pub struct MaskedCase {
    pub case_id: String,
    pub module: Module,
    pub own_score: u32,
    pub total_score: u32,
    /// rule_ids contributed by other modules that pushed it over the threshold.
    pub overlap_rules: Vec<String>,
}

/// A full blocking run of the corpus at one PL under one candidate config.
#[derive(Debug, Clone)]
pub struct BlockingReport {
    pub label: &'static str,
    pub execution_pl: u8,
    pub threshold: u32,
    pub modules: Vec<BlockingModuleMetrics>,
    pub masked: Vec<MaskedCase>,
    /// Malicious case ids that block on total score (for cross-config diffing).
    pub blocking_ids: Vec<String>,
    /// Benign case ids that wrongly block (expected empty).
    pub benign_blocking_ids: Vec<String>,
    /// Smallest own-merit score among score-based own-merit blockers (Reject cases
    /// excluded — they block via 400, not score). `None` if there are none.
    pub min_own_block_score: Option<u32>,
    /// Smallest total score among score-based total blockers (Reject excluded).
    pub min_total_block_score: Option<u32>,
    /// Largest benign score (0 on the current corpus).
    pub max_benign_score: u32,
}

impl BlockingReport {
    /// Run the whole corpus at `execution_pl` under `cfg`.
    pub fn run(cfg: ScoringConfig, execution_pl: u8) -> Self {
        let mut modules = Vec::new();
        let mut masked = Vec::new();
        let mut blocking_ids = Vec::new();
        let mut benign_blocking_ids = Vec::new();
        let mut min_own: Option<u32> = None;
        let mut min_total: Option<u32> = None;
        let mut max_benign = 0u32;

        for table in cases::MODULE_TABLES {
            let module = table[0].module;
            let mut bm = BlockingModuleMetrics {
                module,
                malicious_total: 0,
                blocked_total: 0,
                blocked_own: 0,
                benign_total: 0,
                benign_blocked: 0,
            };

            for case in *table {
                let result = run_case_with(case, execution_pl, cfg.severity);
                let outcome = match &result {
                    RunResult::Skipped => continue,
                    RunResult::Ran(o) => o,
                };

                let total = outcome.score;
                let own: u32 = outcome
                    .contributions
                    .iter()
                    .filter(|c| c.module == module.name())
                    .map(|c| c.points)
                    .sum();
                // Request smuggling blocks via Reject 400 regardless of score.
                let reject = matches!(outcome.verdict, Verdict::Reject);

                match case.expect {
                    Expect::Triggers => {
                        bm.malicious_total += 1;
                        let blk_total = reject || total >= cfg.threshold;
                        let blk_own = reject || own >= cfg.threshold;
                        if blk_total {
                            bm.blocked_total += 1;
                            blocking_ids.push(case.id.to_string());
                            if !reject {
                                min_total = Some(min_total.map_or(total, |m| m.min(total)));
                            }
                        }
                        if blk_own {
                            bm.blocked_own += 1;
                            if !reject {
                                min_own = Some(min_own.map_or(own, |m| m.min(own)));
                            }
                        }
                        if blk_total && !blk_own {
                            masked.push(MaskedCase {
                                case_id: case.id.to_string(),
                                module,
                                own_score: own,
                                total_score: total,
                                overlap_rules: outcome
                                    .contributions
                                    .iter()
                                    .filter(|c| c.module != module.name())
                                    .map(|c| c.rule_id.clone())
                                    .collect(),
                            });
                        }
                    }
                    Expect::Clean => {
                        bm.benign_total += 1;
                        max_benign = max_benign.max(total);
                        if total >= cfg.threshold {
                            bm.benign_blocked += 1;
                            benign_blocking_ids.push(case.id.to_string());
                        }
                    }
                    Expect::ExpectedMiss { .. } => {}
                }
            }

            modules.push(bm);
        }

        BlockingReport {
            label: cfg.label,
            execution_pl,
            threshold: cfg.threshold,
            modules,
            masked,
            blocking_ids,
            benign_blocking_ids,
            min_own_block_score: min_own,
            min_total_block_score: min_total,
            max_benign_score: max_benign,
        }
    }

    pub fn malicious_total(&self) -> usize {
        self.modules.iter().map(|m| m.malicious_total).sum()
    }
    pub fn blocked_total(&self) -> usize {
        self.modules.iter().map(|m| m.blocked_total).sum()
    }
    pub fn blocked_own(&self) -> usize {
        self.modules.iter().map(|m| m.blocked_own).sum()
    }
    pub fn benign_total(&self) -> usize {
        self.modules.iter().map(|m| m.benign_total).sum()
    }
    pub fn benign_blocked(&self) -> usize {
        self.modules.iter().map(|m| m.benign_blocked).sum()
    }

    /// Blocking recall on the total score (overlaps included).
    pub fn blocking_recall_total(&self) -> f64 {
        ratio(self.blocked_total(), self.malicious_total())
    }
    /// Blocking recall on own-module merit (overlaps excluded).
    pub fn blocking_recall_own(&self) -> f64 {
        ratio(self.blocked_own(), self.malicious_total())
    }
    /// Robustness of own-merit blocking: `min own-merit blocking score − threshold`.
    pub fn block_margin_own(&self) -> Option<i64> {
        self.min_own_block_score
            .map(|s| s as i64 - self.threshold as i64)
    }
    /// Headroom against benign false-blocks: `threshold − max benign score`.
    pub fn benign_margin(&self) -> i64 {
        self.threshold as i64 - self.max_benign_score as i64
    }
}

fn ratio(n: usize, d: usize) -> f64 {
    if d == 0 {
        1.0
    } else {
        n as f64 / d as f64
    }
}
