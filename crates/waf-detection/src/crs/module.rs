// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! [`CrsModule`] — a [`WafModule`] backed by imported CRS/ModSecurity rules.
//!
//! ## Performance shape (paletto #2)
//! The module is `structural()` so it runs on EVERY request — the content fast-path
//! (`ContentPrefilter`) only knows the native patterns and cannot prove a CRS rule inert.
//! To keep that affordable, single-link positive `@rx` rules (the bulk of CRS) are grouped
//! into **fast buckets** keyed by `(variables, transform-pipeline)`: each bucket extracts +
//! transforms its target values ONCE and runs a single [`RegexSet`] over them, instead of
//! N regexes in a loop. Chains, negations and non-`@rx` operators fall to a per-rule slow
//! path. So cost scales with the number of distinct `(vars, t:)` buckets, not rule count.

use std::collections::BTreeMap;

use regex::{Regex, RegexSet};
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use super::ast::{CrsRule, MatchUnit, ParsedRuleset, SkippedRule, Transform, Variable};
use super::operator::{compile, rx_pattern, Matcher};
use super::parse::parse;
use super::{target, transform};

/// One compiled match unit (head or chain child).
struct Link {
    vars: Vec<Variable>,
    transforms: Vec<Transform>,
    matcher: Matcher,
    negated: bool,
}

/// A slow-path rule (chain / negated / non-`@rx`): all links must match.
struct Compiled {
    id: u64,
    severity: Severity,
    links: Vec<Link>,
}

/// A fast bucket of single-link positive `@rx` rules sharing the same `(vars, t:)`.
struct FastBucket {
    vars: Vec<Variable>,
    transforms: Vec<Transform>,
    set: RegexSet,
    /// Aligned, index-for-index, with the patterns in `set`.
    ids: Vec<u64>,
    severities: Vec<Severity>,
}

/// Accumulator while grouping fast rules before the per-bucket [`RegexSet`] is built.
struct BucketAcc {
    vars: Vec<Variable>,
    transforms: Vec<Transform>,
    patterns: Vec<String>,
    ids: Vec<u64>,
    severities: Vec<Severity>,
}

/// A `WafModule` evaluating imported CRS/ModSecurity rules. Build with [`CrsModule::from_str`]
/// (one source) — the proxy loader concatenates the configured files in include order and
/// resolves the boot report.
pub struct CrsModule {
    fast: Vec<FastBucket>,
    slow: Vec<Compiled>,
    skipped: Vec<SkippedRule>,
    loaded: usize,
}

impl CrsModule {
    /// Parse + compile one `seclang` source (e.g. the configured files concatenated in
    /// include order).
    pub fn from_source(source: &str) -> Self {
        Self::from_parsed(parse(source))
    }

    /// Compile an already-parsed ruleset (rules that fail to compile join `skipped`).
    pub fn from_parsed(parsed: ParsedRuleset) -> Self {
        let mut skipped = parsed.skipped;
        let mut fast_map: BTreeMap<String, BucketAcc> = BTreeMap::new();
        let mut slow: Vec<Compiled> = Vec::new();
        let mut loaded = 0usize;

        for rule in parsed.rules {
            if let Some(pattern) = fast_pattern(&rule) {
                // Validate the regex individually so a bad one is skipped by id (a
                // wholesale RegexSet failure would not tell us which pattern broke).
                if let Err(e) = Regex::new(pattern) {
                    skipped.push(SkippedRule {
                        id: Some(rule.id),
                        line_no: rule.line_no,
                        reason: format!("invalid @rx regex: {e}"),
                    });
                    continue;
                }
                let key = format!("{:?}|{:?}", rule.head.variables, rule.head.transforms);
                let acc = fast_map.entry(key).or_insert_with(|| BucketAcc {
                    vars: rule.head.variables.clone(),
                    transforms: rule.head.transforms.clone(),
                    patterns: Vec::new(),
                    ids: Vec::new(),
                    severities: Vec::new(),
                });
                acc.patterns.push(pattern.to_string());
                acc.ids.push(rule.id);
                acc.severities.push(rule.severity);
                loaded += 1;
            } else {
                match compile_rule(&rule) {
                    Ok(c) => {
                        slow.push(c);
                        loaded += 1;
                    }
                    Err(reason) => skipped.push(SkippedRule {
                        id: Some(rule.id),
                        line_no: rule.line_no,
                        reason,
                    }),
                }
            }
        }

        // Build one RegexSet per bucket. A very large bucket can exceed the compiled-size
        // limit; rather than panic (a real CRS file must not crash the load) we degrade that
        // bucket's rules to the per-rule slow path (each pattern was already validated).
        let mut fast = Vec::with_capacity(fast_map.len());
        for acc in fast_map.into_values() {
            match RegexSet::new(&acc.patterns) {
                Ok(set) => fast.push(FastBucket {
                    vars: acc.vars,
                    transforms: acc.transforms,
                    set,
                    ids: acc.ids,
                    severities: acc.severities,
                }),
                Err(_) => {
                    for (i, pattern) in acc.patterns.iter().enumerate() {
                        if let Ok(re) = Regex::new(pattern) {
                            slow.push(Compiled {
                                id: acc.ids[i],
                                severity: acc.severities[i],
                                links: vec![Link {
                                    vars: acc.vars.clone(),
                                    transforms: acc.transforms.clone(),
                                    matcher: Matcher::Rx(re),
                                    negated: false,
                                }],
                            });
                        }
                    }
                }
            }
        }

        Self { fast, slow, skipped, loaded }
    }

    /// Number of rules successfully loaded (fast + slow).
    pub fn loaded_count(&self) -> usize {
        self.loaded
    }

    /// Rules that could not be loaded into the v1 subset (with reasons).
    pub fn skipped(&self) -> &[SkippedRule] {
        &self.skipped
    }

    /// One-line boot summary; the proxy logs this so the coverage gap is explicit (D3=A).
    pub fn report(&self) -> String {
        format!("CRS import: {} rules loaded, {} skipped", self.loaded, self.skipped.len())
    }

    /// Collect + transform the values for one `(vars, transforms)` pair (paletto #1: from raw).
    fn values_for(vars: &[Variable], transforms: &[Transform], ctx: &RequestContext) -> Vec<String> {
        target::collect_values(vars, ctx)
            .into_iter()
            .map(|v| transform::apply(&v, transforms))
            .collect()
    }
}

/// The `@rx` pattern of a fast-eligible rule (single link, positive, `@rx`), else `None`.
fn fast_pattern(rule: &CrsRule) -> Option<&str> {
    if rule.chain.is_empty() && !rule.head.negated {
        rx_pattern(&rule.head.operator)
    } else {
        None
    }
}

fn compile_rule(rule: &CrsRule) -> Result<Compiled, String> {
    let mut links = Vec::with_capacity(1 + rule.chain.len());
    links.push(compile_link(&rule.head)?);
    for child in &rule.chain {
        links.push(compile_link(child)?);
    }
    Ok(Compiled { id: rule.id, severity: rule.severity, links })
}

fn compile_link(u: &MatchUnit) -> Result<Link, String> {
    Ok(Link {
        vars: u.variables.clone(),
        transforms: u.transforms.clone(),
        matcher: compile(&u.operator)?,
        negated: u.negated,
    })
}

fn eval_compiled(c: &Compiled, ctx: &RequestContext) -> bool {
    // Every link (head + chain children) must match for the rule to fire.
    for link in &c.links {
        let values = CrsModule::values_for(&link.vars, &link.transforms, ctx);
        let any = values.iter().any(|v| link.matcher.matches(v));
        // Negated operator (v1 approximation): the link matches when the operator does NOT
        // match any value (the common `!@rx ^$` "not empty" intent). Documented limit.
        let link_matches = if link.negated { !any } else { any };
        if !link_matches {
            return false;
        }
    }
    true
}

fn push_item(items: &mut Vec<ScoreItem>, ctx: &RequestContext, id: u64, severity: Severity) {
    let rule_id = format!("crs-{id}");
    warn!(request_id = %ctx.request_id, rule_id = %rule_id, severity = ?severity, "crs detection");
    items.push(ScoreItem { rule_id, severity });
}

impl WafModule for CrsModule {
    fn id(&self) -> &str {
        "crs"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, _cfg: &Config) {
        // Rules are compiled at construction (`from_str`/`from_parsed`), before serving.
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let mut items: Vec<ScoreItem> = Vec::new();

        // Fast buckets: one value-extraction + one RegexSet pass per bucket.
        for b in &self.fast {
            let values = Self::values_for(&b.vars, &b.transforms, ctx);
            if values.is_empty() {
                continue;
            }
            let mut hit = vec![false; b.ids.len()];
            for v in &values {
                for idx in b.set.matches(v).into_iter() {
                    hit[idx] = true;
                }
            }
            for (i, &h) in hit.iter().enumerate() {
                if h {
                    push_item(&mut items, ctx, b.ids[i], b.severities[i]);
                }
            }
        }

        // Slow path: chains / negations / non-@rx operators.
        for c in &self.slow {
            if eval_compiled(c, ctx) {
                push_item(&mut items, ctx, c.id, c.severity);
            }
        }

        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Scores(items)
        }
    }

    /// CRS rules carry external patterns the native `ContentPrefilter` does not know about,
    /// so the fast-path cannot prove them inert → this module must run on every request.
    fn structural(&self) -> bool {
        true
    }
}
