// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

// ── rules (Fase 10b) ────────────────────────────────────────────────────────────
//
// Server-Side Includes injection: an SSI directive `<!--#exec|include|echo|…-->`
// injected into a user value and evaluated by the server (command execution via
// `#exec cmd`, file disclosure via `#include`, env leak via `#printenv`). gotestwaf
// ss-include. Before this rule the payloads only tripped `sqli-quote-comment`
// incidentally (the `"-->` tail) — a fragile, mis-attributed catch that a quote-less
// SSI payload would evade. The directive opener `<!--#<verb>` is unequivocal SSI
// syntax → Critical, block-alone (decision 3). Pattern targets the normalizer OUTPUT
// (Fase 2): ASCII, NFKC-stable.

pub static SSI_RULES: &[Rule] = &[
    Rule {
        id: "ssi-directive",
        // SSI directive opener: `<!--#` then an SSI command verb. Matches
        // `<!--#exec cmd="ls" -->`, `<!--#include virtual=…`, `<!--#printenv-->`.
        // A plain HTML comment `<!-- text -->` has no `#verb` and is not flagged.
        pattern: r"(?i)<!--#\s*(?:exec|include|echo|config|printenv|fsize|flastmod|set)\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SsiModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl SsiModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for SsiModule {
    fn id(&self) -> &str {
        "ssi"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = SSI_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("SSI rule compilation failed — check patterns at startup"),
        );
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let Some(rule_set) = &self.rule_set else {
            return Decision::Allow;
        };

        let query = ctx.normalized.query_params.iter().map(|(_, v)| v.as_str());
        let cookies = ctx.normalized.cookies.iter().map(|(_, v)| v.as_str());
        let body_vals = body_str_values(&ctx.normalized.body);
        let body = body_vals.iter().map(String::as_str);
        let derived = ctx.normalized.derived_decoded.iter().map(String::as_str);

        // URLPath coverage (10c REOPEN, pcap-confirmed): gotestwaf places payloads in the
        // URL PATH; this module must scan the resolved path too (mirrors rce/xss), else a
        // path-placed payload bypasses. The prefilter already scans the path (sound).
        let path = std::iter::once(ctx.normalized.path.as_str());
        // P1-B: also scan the allowlisted request headers (Referer / X-Forwarded-* / custom x-*).
        let headers = inspectable_header_values(ctx);
        let matched = all_matches(rule_set, path.chain(query).chain(cookies).chain(body).chain(derived).chain(headers));
        if matched.is_empty() {
            return Decision::Allow;
        }

        let items: Vec<ScoreItem> = matched
            .iter()
            .map(|&idx| {
                let rule = self.active_rules[idx];
                warn!(
                    request_id = %ctx.request_id,
                    rule_id = %rule.id,
                    severity = ?rule.severity,
                    "ssi detection"
                );
                ScoreItem {
                    rule_id: rule.id.to_string(),
                    severity: rule.severity,
                }
            })
            .collect();

        Decision::Scores(items)
    }
}
