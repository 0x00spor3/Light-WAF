use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, Rule};

// ── rules ─────────────────────────────────────────────────────────────────────

pub static SQLI_RULES: &[Rule] = &[
    Rule {
        id: "sqli-union-select",
        pattern: r"(?i)\bunion\s+(?:all\s+)?select\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-tautology-or",
        // OR followed by a comparison: OR 1=1, OR 'a'='a', OR x=x
        pattern: r#"(?i)\bor\s+[\w'"` ]+\s*=\s*[\w'"` ]"#,
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-stacked-query",
        // Semicolon followed by a DML/DDL keyword — stacked query injection.
        pattern: r"(?i);\s*(?:select|insert|update|delete|drop|truncate|exec(?:ute)?|call)\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-time-based",
        pattern: r"(?i)\b(?:sleep|pg_sleep|waitfor\s+delay|benchmark)\s*\(",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-tautology-and",
        pattern: r#"(?i)\band\s+[\w'"` ]+\s*=\s*[\w'"` ]"#,
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "sqli-quote-comment",
        // Single/double quote immediately followed by -- or # comment markers.
        pattern: r#"(?i)['"`]\s*(?:--|#)"#,
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "sqli-cast-convert",
        // CAST(x AS type) or CONVERT(x, type) — common in data exfiltration.
        pattern: r"(?i)\b(?:cast|convert)\s*\(",
        severity: Severity::Notice,
        paranoia: 3,
    },
    Rule {
        id: "sqli-hex-literal",
        // Long hex literals used to encode strings (≥6 hex digits to avoid
        // matching short colour codes like #fff or 0x1A).
        pattern: r"(?i)\b0x[0-9a-f]{6,}\b",
        severity: Severity::Notice,
        paranoia: 3,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SqliModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl SqliModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for SqliModule {
    fn id(&self) -> &str {
        "sqli"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = SQLI_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("SQLi rule compilation failed — check patterns at startup"),
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

        let matched = all_matches(rule_set, query.chain(cookies).chain(body));
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
                    "sqli detection"
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
