use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, Rule};

// ── rules ─────────────────────────────────────────────────────────────────────

pub static XSS_RULES: &[Rule] = &[
    Rule {
        id: "xss-script-tag",
        // <script followed by whitespace, > or /, covering <script>, <script >, <script/>.
        pattern: r"(?i)<script[\s>/]",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xss-javascript-proto",
        pattern: r"(?i)javascript\s*:",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xss-event-handler",
        // Inline event handlers: onerror=, onclick=, onload=, onmouseover=, etc.
        // Requires '=' immediately after the handler name to avoid matching English
        // words like "online" or "only" that don't precede an assignment.
        pattern: r"(?i)\bon\w+\s*=",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xss-dangerous-tag",
        // Tags that are not used for normal content but are common XSS vectors.
        pattern: r"(?i)<(?:iframe|object|embed|applet|link|meta|base)[\s>/]",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "xss-eval",
        pattern: r"(?i)\beval\s*\(",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "xss-document-cookie",
        pattern: r"(?i)document\s*\.\s*cookie",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "xss-vbscript-proto",
        pattern: r"(?i)vbscript\s*:",
        severity: Severity::Notice,
        paranoia: 3,
    },
    Rule {
        id: "xss-data-html-uri",
        // data:text/html URIs used to execute scripts via src or href attributes.
        pattern: r"(?i)data\s*:\s*text/html",
        severity: Severity::Notice,
        paranoia: 3,
    },
    Rule {
        id: "xss-innerhtml",
        pattern: r"(?i)\.innerHTML\s*=",
        severity: Severity::Notice,
        paranoia: 3,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct XssModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl XssModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for XssModule {
    fn id(&self) -> &str {
        "xss"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = XSS_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("XSS rule compilation failed — check patterns at startup"),
        );
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let Some(rule_set) = &self.rule_set else {
            return Decision::Allow;
        };

        // XSS also inspects the normalized path (in-URL tag injection).
        let path = std::iter::once(ctx.normalized.path.as_str());
        let query = ctx.normalized.query_params.iter().map(|(_, v)| v.as_str());
        let cookies = ctx.normalized.cookies.iter().map(|(_, v)| v.as_str());
        let body_vals = body_str_values(&ctx.normalized.body);
        let body = body_vals.iter().map(String::as_str);

        let matched = all_matches(rule_set, path.chain(query).chain(cookies).chain(body));
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
                    "xss detection"
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
