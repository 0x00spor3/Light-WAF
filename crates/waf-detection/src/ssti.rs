use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

// ── rules (Fase 10a) ────────────────────────────────────────────────────────────
//
// Server-Side Template Injection: a template-engine expression injected into a
// user-controlled value and evaluated server-side (RCE / data exfiltration). The
// discriminator vs benign text is the TEMPLATE DELIMITER carrying an evaluatable
// payload, not a bare `{{ }}` (which legit client templates / mustache content use):
//   - arithmetic inside a delimiter (`{{1337*1338}}`, `#{16*8787}`, `${7*7}`) — the
//     classic polyglot probe; a digit·operator·digit immediately inside the delimiter
//     is never benign user input;
//   - FreeMarker directives (`<#assign …>`, `?new()`, `freemarker.template…`) — engine
//     syntax that only a template injection produces.
// Unequivocal template syntax → Critical, block-alone (decision 3). Patterns target
// the normalizer OUTPUT (Fase 2): query/body values are double percent-decoded +
// NFKC-normalized; every token here is ASCII, NFKC-stable.
//
// Fase 10a covers the URL/Plain-encoded form; the Base64Flat duplicates are 10c-scope
// (need base64-decode in §6, invariant here).

pub static SSTI_RULES: &[Rule] = &[
    Rule {
        id: "ssti-template-arithmetic",
        // A template delimiter (`{{`, `#{`, `${`) immediately followed by an
        // arithmetic expression `<digits> <op> <digits>`. Matches `{{1337*1338}}`,
        // `#{16*8787}`, `${7*7}`; a benign `{{ user.name }}` or `${base}` has no
        // digit-operator-digit and is not flagged.
        pattern: r"(?:\{\{|[#$]\{)\s*\d+\s*[*+/x-]\s*\d+",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "ssti-freemarker-directive",
        // FreeMarker directive / built-in syntax: `<#assign|list|if|…>`, the
        // instantiation built-in `?new()`, or the FQN of the template utility classes.
        // Matches `<#assign ex = "freemarker.template.utility.Execute"?new()>`.
        pattern: r"(?i)<#(?:assign|list|if|include|macro|function|global|setting)\b|\?new\(\)|freemarker\.template",
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SstiModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl SstiModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for SstiModule {
    fn id(&self) -> &str {
        "ssti"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = SSTI_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("SSTI rule compilation failed — check patterns at startup"),
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
                    "ssti detection"
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
