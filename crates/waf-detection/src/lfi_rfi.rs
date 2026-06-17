use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, Rule};

// ── rules ─────────────────────────────────────────────────────────────────────
//
// Scope (deliberately non-overlapping with neighbouring modules to avoid
// double-counting in the cumulative score):
//   - Path Traversal owns filesystem path manipulation (`../`, /etc/passwd,
//     null-byte, UNC). This module does NOT re-detect those.
//   - SSRF (Module 4) owns the server fetching attacker URLs (metadata IPs,
//     localhost, gopher://, dict://). This module owns *code/script inclusion*.
// So LFI/RFI here = inclusion MECHANISMS: PHP/stream wrappers + remote inclusion
// of a script.
//
// Patterns target the normalizer's OUTPUT (Fase 2): query, body AND cookie values
// share the same canonicalization (percent-decode, double-encoding-aware, + NFKC),
// so an encoded wrapper in any of them is resolved before inspection. All tokens
// are ASCII (NFKC-stable). See ARCHITECTURE.md §6 for the shared decode pass.

pub static LFI_RFI_RULES: &[Rule] = &[
    Rule {
        id: "lfi-stream-wrapper",
        // PHP / stream wrappers used to read, execute or smuggle content.
        pattern: r"(?i)(?:php|phar|zip|glob|expect|file|data)://",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "lfi-filter-chain",
        // php://filter conversion chain for source disclosure (distinct token
        // from the wrapper itself, so both legitimately contribute).
        pattern: r"(?i)convert\.(?:base64-encode|base64-decode|quoted-printable-encode)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "lfi-data-base64",
        // data: URI carrying a base64 payload (code inclusion via data wrapper).
        pattern: r"(?i)data:[^,]*;base64,",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "rfi-remote-script",
        // Remote URL pointing at an executable script — classic RFI.
        pattern: r"(?i)(?:https?|ftp)://\S+\.(?:php|phtml|phar|asp|aspx|jsp)\b",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "rfi-remote-url",
        // Bare remote URL in a parameter. Very FP-prone (any redirect/link
        // param), so Notice/PL3 only and non-blocking on its own.
        pattern: r"(?i)(?:https?|ftp)://",
        severity: Severity::Notice,
        paranoia: 3,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct LfiRfiModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl LfiRfiModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for LfiRfiModule {
    fn id(&self) -> &str {
        "lfi_rfi"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = LFI_RFI_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("LFI/RFI rule compilation failed — check patterns at startup"),
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
                    "lfi/rfi detection"
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
