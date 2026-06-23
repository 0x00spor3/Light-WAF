use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, Rule};

// ── rules ─────────────────────────────────────────────────────────────────────
//
// Scope (non-overlapping with RFI/LFI to avoid double-counting): SSRF detects
// the TARGET the server is being pushed to reach — cloud-metadata endpoints,
// loopback, private/obfuscated IPs, and SSRF-specific schemes (gopher/dict/…).
// The generic schemes `http(s)://`/`ftp://` stay with RFI; `file://`/`php://`
// stay with LFI. So `http://169.254.169.254/` legitimately scores from BOTH
// RFI (rfi-remote-url, weak) and SSRF (cloud-metadata, strong): different
// signals, not redundant.
//
// DECLARED intra-module overlap: 169.254.169.254 matches `ssrf-cloud-metadata`
// (Critical) AND `ssrf-private-ip` link-local (Notice, PL3) → additive 5+2 at
// PL3. Intentional defense-in-depth, kept explicit (see test).
//
// Known gaps (documented in ARCHITECTURE §8):
//   - decimal/hex/octal obfuscation below covers only 127.0.0.1, not the
//     metadata IP (169.254.169.254 decimal = 2852039166);
//   - IPv6 coverage is limited to [::1] and fd00:ec2::254 (no fc00::/7, fe80::).

pub static SSRF_RULES: &[Rule] = &[
    Rule {
        id: "ssrf-cloud-metadata",
        // Cloud instance-metadata endpoints (AWS/GCP/Azure/Alibaba).
        pattern: r"(?i)(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|fd00:ec2::254)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "ssrf-dangerous-scheme",
        // SSRF-specific URL schemes (NOT http/https/ftp/file — those are RFI/LFI).
        pattern: r"(?i)(?:gopher|dict|ldap|tftp|sftp|redis|jar|netdoc)://",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "ssrf-loopback",
        // Loopback hosts. The `127.1` short form is anchored to a host boundary
        // (start, `/` or `@`) so it does not match valid IPs ending in `.127.1`
        // such as 192.168.127.1.
        pattern: r"(?i)(?:\b(?:127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\])\b|(?:[/@]|\A)127\.1(?:[:/]|\z))",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "ssrf-ip-obfuscation",
        // Decimal / hex / octal encodings of 127.0.0.1.
        pattern: r"(?i)(?:0x7f[0-9a-f]{6}|\b2130706433\b|\b017[0-7]\.0\.0\.0?1)",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "ssrf-private-ip",
        // RFC1918 private ranges + link-local. Noisy (legit internal refs,
        // version-like strings), hence Notice/PL3.
        pattern: r"(?i)\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|169\.254\.\d{1,3}\.\d{1,3})\b",
        severity: Severity::Notice,
        paranoia: 3,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct SsrfModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl SsrfModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for SsrfModule {
    fn id(&self) -> &str {
        "ssrf"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = SSRF_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("SSRF rule compilation failed — check patterns at startup"),
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

        let matched = all_matches(rule_set, query.chain(cookies).chain(body).chain(derived));
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
                    "ssrf detection"
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
