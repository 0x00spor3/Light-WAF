use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

// ── rules (Fase 10a) ────────────────────────────────────────────────────────────
//
// Mail (SMTP/IMAP) command injection: a CR/LF followed by a mail-protocol verb smuggled
// into a user value, to inject extra SMTP/IMAP commands. Scope (§8): the mail-COMMAND
// vocabulary after CR/LF — distinct from `header_injection`, which owns HTTP response-
// splitting (Set-Cookie / status). The two OVERLAP on the CR/LF mechanism (a mail payload
// also trips header_injection's CR/LF-in-query rule); that is declared defense-in-depth,
// attribution stays `case.module = Mail`.
//
// FP discipline: the rule REQUIRES the CR/LF — a value that merely contains "QUIT" or
// "MAIL FROM" without a newline is not flagged (benign guards). Only unequivocal verbs are
// listed (no bare "DATA"/"LOGIN" which are common words). Base64Flat duplicates are
// 10c-scope (`ExpectedMiss{until_phase:"10c"}`).

pub static MAIL_RULES: &[Rule] = &[
    Rule {
        id: "mail-command-injection",
        // CR/LF, optional IMAP tag (`V100 `), then an SMTP/IMAP verb.
        pattern: r"(?i)[\r\n]\s*(?:\w+\s+)?(?:CAPABILITY|FETCH|QUIT|RCPT\s+TO|MAIL\s+FROM|STARTTLS|EHLO|HELO)\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct MailModule {
    rule_set: Option<RegexSet>,
    active_rules: Vec<&'static Rule>,
}

impl MailModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for MailModule {
    fn id(&self) -> &str {
        "mail"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = MAIL_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("Mail rule compilation failed — check patterns at startup"),
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
                    "mail detection"
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
