// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

// ── rules (Fase 10a) ────────────────────────────────────────────────────────────
//
// LDAP injection = LDAP *search-filter* syntax injected into a user-controlled value.
// Scope (§8): boolean filter combinators and extensible-match — distinct from SQL/NoSQL.
// CRS-derived. The discriminator vs a LEGITIMATE single filter `(cn=John Doe)` is the
// boolean COMBINATOR `(&(` / `(|(`: a normal filter has none, an injected one builds a
// compound filter (auth-bypass, enumeration). A lone `*` or `=` is NOT enough to flag —
// see the benign guards in the corpus. Unequivocal LDAP filter syntax → Critical,
// block-alone (decision 3); pattern targets the normalizer OUTPUT (Fase 2, ASCII, NFKC-
// stable).
//
// Fase 10a covers the URL/Plain-encoded form; the Base64Flat duplicates are 10c-scope
// (need base64-decode in §6, invariant here).

pub static LDAP_RULES: &[Rule] = &[
    Rule {
        id: "ldap-logical-filter",
        // Boolean filter combinator `(&(` or `(|(`. Matches the gotestwaf
        // `(&(uid=admin)(!(&(1=0)(userPassword=q))))` and `*(|(objectclass=*))`;
        // a single `(cn=John Doe)` has no combinator and is not flagged.
        pattern: r"\((?:&|\|)\(",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "ldap-extensible-match",
        // Extensible-match with an OID or `dn` matching rule: `:<oid>:=` / `:dn:=`.
        // Matches `userPassword:2.5.13.18:=123`; a bare OID value `2.5.4.3` has no
        // `:…:=` and is not flagged.
        pattern: r"(?i):(?:dn|\d+(?:\.\d+)+):=",
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct LdapModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl LdapModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for LdapModule {
    fn id(&self) -> &str {
        "ldap"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = LDAP_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("LDAP rule compilation failed — check patterns at startup"),
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
                    "ldap detection"
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
