// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

// ── rules ─────────────────────────────────────────────────────────────────────
//
// Two rule families (see ARCHITECTURE §7 and the Fase 2 normalizer):
//   - traversal sequences (`../`, `..\`) survive in query/cookie/body but NOT in
//     `normalized.path`, which the normalizer already resolves (`resolve_path`);
//   - sensitive target paths survive in `normalized.path` even after the `..`
//     have been resolved away (e.g. `/app/../../etc/passwd` -> `/etc/passwd`),
//     so they catch traversal that targeted the URL path itself.
// Both families run uniformly over all inspected fields; a rule that cannot
// match a given field (e.g. `../` on the resolved path) simply stays silent.

pub static PATH_TRAVERSAL_RULES: &[Rule] = &[
    Rule {
        id: "pt-dotdot-traversal",
        // Two or more *consecutive* traversal segments (`../../`, `..\..\`,
        // mixed) — the signature of an actual directory escape. A single `../`
        // is left to `pt-sensitive-*` (which still flags traversal that reaches a
        // sensitive target on the resolved path/value): requiring `{2,}` keeps a
        // benign relative `../` (`docs/../report.pdf`, `../images/logo.png`) Clean
        // without losing real escapes (`/static/img/../../etc/passwd` has `../../`).
        // Structural narrowing (no lookahead — the `regex` crate has none). 10b-cont.
        pattern: r"(?:\.\.[\\/]){2,}",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "pt-sensitive-unix",
        // Classic Unix exfiltration targets.
        pattern: r"(?i)/(?:etc/(?:passwd|shadow|group|hosts)|proc/self|proc/version)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "pt-sensitive-windows",
        // Windows targets; `system32` anchored to a path separator + word
        // boundary so legit tokens like `system32_dark` don't false-positive.
        pattern: r"(?i)(?:boot\.ini|win\.ini|[\\/]windows[\\/]|[\\/]system32\b)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "pt-null-byte",
        // NUL byte truncation. Dead on the path (the normalizer strips NUL), but
        // live on query/body where `%00` is decoded to a real NUL byte.
        pattern: r"\x00",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "pt-unc-path",
        // UNC network path: \\server\share — Windows remote file access. The host
        // class includes `:` so an IPv6-literal host (`\\::1\c$\…`, localhost over
        // UNC) matches too; the literal backslashes survive normalization (Fase 2),
        // only the host token needed widening. gotestwaf path-traversal.
        pattern: r"(?i)\\\\[a-z0-9_.$:-]+\\",
        severity: Severity::Notice,
        paranoia: 3,
    },
    Rule {
        id: "pt-unc-admin-share",
        // UNC path to an ADMINISTRATIVE share — `\\host\c$\`, `\\host\admin$\`, `\\host\ipc$\`.
        // The `$`-suffixed share is the attack tell (remote SYSTEM-drive / IPC access, e.g.
        // `\\::1\c$\users\default\ntuser.dat`); ordinary file shares (`\\srv\public\`) have
        // no `$` and stay on the Notice-level `pt-unc-path`. Promotes ONLY the admin-share
        // form to Critical, no FP on legitimate UNC references.
        pattern: r"(?i)\\\\[a-z0-9_.:-]+\\[a-z]+\$\\",
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct PathTraversalModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl PathTraversalModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for PathTraversalModule {
    fn id(&self) -> &str {
        "path_traversal"
    }

    fn phase(&self) -> Phase {
        Phase::RequestLine
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = PATH_TRAVERSAL_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("path-traversal rule compilation failed — check patterns at startup"),
        );
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let Some(rule_set) = &self.rule_set else {
            return Decision::Allow;
        };

        let path = std::iter::once(ctx.normalized.path.as_str());
        let query = ctx.normalized.query_params.iter().map(|(_, v)| v.as_str());
        let cookies = ctx.normalized.cookies.iter().map(|(_, v)| v.as_str());
        let body_vals = body_str_values(&ctx.normalized.body);
        let body = body_vals.iter().map(String::as_str);
        let derived = ctx.normalized.derived_decoded.iter().map(String::as_str);

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
                    "path-traversal detection"
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
