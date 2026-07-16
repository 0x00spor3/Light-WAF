// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

use regex::{Regex, RegexSet};
use tracing::warn;
use waf_core::{Config, Decision, ParsedBody, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

/// Mongo operators in KEY position (G-3): a param name (`q[$ne]`) or JSON object key
/// (`{"$gt":…}`) carrying an operator is STRUCTURAL — unequivocal NoSQL injection,
/// unlike the same token in a value (ambiguous → the Warning `nosql-operator` rule).
/// Closed set + `\b` so JSON-Schema `$ref`/`$id`/`$schema`/`$defs`/`$comment` and a
/// currency `$100` do NOT match.
pub(crate) const NOSQL_OPERATOR_KEY_PATTERN: &str =
    r"\$(?:or|and|nor|not|ne|eq|gt|gte|lt|lte|nin|in|regex|exists|expr|elemMatch|all|size|type|mod|where|jsonSchema)\b";

/// Key strings the operator-in-key scan inspects: JSON / form field keys and multipart
/// field names. Query param names are added by the caller. Also read by the content
/// prefilter (Pillar 3 soundness — it must scan the same key surface this module does).
pub(crate) fn body_key_strings(body: &ParsedBody) -> Vec<&str> {
    match body {
        ParsedBody::JsonFlattened(p) | ParsedBody::FormUrlEncoded(p) => {
            p.iter().map(|(k, _)| k.as_str()).collect()
        }
        ParsedBody::Multipart(fields) => fields.iter().map(|f| f.name.as_str()).collect(),
        _ => Vec::new(),
    }
}

// ── rules (Fase 10a) ────────────────────────────────────────────────────────────
//
// NoSQL injection (MongoDB-flavoured). Two confidence tiers (decision 3):
//   - server-side JS execution / shell-method calls = UNEQUIVOCAL → Critical, block-alone;
//   - boolean/comparison OPERATORS = ambiguous (could appear in benign JSON-ish text) →
//     Warning, accumulate.
// FP discipline: the operator rule matches the CLOSED set of Mongo operators bounded by
// `\b`, so a benign `$`-prefixed JSON field name (`$schema`, `$ref`, `$id`) or a currency
// `$100` is NOT flagged — see the benign guards in the corpus. CRS-derived; patterns
// target the normalizer OUTPUT (Fase 2, ASCII, NFKC-stable). The Base64Flat duplicates
// are 10c-scope (corpus `ExpectedMiss{until_phase:"10c"}`).

pub static NOSQL_RULES: &[Rule] = &[
    Rule {
        id: "nosql-where-js",
        // `$where` runs server-side JavaScript — unequivocal.
        pattern: r"\$where\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "nosql-shell-method",
        // Mongo shell collection method call: `db.<coll>.insert(` etc.
        pattern: r"\bdb\.\w+\.(?:insert|find|update|remove|save|drop|count|aggregate)\s*\(",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "nosql-js-timing",
        // Busy-loop timing payload injected into a `$where`-style JS context.
        pattern: r"do\s*\{[^}]*\}\s*while\s*\(",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "nosql-operator",
        // Boolean/comparison operators — ambiguous, accumulate. Closed set + `\b` so
        // benign `$schema`/`$ref`/`$100` do not match.
        pattern: r"\$(?:or|and|nor|ne|gt|gte|lt|lte|nin|in|regex|exists|expr|elemMatch)\b",
        severity: Severity::Warning,
        paranoia: 2,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct NosqlModule {
    rule_set: Option<RegexSet>,
    active_rules: Vec<&'static Rule>,
    /// G-3: matcher for Mongo operators in KEY position (param names / JSON keys).
    operator_key: Option<Regex>,
}

impl NosqlModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for NosqlModule {
    fn id(&self) -> &str {
        "nosql"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = NOSQL_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("NoSQL rule compilation failed — check patterns at startup"),
        );
        // G-3: the operator-in-key scan is always active (structural, PL-independent).
        self.operator_key =
            Some(Regex::new(NOSQL_OPERATOR_KEY_PATTERN).expect("NoSQL key pattern compilation"));
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

        let mut items: Vec<ScoreItem> = matched
            .iter()
            .map(|&idx| {
                let rule = self.active_rules[idx];
                warn!(
                    request_id = %ctx.request_id,
                    rule_id = %rule.id,
                    severity = ?rule.severity,
                    "nosql detection"
                );
                ScoreItem {
                    rule_id: rule.id.to_string(),
                    severity: rule.severity,
                }
            })
            .collect();

        // G-3: scan KEY position (param names + JSON/form/multipart keys). A Mongo operator
        // as a key is unequivocal → Critical, once.
        if let Some(re) = &self.operator_key {
            let key_hit = ctx
                .normalized
                .query_params
                .iter()
                .map(|(k, _)| k.as_str())
                .chain(body_key_strings(&ctx.normalized.body))
                .any(|k| re.is_match(k));
            if key_hit && !items.iter().any(|i| i.rule_id == "nosql-operator-key") {
                warn!(
                    request_id = %ctx.request_id,
                    rule_id = "nosql-operator-key",
                    severity = ?Severity::Critical,
                    "nosql detection"
                );
                items.push(ScoreItem {
                    rule_id: "nosql-operator-key".to_string(),
                    severity: Severity::Critical,
                });
            }
        }

        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Scores(items)
        }
    }
}
