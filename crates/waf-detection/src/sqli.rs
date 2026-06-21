use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

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
        // OR <operand> = <operand> where each operand is numeric or a single
        // (optionally quoted) char: OR 1=1, OR 'a'='a', OR x=x. The regex engine
        // has no backreferences, so we can't enforce equality; restricting operands
        // to numeric/single-char rejects benign `or word=word` phrases (e.g.
        // "men or women=adult") that the old space-in-class `+` pattern flagged.
        pattern: r#"(?i)\bor\s+(?:\d+|['"`]?\w['"`]?)\s*=\s*(?:\d+|['"`]?\w['"`]?)"#,
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
        id: "sqli-mysql-versioned-comment",
        // MySQL executable comment `/*!...*/` (optionally version-gated `/*!50000`)
        // wrapping a SQL keyword — the classic `/*!UNiOn*/ /*!SeLEct*/` evasion that
        // splits keywords so `union\s+select` can't see them (Fase 10b, gotestwaf
        // sql-injection). Requiring a SQL keyword after `/*!` excludes the benign
        // CSS/JS minifier preservation comment `/*! license … */`.
        pattern: r"(?i)/\*!\d*\s*(?:union|select|insert|update|delete|drop|alter|or|and|where|from|having|exec|cast|concat|sleep)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-information-schema",
        // Access to the DB metadata catalog — schema/table/column enumeration. The
        // underscore token `information_schema` never appears in benign input ("the
        // information schema of the form" has a space, not `_`). gotestwaf
        // sql-injection `… from information_schema.columns …`.
        pattern: r"(?i)\binformation_schema\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-json-function",
        // MySQL JSON functions used in boolean/exfil SQLi (`OR JSON_EXTRACT(…)=…`,
        // `AND JSON_DEPTH('{}')!=…`) — gotestwaf sql-injection. A `json_<fn>(` call in
        // a user value is an unequivocal SQL signal (no benign API passes it as data).
        pattern: r"(?i)\bjson_(?:extract|depth|keys|search|contains|contains_path|value|arrayagg|objectagg|object|array|quote|unquote|type|valid|length|merge\w*|set|insert|replace|remove|overlaps|table|pretty|storage_\w+)\s*\(",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "sqli-tautology-and",
        // Same narrowing as sqli-tautology-or (rejects benign `and word=word`).
        pattern: r#"(?i)\band\s+(?:\d+|['"`]?\w['"`]?)\s*=\s*(?:\d+|['"`]?\w['"`]?)"#,
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
