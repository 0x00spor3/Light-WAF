use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, Rule};

// ── rules (Fase 10b) ────────────────────────────────────────────────────────────
//
// XML External Entity (XXE) injection: a user-supplied XML document that declares
// an entity / external DTD so the parser dereferences an attacker URL (file://,
// http://) on the server — file disclosure, SSRF, billion-laughs. gotestwaf
// xml-injection + community-xxe. The signatures below target XML *markup
// declarations* that never appear in a plain data value: an entity declaration
// (`<!ENTITY`), an external DOCTYPE (`<!DOCTYPE … SYSTEM`), and the UTF-7 XML
// declaration used to smuggle the markup past byte-level filters. All three are
// unequivocal — block-alone, Critical/PL1 (decision 3). Patterns target the
// normalizer OUTPUT (Fase 2): the query value round-trips the XML verbatim.
//
// PRECISION (no lookaround in the `regex` crate — fixes are structural):
//   - `<!DOCTYPE … SYSTEM` is anchored to SYSTEM, NOT PUBLIC: an XHTML doctype
//     `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0…" "http://…dtd">` is benign and
//     uses PUBLIC, so SYSTEM-only avoids that false positive (the external-PUBLIC
//     *entity* form `<!ENTITY % x PUBLIC …>` is still caught by `xxe-entity`);
//   - `[^\[>]*` between DOCTYPE and SYSTEM stops at an internal-subset `[`, so it
//     never reaches into `<!DOCTYPE x [ … SYSTEM … ]>` (that payload carries an
//     `<!ENTITY` and is attributed there — one rule per payload).
//
// DOCUMENTED LIMITS (see cases/xxe.rs, ExpectedMiss{None}): external XML-Schema
// inclusion (`xsi:schemaLocation` / `<xs:include>`) is regex-indistinguishable from
// benign SOAP/XSD traffic without semantic XML parsing + outbound-URL reputation,
// so flagging it would be a SOAP false-positive factory — deferred to keep the P2
// benign-blocking floor at 0.

pub static XXE_RULES: &[Rule] = &[
    Rule {
        id: "xxe-entity-declaration",
        // `<!ENTITY` — declaring an XML entity. A data value never does this; in a
        // request body it is an XXE / billion-laughs attempt. Catches internal,
        // SYSTEM and PUBLIC external entity declarations alike.
        pattern: r"(?i)<!ENTITY\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xxe-doctype-external",
        // `<!DOCTYPE … SYSTEM` — an external DTD reference. SYSTEM-only (not PUBLIC)
        // so legacy XHTML doctypes (which use PUBLIC) do not false-positive; the
        // `[^\[>]*` body stops before an internal subset `[`.
        pattern: r"(?i)<!DOCTYPE\b[^\[>]*\bSYSTEM\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xxe-utf7-encoding",
        // `encoding="UTF-7"` in the XML declaration — a charset-smuggling evasion
        // (the real `<!DOCTYPE`/`<!ENTITY` markup is UTF-7-encoded to slip past
        // byte-level filters). No modern XML legitimately declares UTF-7.
        pattern: r#"(?i)encoding\s*=\s*["']?\+?utf-?7\b"#,
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct XxeModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl XxeModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for XxeModule {
    fn id(&self) -> &str {
        "xxe"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = XXE_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("XXE rule compilation failed — check patterns at startup"),
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
                    "xxe detection"
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
