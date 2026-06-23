use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

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
        // `javascript:` scheme leading into a function CALL: scheme, then any run of
        // non-paren chars, then an identifier immediately followed by `(`. This is the
        // FP-precise form (Fase 10b): the bare `(?i)javascript\s*:` matched benign prose
        // like "JavaScript: Basics of JavaScript Language" (Critical/PL1 → 403). The
        // `regex` crate has no lookaround (§8 linear-time), so precision is by structure:
        // an attack `javascript:alert(…)` has the call, prose has no `(` after the colon.
        // (Coverage of call-less sinks / entity-obfuscated schemes is later-batch work.)
        pattern: r"(?i)javascript\s*:[^()]*[a-z_$][\w$]*\(",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xss-event-handler",
        // Inline event handlers: onerror=, onclick=, onload=, onmouseover=, etc.
        // Anchored to the real handler names (NOT `on\w+`, which matched benign
        // query params like ?online=true, ?onsale=1 at Critical/PL1).
        pattern: r"(?i)\bon(?:error|load|click|auxclick|mouse\w+|pointer\w+|focus|blur|change|submit|key\w+|abort|drag\w+|drop|input|wheel|scroll|toggle|beforetoggle|select|reset|resize|contextmenu|animation\w+|transition\w+|play|pause|ended|canplay|copy|cut|paste)\s*=",
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
        id: "xss-js-sink-call",
        // A JS sink invoked directly (`alert(…)`, `prompt(…)`) or via the
        // parenthesized form (`(alert)(1)`) — gotestwaf xss-scripting bypasses without
        // a tag/handler/scheme, and also the literal `alert(1)` left inside entity-
        // obfuscated polyglots. NO `\s*` before `(`: that keeps benign prose with a
        // paren ("confirm (your order)") clean while still catching the attack forms.
        // Warning/PL2 = accumulation-only on this high-traffic module (anti-FP).
        pattern: r"(?i)(?:\b(?:alert|confirm|prompt)(?:\?\.)?\(|\(\s*(?:alert|confirm|prompt)\s*\)\s*\()",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "xss-js-sink-invocation",
        // A JS sink invoked via Function.prototype method: `alert.call(…)`,
        // `confirm.apply(…)`, `prompt.bind(…)` — gotestwaf xss-scripting bypasses that
        // carry no tag/handler/scheme (`confirm.call(null,1)`, `alert.apply(null,[1])`).
        // `.call(`/`.apply(`/`.bind(` on a sink name is near-zero FP (prose never writes
        // it), but Warning/PL2 keeps it accumulation-only on this high-traffic module.
        pattern: r"(?i)\b(?:alert|confirm|prompt|eval)\s*\.\s*(?:call|apply|bind)\s*\(",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "xss-document-cookie",
        // Dot OR bracket access: `document.cookie`, `document["cookie"]`,
        // `document['cookie']` (gotestwaf community-xss bracket-notation bypass).
        pattern: r#"(?i)document\s*(?:\.\s*cookie|\[\s*['"]cookie)"#,
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
