// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

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
        // The `javascript:` scheme, three branches of ONE rule (a request matching several
        // still scores once — `all_matches` dedups by rule):
        // 1. CALL (Fase 10b): scheme, then any run of non-paren chars, then an identifier
        //    immediately followed by `(`. FP-precise form for free text: the bare
        //    `(?i)javascript\s*:` matched benign prose like "JavaScript: Basics of JavaScript
        //    Language" (Critical/PL1 → 403). The `regex` crate has no lookaround (§8
        //    linear-time), so precision is by structure: an attack `javascript:alert(…)` has
        //    the call, prose has no `(` after the colon.
        // 2. URL ATTRIBUTE (F1 M2 famiglia 4): the scheme as the VALUE of an attribute that
        //    navigates or executes (`href` — also `xlink:href` —, `src`, `action`,
        //    `formaction`, `data`, SVG animation `values`/`from`/`to`, meta-refresh `url`),
        //    WHATEVER follows: there the scheme itself is the danger, call or not (tagged
        //    templates, assignments, `throw`, bracket access). No tag is required (an
        //    attribute-context breakout `" href=…` counts too); precision comes from the
        //    value STARTING with the scheme and from the CLOSED attribute list
        //    (`title="javascript: tips"` stays clean). `srcdoc` is HTML, not a URL.
        // 3. START OF VALUE (famiglia 4): the scheme at the start of an inspected value
        //    (`?url=`, `?next=`, a JSON leaf, Referer — the value reflected into an href).
        //    Followed by a non-space char, or by whitespace + an identifier immediately
        //    followed by a backtick or `[`, or by `\s*=`. A bare scheme + whitespace + prose
        //    ("javascript: the good parts", `{"skills":"javascript: 5 anni"}`) stays clean.
        //    "Start" also means right after U+FFFD: the multipart fallback text replaces the
        //    framing line breaks with it (`FALLBACK_SEPARATOR`, waf-normalizer `body.rs`) and
        //    an invalid byte before a value becomes it, so a value a lenient backend extracts
        //    from malformed framing still starts the match (`tests/multipart_differential.rs`).
        //    For the same reason U+FFFD right after the colon is the end of that value (the
        //    next framing line), not code: a bare `javascript:` value stays clean.
        // Branches 2-3 read the scheme the way the browser URL parser does: TAB/LF/CR are
        // removed anywhere in a URL (`java%09script:`, `java&#x09;script:` — the normalizer
        // keeps them), and leading C0 controls/space are stripped.
        // FREE TEXT without a call is NOT matched: every code indicator has a prose trap
        // (`=`, `;`, backtick, `[`, keywords like `new`/`void`/`throw`), and a mid-text scheme
        // only executes where branches 2-3 already look.
        // ACCEPTED FP: CMS no-op links (`href="javascript:;"`, `"javascript:void 0"`,
        // `"javascript:"`) block at PL1, consistent with `javascript:void(0)`, already
        // blocked by branch 1 in 1.0.3. A no-op carve-out was rejected: it is an evasion
        // surface (`javascript:;<code>`), and the end of an UNQUOTED value is ambiguous
        // (`href=javascript:; onx=…`, `>`, end of input). There is no per-route exclusion
        // of a native rule today (only the global `[modules.xss]` / severity / paranoia /
        // detection-only levers; `SecRuleRemoveById` applies to CRS rules only).
        // QUANTIFIERS (famiglia 3 convention): stars only over single classes, ONE level,
        // inner alternatives disjoint on their first char; the top-level branches 1 and 3
        // share the first consumed char `j` (3 is anchored to `^` / U+FFFD). Size pinned by
        // `waf-detection/tests/prefilter_size.rs`.
        pattern: r#"(?i)javascript\s*:[^()]*[a-z_$][\w$]*\(|\b(?:href|src|action|f(?:ormaction|rom)|data|values|to|url)\s*=[\x00-\x20]*(?:["'`][\x00-\x20]*)?j[\t\n\r]*a[\t\n\r]*v[\t\n\r]*a[\t\n\r]*s[\t\n\r]*c[\t\n\r]*r[\t\n\r]*i[\t\n\r]*p[\t\n\r]*t[\t\n\r]*:|(?:^|\x{FFFD})[\x00-\x20]*j[\t\n\r]*a[\t\n\r]*v[\t\n\r]*a[\t\n\r]*s[\t\n\r]*c[\t\n\r]*r[\t\n\r]*i[\t\n\r]*p[\t\n\r]*t[\t\n\r]*:(?:[^\s\x{FFFD}]|\s+[a-z_$][\w$.]*(?:[`\[]|\s*=))"#,
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "xss-event-handler",
        // Inline event handlers, two branches of ONE rule (a request matching both still
        // scores once — `all_matches` dedups by rule):
        // 1. LIST: the real handler names, anywhere (NOT `on\w+`, which matched benign
        //    query params like ?online=true, ?onsale=1 at Critical/PL1). Kept because it
        //    also covers the tag-less attribute-context form (`" onfocus=… autofocus`).
        // 2. TAG (F1 M2 famiglia 3): ANY `on[a-z]{3,}=` in attribute-NAME position of an
        //    open tag, so out-of-list handlers (pageshow, SVG animation begin, focusin, …)
        //    are caught without a list. Precision comes from walking the tag's attribute
        //    grammar like the HTML tokenizer: `<tag`, then `[\s/]+`, then attributes —
        //    name, then nothing / `=` + value. A quoted value is consumed whole (an
        //    `on…=` or `>` inside it never counts) and may be followed by no separator;
        //    an unquoted value runs to whitespace (`/` belongs to it); a valueless name is
        //    followed by `[\s/]+`. So `?online=`, `&onboarding=`, `data-online=`,
        //    `alt="online = …"`, `href=/p/online=1` never reach the handler position. Tag
        //    and attribute names use restricted ASCII classes (`; ) { & ? <` excluded) so
        //    code like `a <b ? online = 1` is not read as a tag.
        //    QUANTIFIERS (deliberate exception to the bounded-`{0,N}` convention): counted
        //    repetitions are unrolled by the `regex` crate and grow both the automaton and
        //    latency, while a bounded value/attribute count is a trivial padding bypass.
        //    So: only stars over single character classes (`[^"]*`, `[^']*`, `[^\s>]*`), ONE
        //    level of repetition (the attribute group), and alternatives disjoint on their
        //    first char (`"` / `'` / other; `\s` / `=` / `/`). Linear time either way
        //    (precedent: `[^()]*` in xss-javascript-proto); size is pinned by
        //    `waf-detection/tests/prefilter_size.rs`.
        pattern: r#"(?i)\bon(?:error|load|click|auxclick|mouse\w+|pointer\w+|focus|blur|change|submit|key\w+|abort|drag\w+|drop|input|wheel|scroll|toggle|beforetoggle|select|reset|resize|contextmenu|animation\w+|transition\w+|play|pause|ended|canplay|copy|cut|paste)\s*=|<[a-z][a-z0-9:._-]*[\s/]+(?:[a-z0-9_:.@#-]+(?:\s+(?:=\s*(?:"[^"]*"[\s/]*|'[^']*'[\s/]*|[^\s>"'][^\s>]*\s+)|/[\s/]*)?|=\s*(?:"[^"]*"[\s/]*|'[^']*'[\s/]*|[^\s>"'][^\s>]*\s+)|/[\s/]*))*on[a-z]{3,}\s*="#,
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
