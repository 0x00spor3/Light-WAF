use regex::Regex;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

// ── design note ───────────────────────────────────────────────────────────────
//
// hyper / the `http` crate reject CR/LF/NUL inside incoming header VALUES at
// parse time, so classic CRLF injection in the header values themselves never
// reaches the WAF. The live attack surface in the request is:
//   1. CRLF smuggled (percent-encoded) into query/body params — `%0d%0a…` —
//      which Fase 2 decodes; the backend may reflect it into a response header.
//   2. Host header injection to an absolute URI (`Host: http://evil`), which
//      hyper DOES allow (no control chars).
//
// This is the first FIELD-AWARE module: rules carry a `scope` so that bare CR/LF
// is flagged where it is anomalous (query/cookie/header) but tolerated in the
// body (legit textarea line breaks) except at high paranoia. `Phase::Headers`
// only sets pipeline ORDERING — not which fields are inspected (all normalized
// fields are available regardless of phase).

#[derive(Clone, Copy, PartialEq)]
enum Scope {
    /// query params + cookies + header values + body.
    All,
    /// query params + cookies + header values (NOT body — textarea-safe).
    NonBody,
    /// values of `host` / `x-forwarded-host` headers only.
    HostHeaders,
    /// body values only.
    Body,
}

struct HdrRule {
    id: &'static str,
    pattern: &'static str,
    severity: Severity,
    paranoia: u8,
    scope: Scope,
}

static HEADER_INJECTION_RULES: &[HdrRule] = &[
    HdrRule {
        id: "hdr-crlf-header-injection",
        // CR/LF followed by an injectable response-header name + colon.
        pattern: r"(?i)[\r\n]\s*(?:set-cookie|location|content-type|content-length|content-disposition|refresh|link|x-forwarded-for|x-forwarded-host|host)\s*:",
        severity: Severity::Critical,
        paranoia: 1,
        scope: Scope::All,
    },
    HdrRule {
        id: "hdr-crlf-control-char",
        // Bare CR/LF where a newline is anomalous (not the body).
        pattern: r"[\r\n]",
        severity: Severity::Warning,
        paranoia: 2,
        scope: Scope::NonBody,
    },
    HdrRule {
        id: "hdr-host-injection",
        // A Host header must be host[:port] — it never legitimately contains
        // `/`, `@` or a scheme. Any of those means absolute-URI / userinfo Host
        // injection (cache poisoning / routing). IPv6 literals like
        // `[2001:db8::1]:8080` contain none of these, so no false positive.
        pattern: r"(?i)(?:[/@]|https?:)",
        severity: Severity::Warning,
        paranoia: 2,
        scope: Scope::HostHeaders,
    },
    HdrRule {
        id: "hdr-crlf-in-body",
        // Bare CR/LF in the body: legit for textareas, so Notice/PL3 only.
        pattern: r"[\r\n]",
        severity: Severity::Notice,
        paranoia: 3,
        scope: Scope::Body,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct HeaderInjectionModule {
    /// Active (paranoia-filtered) rules with their compiled regex.
    rules: Vec<(&'static HdrRule, Regex)>,
}

impl HeaderInjectionModule {
    pub fn new() -> Self {
        Self::default()
    }
}

fn host_header_values(ctx: &RequestContext) -> Vec<&str> {
    ctx.normalized
        .headers
        .iter()
        .filter(|(name, _)| name == "host" || name == "x-forwarded-host")
        .map(|(_, v)| v.as_str())
        .collect()
}

impl WafModule for HeaderInjectionModule {
    fn id(&self) -> &str {
        "header_injection"
    }

    fn phase(&self) -> Phase {
        // Ordering hint only; inspection spans query/body/cookies/headers.
        Phase::Headers
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.rules = HEADER_INJECTION_RULES
            .iter()
            .filter(|r| r.paranoia <= pl)
            .map(|r| {
                let re = Regex::new(r.pattern)
                    .expect("header-injection rule compilation failed — check patterns at startup");
                (r, re)
            })
            .collect();
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if self.rules.is_empty() {
            return Decision::Allow;
        }

        // Build the per-scope value sets once.
        let query: Vec<&str> = ctx.normalized.query_params.iter().map(|(_, v)| v.as_str()).collect();
        let cookies: Vec<&str> = ctx.normalized.cookies.iter().map(|(_, v)| v.as_str()).collect();
        let headers: Vec<&str> = ctx.normalized.headers.iter().map(|(_, v)| v.as_str()).collect();
        let body_owned = crate::body_str_values(&ctx.normalized.body);
        let body: Vec<&str> = body_owned.iter().map(String::as_str).collect();
        let hosts = host_header_values(ctx);

        let mut items: Vec<ScoreItem> = Vec::new();

        for (rule, re) in &self.rules {
            let matched = match rule.scope {
                Scope::All => {
                    query.iter().chain(&cookies).chain(&headers).chain(&body).any(|v| re.is_match(v))
                }
                Scope::NonBody => {
                    query.iter().chain(&cookies).chain(&headers).any(|v| re.is_match(v))
                }
                Scope::HostHeaders => hosts.iter().any(|v| re.is_match(v)),
                Scope::Body => body.iter().any(|v| re.is_match(v)),
            };

            if matched {
                warn!(
                    request_id = %ctx.request_id,
                    rule_id = %rule.id,
                    severity = ?rule.severity,
                    "header-injection detection"
                );
                items.push(ScoreItem {
                    rule_id: rule.id.to_string(),
                    severity: rule.severity,
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
