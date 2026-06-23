use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::{all_matches, body_str_values, inspectable_header_values, Rule};

// ── rules ─────────────────────────────────────────────────────────────────────
//
// Command injection is the most false-positive-prone category (shell
// metacharacters are common in legit text), so the paranoia tiers are deliberate:
//   - PL1 (Critical): only high-confidence signals — command substitution,
//     a metacharacter *followed by a known command*, explicit shell binaries,
//     reverse-shell idioms.
//   - PL2 (Warning): backticks (common in markdown), ${IFS}, remote fetch,
//     Windows shell invocation.
//   - PL3 (Notice): bare logical operators `&&` / `||`, noisy on their own.
//
// All patterns target the normalizer's OUTPUT form (Fase 2): query/body values
// are double percent-decoded + NFKC-normalized. Every token here is ASCII, which
// NFKC leaves unchanged, so shell metacharacters and `${IFS}` are matched as-is.

pub static RCE_RULES: &[Rule] = &[
    Rule {
        id: "rce-cmd-substitution",
        // $( ... ) command substitution.
        pattern: r"\$\([^)]+\)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-chained-command",
        // A shell separator immediately followed by a known command name.
        pattern: r"(?i)[;&|]\s*(?:cat|ls|id|whoami|uname|pwd|wget|curl|nc|ncat|netcat|ping|bash|sh|zsh|python|perl|ruby|nslookup|dig|getent|host|chmod|rm|cp|mv|kill|telnet|powershell|cmd)\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-shell-path",
        // Explicit shell binary path / executable.
        pattern: r"(?i)(?:/bin/(?:sh|bash|zsh|dash|ksh)\b|cmd\.exe|powershell\.exe)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-reverse-shell",
        // Common reverse-shell idioms.
        pattern: r"(?i)(?:/dev/tcp/|bash\s+-i|nc\s+-[a-z]*e|mkfifo)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-yaml-deserialization",
        // Unsafe YAML deserialization gadgets (PyYAML `!!python/object/...`,
        // `!!python/object/apply`, etc.) — gotestwaf rce-urlparam. The `!!python/`
        // tag never appears in benign input → unequivocal RCE.
        pattern: r"(?i)!!python/(?:object|module|name|apply)",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-backtick",
        // Backtick command substitution; also common in markdown inline code,
        // hence Warning/PL2 (won't block on its own).
        pattern: r"`[^`]+`",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "rce-ifs-evasion",
        // ${IFS} / $IFS used to smuggle spaces.
        pattern: r"(?i)\$(?:\{ifs\}|ifs\b)",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "rce-download-exec",
        // Remote payload fetch via wget/curl.
        pattern: r"(?i)\b(?:wget|curl)\s+(?:-\S+\s+)*https?://",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "rce-windows-shell",
        // Windows shell invocation: cmd /c …, powershell -…, or the built-in
        // `set /a`|`set /p` (arithmetic/prompt — gotestwaf shell-injection `| set /a`).
        // `/a\b`/`/p\b` anchors avoid matching `set /address` etc.
        pattern: r"(?i)(?:cmd(?:\.exe)?\s*/c|powershell(?:\.exe)?\s+-|\bset\s+/[ap]\b)",
        severity: Severity::Warning,
        paranoia: 2,
    },
    Rule {
        id: "rce-logical-operator",
        // Bare shell logical operators. NB: `&&|\|\|` — NOT `&&|||` (which would
        // contain an empty alternative and match everything).
        pattern: r"&&|\|\|",
        severity: Severity::Notice,
        paranoia: 3,
    },
    Rule {
        id: "rce-expression-language",
        // Server-side expression-language / template code execution: a `${…}` or `#{…}`
        // block that CALLS a dangerous function — PHP `${@print(…)}` (gotestwaf
        // community-rce-rawrequests), SpEL/EL `#{…Runtime.exec(…)}`, etc. Scoped to a
        // dangerous-function CALL inside the braces so it stays distinct from SSTI
        // (`{{…}}` / `${n*n}` arithmetic) and benign interpolation (`${base_url}`,
        // `#{user.name}`) which have no such call. `[^}]*` keeps it within one block.
        pattern: r"(?i)[#$]\{[^}]*\b(?:print|eval|exec|system|passthru|assert|shell_exec|popen|phpinfo|file_get_contents|getruntime|runtime|processbuilder)\s*\(",
        severity: Severity::Critical,
        paranoia: 1,
    },
    // ── VBScript / Classic-ASP RCE (Fase 10c §6-D3) ────────────────────────────────
    // gotestwaf rce-urlparam ships a VBScript webshell obfuscated with string-concat
    // (`"Ex"&"e"&"cute` → `Execute`) and whitespace-split (`Ev al`). On the wire the
    // concat `&` is a literal query separator → the payload SHATTERS across params, but
    // several VBScript/ASP intrinsics survive a fragment INTACT and are unambiguous on
    // their own. (The `"&"`-concat de-obf channel additionally reconstructs `Execute(`
    // for the well-formed `%26` variant — see waf-normalizer `strip_vbscript_concat`.)
    Rule {
        id: "rce-vbscript-on-error",
        // `On Error Resume Next` — a VBScript-only statement; in a request parameter it
        // is a webshell/script-injection tell, never benign app input.
        pattern: r"(?i)\bon\s+error\s+resume\s+next\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-asp-server-intrinsic",
        // Classic-ASP `Server.` intrinsics used by webshells to spawn COM / read files /
        // tune the runtime. ASP-only method names → high confidence.
        pattern: r"(?i)\bserver\.(?:scripttimeout|createobject|mappath|execute|transfer)\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-vbscript-createobject",
        // `CreateObject("WScript.Shell" | "MSXML2…" | "ADODB…" | FileSystemObject | …)` —
        // the canonical VBScript/COM webshell sink. Anchored to the dangerous progIDs so
        // a bare `CreateObject(` (also a .NET API) does not match on its own.
        pattern: r#"(?i)\bcreateobject\s*\(\s*["']?(?:wscript\.|msxml|adodb\.|scripting\.filesystemobject|shell\.application|microsoft\.xmlhttp)"#,
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "rce-asp-response-write",
        // `Response.Write(` — ASP output sink; common in webshell scaffolding. More
        // tutorial-prone than the above, so Warning (accumulates, sub-threshold alone).
        pattern: r"(?i)\bresponse\.write\s*\(",
        severity: Severity::Warning,
        paranoia: 2,
    },
];

// ── module ────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct RceModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl RceModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for RceModule {
    fn id(&self) -> &str {
        "rce"
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = RCE_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("RCE rule compilation failed — check patterns at startup"),
        );
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let Some(rule_set) = &self.rule_set else {
            return Decision::Allow;
        };

        // `normalized.path` is inspected too: command injection in the URL PATH
        // (`/; cat /etc/passwd`, `/cmd=127.0.0.1 && ls /etc`) — gotestwaf rce-urlpath
        // — bypasses a query/body-only scan. The path is the resolved, decoded form
        // (Fase 2), so shell metacharacters appear as-is.
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
                    "rce detection"
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
