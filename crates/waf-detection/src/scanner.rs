use regex::RegexSet;
use tracing::warn;
use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};

use crate::Rule;

// ── rules (Fase 10a) ────────────────────────────────────────────────────────────
//
// Automated-scanner / security-tool fingerprinting via the request User-Agent. A
// benign client never advertises a scanner name or an out-of-band interaction
// domain in its UA, so these are unequivocal signals → Critical, block-alone
// (decision 3). Two families:
//   - the tool's own fingerprint string (sqlmap, nuclei, OpenVAS, ffuf, …, `.nasl`);
//   - OOB callback domains (Burp Collaborator / interactsh / oast.*) embedded in the
//     UA, including the `${jndi:ldap://…oast.me/…}` log4shell-in-UA spray (caught by
//     the OOB domain, not a JNDI-specific rule).
//
// Scope is the **User-Agent header value only** (the module name's contract): the
// fingerprints would over-match other free-text headers (e.g. a `nmap.org` Referer),
// and the live attack surface this module owns is the UA. The content prefilter
// over-scans all headers with these patterns — sound (it can only over-flag).

pub static SCANNER_RULES: &[Rule] = &[
    Rule {
        id: "scanner-tool-ua",
        // Known offensive-security tool fingerprints. `\b` anchors keep `nmap` from
        // matching `roadmap`/`sitemap`. `fuzz faster u fool` is ffuf's UA string;
        // `\.nasl` is the Nessus/OpenVAS plugin script suffix. `openvas\w*` tolerates a
        // glued suffix — gotestwaf's real UA is `…OpenVASVT` (no separator), which a bare
        // `openvas\b` missed (10c REOPEN, pcap-confirmed); the prefix is unambiguous.
        pattern: r"(?i)\b(?:sqlmap|nikto|nuclei|openvas\w*|nessus|acunetix|netsparker|wpscan|dirbuster|gobuster|masscan|nmap|hydra|w3af|arachni|zaproxy|burpsuite|fuzz faster u fool|ffuf|wfuzz)\b|\.nasl\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
    Rule {
        id: "scanner-oob-interaction",
        // Out-of-band interaction domains used by scanners / OOB payloads to confirm
        // blind execution (Burp Collaborator, interactsh, the oast.* family).
        pattern: r"(?i)\b(?:burpcollaborator\.net|interact\.sh|oast\.(?:me|fun|pro|live|site|online))\b",
        severity: Severity::Critical,
        paranoia: 1,
    },
];

// ── module ──────────────────────────────────────────────────────────────────────

#[derive(Default)]
pub struct ScannerModule {
    rule_set: Option<RegexSet>,
    /// Rules active at the configured paranoia level, index-aligned with `rule_set`.
    active_rules: Vec<&'static Rule>,
}

impl ScannerModule {
    pub fn new() -> Self {
        Self::default()
    }
}

impl WafModule for ScannerModule {
    fn id(&self) -> &str {
        "scanner"
    }

    fn phase(&self) -> Phase {
        // Ordering hint only; inspection reads the User-Agent header value.
        Phase::Headers
    }

    fn init(&mut self, cfg: &Config) {
        let pl = cfg.waf.paranoia_level;
        self.active_rules = SCANNER_RULES.iter().filter(|r| r.paranoia <= pl).collect();
        self.rule_set = Some(
            RegexSet::new(self.active_rules.iter().map(|r| r.pattern))
                .expect("scanner rule compilation failed — check patterns at startup"),
        );
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let Some(rule_set) = &self.rule_set else {
            return Decision::Allow;
        };

        // Scope: User-Agent header value(s) only (see module docs).
        let mut hit = vec![false; rule_set.len()];
        for (_, value) in ctx.normalized.headers.iter().filter(|(n, _)| n == "user-agent") {
            for idx in rule_set.matches(value).into_iter() {
                hit[idx] = true;
            }
        }

        let items: Vec<ScoreItem> = hit
            .iter()
            .enumerate()
            .filter_map(|(idx, &fired)| {
                if !fired {
                    return None;
                }
                let rule = self.active_rules[idx];
                warn!(
                    request_id = %ctx.request_id,
                    rule_id = %rule.id,
                    severity = ?rule.severity,
                    "scanner detection"
                );
                Some(ScoreItem {
                    rule_id: rule.id.to_string(),
                    severity: rule.severity,
                })
            })
            .collect();

        if items.is_empty() {
            Decision::Allow
        } else {
            Decision::Scores(items)
        }
    }
}
