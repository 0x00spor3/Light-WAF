//! Coverage report for the harvest (Fase 7 / Pilastro 1).
//!
//! Runs every case at the baseline paranoia level and prints, per module:
//! - each shipped rule → the Triggers case(s) that fire it (+ min_pl), or UNCOVERED;
//! - any benign false positive;
//! - the ExpectedMiss status (still missed vs now caught).
//!
//! This is the artefact to review before building metrics/tests/report. Not the
//! final metrics report. Run: `cargo run -p waf-corpus --example coverage`.

use std::collections::BTreeMap;

use waf_corpus::cases;
use waf_corpus::{run_case, Expect, RunResult, BASELINE_PARANOIA};

/// Authoritative (module, rule_id, paranoia) list, transcribed from the detection
/// crate's rule tables. request_smuggling exposes a single rule_id for five
/// framing checks (no paranoia gating).
const RULES: &[(&str, &str, u8)] = &[
    ("sqli", "sqli-union-select", 1),
    ("sqli", "sqli-tautology-or", 1),
    ("sqli", "sqli-stacked-query", 1),
    ("sqli", "sqli-time-based", 1),
    ("sqli", "sqli-tautology-and", 2),
    ("sqli", "sqli-quote-comment", 2),
    ("sqli", "sqli-cast-convert", 3),
    ("sqli", "sqli-hex-literal", 3),
    ("xss", "xss-script-tag", 1),
    ("xss", "xss-javascript-proto", 1),
    ("xss", "xss-event-handler", 1),
    ("xss", "xss-dangerous-tag", 2),
    ("xss", "xss-eval", 2),
    ("xss", "xss-document-cookie", 2),
    ("xss", "xss-vbscript-proto", 3),
    ("xss", "xss-data-html-uri", 3),
    ("xss", "xss-innerhtml", 3),
    ("path_traversal", "pt-dotdot-traversal", 1),
    ("path_traversal", "pt-sensitive-unix", 1),
    ("path_traversal", "pt-sensitive-windows", 1),
    ("path_traversal", "pt-null-byte", 2),
    ("path_traversal", "pt-unc-path", 3),
    ("rce", "rce-cmd-substitution", 1),
    ("rce", "rce-chained-command", 1),
    ("rce", "rce-shell-path", 1),
    ("rce", "rce-reverse-shell", 1),
    ("rce", "rce-backtick", 2),
    ("rce", "rce-ifs-evasion", 2),
    ("rce", "rce-download-exec", 2),
    ("rce", "rce-windows-shell", 2),
    ("rce", "rce-logical-operator", 3),
    ("lfi_rfi", "lfi-stream-wrapper", 1),
    ("lfi_rfi", "lfi-filter-chain", 1),
    ("lfi_rfi", "lfi-data-base64", 2),
    ("lfi_rfi", "rfi-remote-script", 2),
    ("lfi_rfi", "rfi-remote-url", 3),
    ("ssrf", "ssrf-cloud-metadata", 1),
    ("ssrf", "ssrf-dangerous-scheme", 1),
    ("ssrf", "ssrf-loopback", 2),
    ("ssrf", "ssrf-ip-obfuscation", 2),
    ("ssrf", "ssrf-private-ip", 3),
    ("header_injection", "hdr-crlf-header-injection", 1),
    ("header_injection", "hdr-crlf-control-char", 2),
    ("header_injection", "hdr-host-injection", 2),
    ("header_injection", "hdr-crlf-in-body", 3),
    ("request_smuggling", "request-smuggling", 1),
];

fn main() {
    let all = cases::all();

    // rule_id -> list of (case_id, min_pl) that actually fired it.
    let mut coverage: BTreeMap<&str, Vec<(String, u8)>> = BTreeMap::new();
    let mut false_positives: Vec<String> = Vec::new();
    let mut trigger_failures: Vec<String> = Vec::new();
    let mut expected_miss: Vec<(String, bool)> = Vec::new();

    for case in &all {
        let RunResult::Ran(outcome) = run_case(case, BASELINE_PARANOIA) else {
            continue; // skipped: not active at baseline (none expected at PL3)
        };
        match case.expect {
            Expect::Triggers => {
                if outcome.triggered {
                    for r in &outcome.matched_rules {
                        coverage
                            .entry(rule_key(r))
                            .or_default()
                            .push((case.id.to_string(), case.min_pl));
                    }
                } else {
                    trigger_failures.push(format!("{} (no rule fired)", case.id));
                }
            }
            Expect::Clean => {
                if outcome.triggered {
                    false_positives
                        .push(format!("{} -> {:?}", case.id, outcome.matched_rules));
                }
            }
            Expect::ExpectedMiss { .. } => expected_miss.push((case.id.to_string(), outcome.triggered)),
        }
    }

    println!("== Corpus coverage @ PL{BASELINE_PARANOIA} ==");
    println!("total cases: {}\n", all.len());

    let mut uncovered = Vec::new();
    let mut current = "";
    for (module, rule, pl) in RULES {
        if module != &current {
            println!("[{module}]");
            current = module;
        }
        match coverage.get(rule) {
            Some(hits) => {
                let ids: Vec<String> = hits
                    .iter()
                    .map(|(id, mp)| format!("{id}(min_pl={mp})"))
                    .collect();
                println!("  {rule:32} PL{pl}  <- {}", ids.join(", "));
            }
            None => {
                println!("  {rule:32} PL{pl}  <- UNCOVERED");
                uncovered.push(*rule);
            }
        }
    }

    println!("\n== ExpectedMiss (known §8 gaps) ==");
    for (id, triggered) in &expected_miss {
        let status = if *triggered { "now CAUGHT (good regression)" } else { "still missed" };
        println!("  {id:32} {status}");
    }

    println!("\n== Summary ==");
    println!("uncovered rules:   {}", uncovered.len());
    println!("trigger failures:  {}", trigger_failures.len());
    println!("false positives:   {}", false_positives.len());
    for f in &trigger_failures {
        println!("  TRIGGER-FAIL {f}");
    }
    for f in &false_positives {
        println!("  FALSE-POSITIVE {f}");
    }
    for r in &uncovered {
        println!("  UNCOVERED {r}");
    }
}

/// Map a matched rule_id to its `'static` key in RULES (so the coverage map does
/// not borrow the per-case outcome).
fn rule_key(rule_id: &str) -> &'static str {
    RULES
        .iter()
        .find(|(_, r, _)| *r == rule_id)
        .map(|(_, r, _)| *r)
        .unwrap_or("(other)")
}
