// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Multipart framing must not change the verdict on what it carries.
//!
//! Every query-placed corpus payload is sent as a clean multipart value and again in
//! malformed framing, then the two are compared. Attacks must not vanish, benign values
//! must not pick up rules. `boundary-mismatch` is the hard one: the parser extracts nothing,
//! so it exercises the whole-body fallback on its own, for the shapes nobody anticipated.

use waf_corpus::{cases, run_case, Case, Expect, Field, RunResult, BASELINE_PARANOIA};

type Render = fn(&str) -> (&'static str, Vec<u8>);

const CLEAN_CT: &str = "multipart/form-data; boundary=B";

fn clean(value: &str) -> (&'static str, Vec<u8>) {
    let body = format!(
        "--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n{value}\r\n--B--\r\n"
    );
    (CLEAN_CT, body.into_bytes())
}

fn lf_only(value: &str) -> (&'static str, Vec<u8>) {
    let body = format!("--B\nContent-Disposition: form-data; name=\"f\"\n\n{value}\n--B--\n");
    (CLEAN_CT, body.into_bytes())
}

fn invalid_byte(value: &str) -> (&'static str, Vec<u8>) {
    let mut body = b"--B\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n\xff".to_vec();
    body.extend_from_slice(value.as_bytes());
    body.extend_from_slice(b"\r\n--B--\r\n");
    (CLEAN_CT, body)
}

fn boundary_mismatch(value: &str) -> (&'static str, Vec<u8>) {
    let (_, body) = clean(value);
    ("multipart/form-data; boundary=Z", body)
}

const VARIANTS: &[(&str, Render)] = &[
    ("lf-only", lf_only),
    ("invalid-byte", invalid_byte),
    ("boundary-mismatch", boundary_mismatch),
];

/// These payloads ARE their line breaks (`\r\nQUIT\r\n`), which the fallback text removes.
/// In any framing the parser can follow the value is extracted with them and matched.
const NEEDS_LINE_BREAKS: &[&str] =
    &["mail-imap-capability-query", "mail-smtp-quit-query", "mail-smtp-rcpt-query"];

fn rules(case: &Case, (content_type, body): (&'static str, Vec<u8>)) -> Option<Vec<String>> {
    let probe = Case {
        field: Field::RawBytes { content_type, body: Box::leak(body.into_boxed_slice()) },
        ..*case
    };
    match run_case(&probe, BASELINE_PARANOIA) {
        RunResult::Ran(outcome) if !outcome.normalization_failed => Some(outcome.matched_rules),
        _ => None,
    }
}

/// Every query-placed corpus payload.
fn payloads() -> Vec<(Case, &'static str)> {
    cases::all()
        .into_iter()
        .filter_map(|case| match case.field {
            Field::Query { value, .. } => Some((case, value)),
            _ => None,
        })
        .collect()
}

#[test]
fn attacks_survive_malformed_framing() {
    let mut vanished = Vec::new();
    let mut compared = 0;
    for (case, value) in payloads() {
        if case.expect != Expect::Triggers {
            continue;
        }
        let Some(baseline) = rules(&case, clean(value)) else { continue };
        if baseline.is_empty() {
            continue;
        }
        compared += 1;
        for (name, render) in VARIANTS {
            if *name == "boundary-mismatch" && NEEDS_LINE_BREAKS.contains(&case.id) {
                continue;
            }
            if rules(&case, render(value)).is_some_and(|fired| fired.is_empty()) {
                vanished.push(format!("{} [{name}]", case.id));
            }
        }
    }
    assert!(compared >= 50, "too few payloads compared: {compared}");
    assert!(vanished.is_empty(), "attacks vanished ({} of {compared}): {vanished:#?}", vanished.len());
}

#[test]
fn benign_values_stay_clean_in_malformed_framing() {
    let mut regressions = Vec::new();
    let mut compared = 0;
    for (case, value) in payloads() {
        if case.expect != Expect::Clean {
            continue;
        }
        let Some(baseline) = rules(&case, clean(value)) else { continue };
        compared += 1;
        for (name, render) in VARIANTS {
            let Some(fired) = rules(&case, render(value)) else { continue };
            let added: Vec<_> = fired.iter().filter(|r| !baseline.contains(r)).collect();
            if !added.is_empty() {
                regressions.push(format!("{} [{name}]: {added:?}", case.id));
            }
        }
    }
    assert!(compared >= 30, "too few payloads compared: {compared}");
    assert!(regressions.is_empty(), "new rules on benign input: {regressions:#?}");
}

/// Pseudo-random file bytes in malformed framing: as lossy text they would match all sorts
/// of rules, so a binary upload must stay out of the fallback.
#[test]
fn binary_upload_in_malformed_framing_stays_clean() {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    for _ in 0..8 {
        let mut body = b"--B\nContent-Disposition: form-data; name=\"f\"; filename=\"a.bin\"\n\n".to_vec();
        for _ in 0..64 * 1024 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            body.push(state as u8);
        }
        body.extend_from_slice(b"\n--B--\n");

        let case = Case {
            id: "mp-random-binary",
            module: waf_corpus::Module::PathTraversal,
            field: Field::RawBody { content_type: "", body: "" },
            min_pl: 1,
            expect: Expect::Clean,
            rules: &[],
            desc: "",
        };
        let fired = rules(&case, (CLEAN_CT, body)).expect("case must run");
        assert!(fired.is_empty(), "stray rules on random bytes: {fired:?}");
    }
}
