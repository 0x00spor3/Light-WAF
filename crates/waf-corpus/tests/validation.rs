//! Anti-regression validation suite (Fase 7 / Pilastro 1).
//!
//! Hard structural guards that must always hold (detection is frozen):
//!   (a) zero trigger-failures on malicious cases that ran (min_pl <= execution_pl);
//!   (b) zero false positives on benign cases;
//!   (c) the declared §8 overlaps are present;
//!   (d) every ExpectedMiss gap is still missed.
//!
//! Numeric recall/FP targets (misura-poi-fissa) are added on top of these once the
//! baseline is reviewed; (a) and (b) already encode the measured baseline of
//! recall = 100% / FP = 0% on the authored cases.

use waf_corpus::metrics::{BlockingReport, Report};
use waf_corpus::{
    cases, run_case_fast, run_case_with, Case, CaseOutcome, Expect, Field, Module,
    BASELINE_PARANOIA, RECOMMENDED_CONFIG, RECOMMENDED_SEVERITY, RECOMMENDED_THRESHOLD, RunResult,
    Verdict,
};

/// True when an overlap entry for `case_id` lists `extra_rule` among its extras.
fn has_overlap(report: &Report, case_id: &str, extra_rule: &str) -> bool {
    report
        .overlaps
        .iter()
        .any(|o| o.case_id == case_id && o.extra.iter().any(|e| e == extra_rule))
}

#[test]
fn no_trigger_failures_on_malicious() {
    let report = Report::run(BASELINE_PARANOIA);
    let fails: Vec<&String> = report.modules.iter().flat_map(|m| &m.trigger_failures).collect();
    assert!(fails.is_empty(), "malicious cases failed to trigger: {fails:?}");
}

#[test]
fn no_false_positives_on_benign() {
    let report = Report::run(BASELINE_PARANOIA);
    let fps: Vec<&(String, Vec<String>)> =
        report.modules.iter().flat_map(|m| &m.false_positives).collect();
    assert!(fps.is_empty(), "benign cases produced false positives: {fps:?}");
}

#[test]
fn declared_overlaps_present() {
    let report = Report::run(BASELINE_PARANOIA);

    // §8: 169.254.169.254 hits cloud-metadata AND private-ip (link-local).
    assert!(
        has_overlap(&report, "ssrf-cloud-metadata-query", "ssrf-private-ip"),
        "expected ssrf metadata/private-ip overlap"
    );
    // §8: bare http(s)/ftp URLs also hit the FP-prone rfi-remote-url at PL3.
    for case in [
        "ssrf-loopback-query",
        "ssrf-ip-obfuscation-query",
        "ssrf-private-ip-query",
        "rce-download-exec-query",
    ] {
        assert!(
            has_overlap(&report, case, "rfi-remote-url"),
            "expected rfi-remote-url overlap on {case}"
        );
    }
    // Intra-module: a CRLF + header-name payload also matches the bare-CRLF rule.
    assert!(
        has_overlap(&report, "hdr-crlf-header-injection-query", "hdr-crlf-control-char"),
        "expected hdr crlf control-char overlap"
    );
}

#[test]
fn baseline_targets_met() {
    // misura-poi-fissa, "minimum corpus counts" form: perfect recall and zero FP
    // on the authored cases (the measured baseline), plus a floor on volume so the
    // suite keeps guaranteeing coverage. Adding cases never breaks this; a
    // regression (a missed trigger or a new FP) does.
    let report = Report::run(BASELINE_PARANOIA);
    let agg = report.aggregate();

    assert_eq!(agg.recall(), 1.0, "recall must stay 100% ({:?})", agg);
    assert_eq!(agg.fp_rate(), 0.0, "false-positive rate must stay 0% ({:?})", agg);
    assert!(
        agg.malicious_total >= 50,
        "malicious coverage floor regressed: {} < 50",
        agg.malicious_total
    );
    assert!(
        agg.benign_total >= 26,
        "benign coverage floor regressed: {} < 26",
        agg.benign_total
    );
}

/// Own-merit score of a named case under the recommended config: sum of points
/// from contributions belonging to the case's own module.
fn own_score(case_id: &str, pl: u8) -> u32 {
    let case = cases::all()
        .into_iter()
        .find(|c| c.id == case_id)
        .unwrap_or_else(|| panic!("unknown case {case_id}"));
    match run_case_with(&case, pl, RECOMMENDED_SEVERITY) {
        RunResult::Ran(o) => o
            .contributions
            .iter()
            .filter(|c| c.module == case.module.name())
            .map(|c| c.points)
            .sum(),
        RunResult::Skipped => panic!("{case_id} skipped at PL{pl}"),
    }
}

#[test]
fn recommended_config_ladder_properties() {
    // The pin is NOT "threshold == 5": it is the five ladder properties that
    // justify C2 over C0/C1/C3 (Fase 7 / Pilastro 2). A regression in any of these
    // — including a future config edit — fails here with a named reason.
    let c = RECOMMENDED_SEVERITY;
    let t = RECOMMENDED_THRESHOLD;

    // (1) A lone Critical blocks with own-merit margin >= 1 (the robustness C2 buys
    //     that CRS-default 5/T5 lacks). At PL1 only Critical (+smuggling Reject) run.
    assert!(c.critical > t, "Critical must clear threshold by >=1");
    let pl1 = BlockingReport::run(RECOMMENDED_CONFIG, 1);
    assert_eq!(
        pl1.block_margin_own(),
        Some(1),
        "lone-Critical own-merit margin must be +1 at PL1"
    );

    // (2) lone Warning (3) and lone Notice (2) stay UNDER threshold — they only
    //     block in accumulation (anti-FP, DECISIONE 3). Grounded on real cases.
    assert!(c.warning < t && c.notice < t, "weak severities must be sub-threshold");
    assert_eq!(own_score("sqli-quote-comment-cookie", 2), c.warning); // 3
    assert!(own_score("sqli-quote-comment-cookie", 2) < t, "lone Warning must not block");
    assert_eq!(own_score("sqli-cast-convert-query", 3), c.notice); // 2
    assert!(own_score("sqli-cast-convert-query", 3) < t, "lone Notice must not block");

    // (3) 2×Notice (4) does NOT reach the threshold — the exact boundary that makes
    //     C1 (T4) unacceptable (it would block ?u=http://10.0.0.x/ in production).
    //     Conscious regression guard.
    assert!(2 * c.notice < t, "two Notices must stay below threshold (else mass FP, cf. C1)");

    // (4) Warning+Notice accumulation (3+2=5) blocks AT the threshold — the by-design
    //     ladder behaviour, exercised by the PL3 lfi case (own merit, same module).
    assert_eq!(own_score("lfi-rfi-remote-script-query", 3), c.warning + c.notice); // 5
    assert!(own_score("lfi-rfi-remote-script-query", 3) >= t, "Warning+Notice must block in accumulation");

    // (5) benign-blocking == 0 at every tested PL (benign all score 0).
    for pl in [1u8, 2, 3] {
        let r = BlockingReport::run(RECOMMENDED_CONFIG, pl);
        assert_eq!(r.benign_blocked(), 0, "no benign may block at PL{pl}: {:?}", r.benign_blocking_ids);
    }
}

#[test]
fn expected_miss_phase_deferrals_honored() {
    use waf_corpus::{phase_reached, CURRENT_PHASE};
    let report = Report::run(BASELINE_PARANOIA);

    // Machine-checkable deferral: a gap whose `until_phase` has ARRIVED must now be
    // caught (else the build fails — implement it or it's a regression); a gap that
    // fires AHEAD of its phase, or a permanent (`None`) gap that starts firing, is a
    // good regression to promote.
    let mut due_but_missed: Vec<&String> = Vec::new();
    let mut early_caught: Vec<&String> = Vec::new();
    for e in &report.expected_miss {
        let due = matches!(e.until_phase, Some(p) if phase_reached(p, CURRENT_PHASE));
        if due {
            if e.still_missed {
                due_but_missed.push(&e.case_id);
            }
        } else if !e.still_missed {
            early_caught.push(&e.case_id);
        }
    }
    assert!(
        due_but_missed.is_empty(),
        "ExpectedMiss past its until_phase at {CURRENT_PHASE} but still missed — implement it (or it is a regression): {due_but_missed:?}"
    );
    assert!(
        early_caught.is_empty(),
        "ExpectedMiss caught ahead of its phase (promote to Triggers, re-baseline): {early_caught:?}"
    );
}

// ── Pilastro 3: fast-path equivalence oracle ───────────────────────────────────
//
// The corpus is the EQUIVALENCE ORACLE: for every case, the fast-path (prefilter
// skip) must produce the SAME enforced decision as the full path, at the frozen
// production config C2. "Decision" is Allow / Block / Reject (DECISIONE 1): the
// asymmetric definition — score+matched_rules are compared only where inspection
// actually runs (a skip, by design, computes neither; the existing block
// short-circuit already produces partial rules). The fail-safe asymmetry
// (DECISIONE 3) is explicit and loud: a skip may NEVER hide a block/reject.

/// Enforced decision at a given threshold, derived offline from a threshold = MAX
/// run (content modules never short-circuit there, so `score` is the full total).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision3 {
    Allow,
    Block,
    Reject,
}

fn decide(o: &CaseOutcome, threshold: u32) -> Decision3 {
    match o.verdict {
        Verdict::Reject => Decision3::Reject,
        Verdict::Block => Decision3::Block, // normalization-limit (≈400)
        Verdict::Allow if o.score >= threshold => Decision3::Block,
        Verdict::Allow => Decision3::Allow,
    }
}

#[test]
fn fastpath_equivalence_on_corpus() {
    let sev = RECOMMENDED_SEVERITY;
    let t = RECOMMENDED_THRESHOLD;

    for pl in [1u8, 2, 3] {
        for case in cases::all() {
            let full = run_case_with(&case, pl, sev);
            let fast = run_case_fast(&case, pl, sev);
            let (fo, fa) = match (&full, &fast) {
                (RunResult::Skipped, RunResult::Skipped) => continue,
                (RunResult::Ran(fo), RunResult::Ran(fa)) => (fo, fa),
                _ => panic!("skip/run disagreement for {} at PL{pl}", case.id),
            };

            let d_full = decide(fo, t);
            let d_fast = decide(fa, t);

            // (3) decision-equivalence — the core P3 property.
            assert_eq!(
                d_full, d_fast,
                "decision mismatch on {} @PL{pl}: full={d_full:?} fast={d_fast:?}",
                case.id
            );

            // (4) CRITICAL fail-safe (DECISIONE 3): a fast-path skip must NEVER hide
            // a block/reject. This is the line that must scream.
            if fa.fastpath_skipped {
                assert_eq!(
                    d_full,
                    Decision3::Allow,
                    "SECURITY: fast-path skipped {} @PL{pl} but full-path = {d_full:?} \
                     (false negative)",
                    case.id
                );
            }

            // Soundness (stronger than decision, threshold-independent): if ANY rule
            // fired in the full path, the prefilter must NOT have skipped — proves
            // "prefilter miss ⟹ no rule matches" on every case (the corpus has
            // >=1 Triggers per rule, so every rule is exercised here).
            if !fo.matched_rules.is_empty() {
                assert!(
                    !fa.fastpath_skipped,
                    "UNSOUND prefilter: skipped {} @PL{pl} yet full fired {:?}",
                    case.id, fo.matched_rules
                );
            }

            // (7) where inspection actually ran, score + matched_rules are identical
            // (same code path) — full equivalence, not just the decision.
            if !fa.fastpath_skipped {
                assert_eq!(fo.score, fa.score, "score drift on {} @PL{pl}", case.id);
                assert_eq!(
                    fo.matched_rules, fa.matched_rules,
                    "matched_rules drift on {} @PL{pl}",
                    case.id
                );
            }
        }
    }
}

#[test]
fn prefilter_covers_all_active_content_rules() {
    // (8) Completeness guard: the union prefilter must cover EXACTLY the active
    // content rules of the per-module tables. If a rule is added to a module but
    // not reachable by `content_rules()`, the union would miss it → silent false
    // negative. Reconstructing the expected set from the same tables makes that
    // drift a loud failure instead of a security hole.
    use std::collections::BTreeSet;
    use waf_detection::{
        header_injection, ldap, lfi_rfi, mail, nosql, path_traversal, rce, scanner, sqli, ssi,
        ssrf, ssti, xss, xxe, ContentPrefilter,
    };

    for pl in [1u8, 2, 3, 4] {
        let mut expected: BTreeSet<&str> = BTreeSet::new();
        for table in [
            sqli::SQLI_RULES,
            xss::XSS_RULES,
            path_traversal::PATH_TRAVERSAL_RULES,
            rce::RCE_RULES,
            lfi_rfi::LFI_RFI_RULES,
            ssrf::SSRF_RULES,
            ldap::LDAP_RULES,
            nosql::NOSQL_RULES,
            mail::MAIL_RULES,
            ssti::SSTI_RULES,
            scanner::SCANNER_RULES,
            ssi::SSI_RULES,
            xxe::XXE_RULES,
        ] {
            for r in table.iter().filter(|r| r.paranoia <= pl) {
                expected.insert(r.id);
            }
        }
        for (id, _, par, _host_only) in header_injection::rule_meta() {
            if par <= pl {
                expected.insert(id);
            }
        }

        let got: BTreeSet<&str> =
            ContentPrefilter::new(pl).rule_ids().into_iter().collect();
        assert_eq!(
            got, expected,
            "prefilter rule set drifted from the module tables at PL{pl}"
        );
    }
}

#[test]
fn prefilter_host_bucket_matches_scope_source() {
    // (8, extended) Scope-correspondence: the host-only bucket must be EXACTLY the
    // rules with Scope::HostHeaders — derived from the real source
    // (`header_injection::rule_meta`), never by hand. A content rule landing in the
    // host bucket (scanned only against host headers) would be a silent false
    // negative; a host rule landing in main (scanned over the path) would re-open
    // the over-match. Either drift fails here.
    use std::collections::BTreeSet;
    use waf_detection::{header_injection, ContentPrefilter};

    for pl in [1u8, 2, 3, 4] {
        let expected_host: BTreeSet<&str> = header_injection::rule_meta()
            .into_iter()
            .filter(|(_, _, par, host_only)| *par <= pl && *host_only)
            .map(|(id, _, _, _)| id)
            .collect();
        let got_host: BTreeSet<&str> =
            ContentPrefilter::new(pl).host_rule_ids().iter().copied().collect();
        assert_eq!(
            got_host, expected_host,
            "host bucket drifted from Scope::HostHeaders at PL{pl}"
        );
    }
}

#[test]
fn fastpath_soundness_adversarial() {
    // Guardia soundness DECISIONE 4 — NON spostare nel corpus (i 79 restano
    // invariati). Due classi che un pre-check a CARATTERI sbaglierebbe, e che il
    // prefiltro-RegexSet-sul-canonico gestisce correttamente:
    //   1. keyword benigna senza metacaratteri — un char-check la marcherebbe
    //      eleggibile e SALTEREBBE un caso che il full-path blocca;
    //   2. payload ENCODED — un char-check sui byte grezzi non vedrebbe il `<`.
    let sev = RECOMMENDED_SEVERITY;
    let t = RECOMMENDED_THRESHOLD;

    let adversarial = [
        Case {
            id: "adv-keyword-union-select",
            module: Module::Sqli,
            field: Field::Query { name: "q", value: "trade union select committee" },
            min_pl: 1,
            expect: Expect::Triggers,
            rules: &["sqli-union-select"],
            desc: "keyword rule fires on plain alphanumerics (no metacharacters)",
        },
        Case {
            id: "adv-encoded-script",
            module: Module::Xss,
            field: Field::RawQuery("q=%3Cscript%3Ealert(1)%3C/script%3E"),
            min_pl: 1,
            expect: Expect::Triggers,
            rules: &["xss-script-tag"],
            desc: "encoded <script> only visible on the canonical surface",
        },
    ];

    for case in adversarial {
        let full = match run_case_with(&case, 3, sev) {
            RunResult::Ran(o) => o,
            RunResult::Skipped => panic!("{} skipped", case.id),
        };
        let fast = match run_case_fast(&case, 3, sev) {
            RunResult::Ran(o) => o,
            RunResult::Skipped => panic!("{} skipped", case.id),
        };
        assert!(
            !full.matched_rules.is_empty(),
            "{}: full-path must detect this",
            case.id
        );
        assert!(
            !fast.fastpath_skipped,
            "{}: prefilter WRONGLY skipped — a char pre-check would; the RegexSet must not",
            case.id
        );
        assert_eq!(
            decide(&full, t),
            decide(&fast, t),
            "{}: decision must be preserved",
            case.id
        );
    }
}
