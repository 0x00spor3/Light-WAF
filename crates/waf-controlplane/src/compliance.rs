// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Compliance evidence reports (§8). A period-scoped, **signed** bundle of evidence assembled from
//! data the system already holds — access control (governance), the tamper-evident audit log, and the
//! WAF telemetry — with each section annotated with the SOC2 / PCI-DSS controls it supports.
//!
//! Read-only, zero-core/zero-datapath: it only aggregates existing stores. The bundle embeds the
//! result of verifying the WHOLE audit chain and is itself **signed** (Ed25519, reusing the audit
//! signer) so the generated report is self-verifiable evidence. This module is PURE — the builder
//! takes already-queried inputs and the endpoint (C2) does the DB reads.

use serde::Serialize;
use time::OffsetDateTime;

use waf_governance::audit::{sha256_hex, verify_chain, verify_signature, AuditSigner};
use waf_governance::model::{AuditRecord, ServiceToken, User};

use crate::model::Alert;

/// Bundle schema version (bump on a breaking shape change).
const REPORT_VERSION: u32 = 1;
/// Cap on the audit sample embedded for spot-checking (the full chain is verified, not shipped).
const AUDIT_SAMPLE_CAP: usize = 50;

const CONTROLS_ACCESS: &[&str] =
    &["SOC2 CC6.1", "SOC2 CC6.2", "SOC2 CC6.3", "PCI 7.1", "PCI 7.2", "PCI 8.1", "PCI 8.2", "PCI 8.3"];
const CONTROLS_AUDIT: &[&str] = &["SOC2 CC7.2", "SOC2 CC7.3", "PCI 10.2", "PCI 10.3", "PCI 10.5"];
const CONTROLS_WAF: &[&str] = &["SOC2 CC7.1", "PCI 6.4.2", "PCI 11.5"];
const CONTROLS_ALERTS: &[&str] = &["SOC2 CC7.2", "SOC2 CC7.4", "PCI 10.6"];

/// The denied counts are period-accurate; allowed/total are cumulative counters (documented limit).
const WAF_CAVEAT: &str = "denied-event counts are period-accurate (each denied request is a timestamped \
row); allowed/total volumes are cumulative counter snapshots, not scoped to the period.";

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

// ── Bundle shape ───────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct Period {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthSourceCounts {
    pub local: i64,
    pub oidc: i64,
    pub other: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessControl {
    pub total_users: i64,
    pub admins: i64,
    pub disabled_accounts: i64,
    pub active_sessions: i64,
    pub auth_sources: AuthSourceCounts,
    pub users: Vec<User>,
    pub service_tokens: Vec<ServiceToken>,
    pub controls: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventCounts {
    pub total_in_period: i64,
    pub logins_success: i64,
    pub logins_failed: i64,
    pub throttled: i64,
    pub admin_actions: i64,
    pub rule_changes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditIntegrity {
    pub chain_ok: bool,
    /// The highest `seq` up to which the chain verified (0 if none / a break at the first record).
    pub verified_through_seq: i64,
    pub chain_head_hash: String,
    pub total_records: i64,
    pub break_reason: Option<String>,
    pub events_in_period: EventCounts,
    /// A capped sample of the period's audit records for spot-checking.
    pub sample: Vec<AuditRecord>,
    pub controls: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecisionCount {
    pub decision: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleCount {
    pub rule_id: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct WafEffectiveness {
    pub denied_in_period: Vec<DecisionCount>,
    pub top_rules: Vec<RuleCount>,
    pub nodes_covered: Vec<String>,
    pub cumulative_totals: Vec<DecisionCount>,
    pub caveat: &'static str,
    pub controls: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AlertsIncidents {
    pub total: i64,
    pub fired_alerts: Vec<Alert>,
    pub controls: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Sections {
    pub access_control: AccessControl,
    pub audit_integrity: AuditIntegrity,
    pub waf_effectiveness: WafEffectiveness,
    pub alerts_incidents: AlertsIncidents,
}

/// The unsigned report body — the exact thing that gets hashed + signed.
#[derive(Debug, Clone, Serialize)]
pub struct ReportBody {
    pub report_version: u32,
    pub period: Period,
    pub generated_at: String,
    pub generated_by: String,
    pub sections: Sections,
}

/// The signed bundle: the body plus its content hash + Ed25519 signature + the public key. The three
/// signing fields sit at the top level (flattened) alongside the body's fields.
#[derive(Debug, Clone, Serialize)]
pub struct SignedReport {
    #[serde(flatten)]
    pub body: ReportBody,
    pub content_hash: String,
    pub signature: String,
    pub public_key: String,
}

// ── Inputs (queried by the endpoint; the builder is pure) ────────────────────────────────────────

/// Everything the builder needs, already read from the stores.
pub struct ReportInputs {
    pub period_from: OffsetDateTime,
    pub period_to: OffsetDateTime,
    pub generated_at: OffsetDateTime,
    pub generated_by: String,
    pub audit_public_key: String,
    // Access control (current snapshots).
    pub users: Vec<User>,
    pub service_tokens: Vec<ServiceToken>,
    pub active_sessions: i64,
    // Audit.
    pub full_audit_chain: Vec<AuditRecord>, // ordered by ascending seq (for verify_chain)
    pub audit_in_period: Vec<AuditRecord>,
    // WAF telemetry.
    pub denied_counts: Vec<(String, i64)>,
    pub top_rules: Vec<(String, i64)>,
    pub nodes_covered: Vec<String>,
    pub cumulative_totals: Vec<(String, i64)>,
    // Alerts.
    pub alerts: Vec<Alert>,
}

fn categorize(records: &[AuditRecord]) -> EventCounts {
    let mut c = EventCounts {
        total_in_period: records.len() as i64,
        logins_success: 0,
        logins_failed: 0,
        throttled: 0,
        admin_actions: 0,
        rule_changes: 0,
    };
    for r in records {
        let a = r.action.as_str();
        if a == "login.success" || a == "login.sso" {
            c.logins_success += 1;
        } else if a == "login.failure" {
            c.logins_failed += 1;
        } else if a == "login.throttled" {
            c.throttled += 1;
        } else if a.starts_with("rule.") {
            c.rule_changes += 1;
        } else if a.starts_with("user.")
            || a.starts_with("token.")
            || a.starts_with("session.")
            || a.starts_with("password.")
        {
            c.admin_actions += 1;
        }
    }
    c
}

/// Assemble the (unsigned) report body from the queried inputs. Pure — no I/O.
pub fn build_report(inputs: &ReportInputs) -> ReportBody {
    // Access control snapshot.
    let admins = inputs.users.iter().filter(|u| u.role == waf_governance::rbac::Role::Admin).count() as i64;
    let disabled = inputs.users.iter().filter(|u| u.disabled).count() as i64;
    let mut auth = AuthSourceCounts { local: 0, oidc: 0, other: 0 };
    for u in &inputs.users {
        match u.auth_source.as_str() {
            "local" => auth.local += 1,
            "oidc" => auth.oidc += 1,
            _ => auth.other += 1,
        }
    }
    let access_control = AccessControl {
        total_users: inputs.users.len() as i64,
        admins,
        disabled_accounts: disabled,
        active_sessions: inputs.active_sessions,
        auth_sources: auth,
        users: inputs.users.clone(),
        service_tokens: inputs.service_tokens.clone(),
        controls: CONTROLS_ACCESS.to_vec(),
    };

    // Audit integrity: verify the WHOLE chain, report how far it holds.
    let chain = &inputs.full_audit_chain;
    let head_hash = chain.last().map(|r| r.hash.clone()).unwrap_or_default();
    let (chain_ok, verified_through_seq, break_reason) =
        match verify_chain(chain, &inputs.audit_public_key) {
            Ok(()) => (true, chain.last().map(|r| r.seq).unwrap_or(0), None),
            Err(brk) => {
                let through = if brk.index == 0 { 0 } else { chain[brk.index - 1].seq };
                (false, through, Some(brk.reason.to_string()))
            }
        };
    let mut sample = inputs.audit_in_period.clone();
    sample.truncate(AUDIT_SAMPLE_CAP);
    let audit_integrity = AuditIntegrity {
        chain_ok,
        verified_through_seq,
        chain_head_hash: head_hash,
        total_records: chain.len() as i64,
        break_reason,
        events_in_period: categorize(&inputs.audit_in_period),
        sample,
        controls: CONTROLS_AUDIT.to_vec(),
    };

    // WAF effectiveness.
    let to_counts = |v: &[(String, i64)]| {
        v.iter().map(|(decision, count)| DecisionCount { decision: decision.clone(), count: *count }).collect()
    };
    let waf_effectiveness = WafEffectiveness {
        denied_in_period: to_counts(&inputs.denied_counts),
        top_rules: inputs
            .top_rules
            .iter()
            .map(|(rule_id, count)| RuleCount { rule_id: rule_id.clone(), count: *count })
            .collect(),
        nodes_covered: inputs.nodes_covered.clone(),
        cumulative_totals: to_counts(&inputs.cumulative_totals),
        caveat: WAF_CAVEAT,
        controls: CONTROLS_WAF.to_vec(),
    };

    let alerts_incidents = AlertsIncidents {
        total: inputs.alerts.len() as i64,
        fired_alerts: inputs.alerts.clone(),
        controls: CONTROLS_ALERTS.to_vec(),
    };

    ReportBody {
        report_version: REPORT_VERSION,
        period: Period { from: rfc3339(inputs.period_from), to: rfc3339(inputs.period_to) },
        generated_at: rfc3339(inputs.generated_at),
        generated_by: inputs.generated_by.clone(),
        sections: Sections { access_control, audit_integrity, waf_effectiveness, alerts_incidents },
    }
}

/// The content hash over a report body: SHA-256 of its canonical JSON. Canonical = serialized via
/// `serde_json::Value` (object keys sorted — serde_json's default `Map` is a `BTreeMap`), so the
/// digest is order-independent and reproducible from the posted bundle (see [`verify_report_value`]).
fn content_hash_of_body(body: &ReportBody) -> String {
    let value = serde_json::to_value(body).unwrap_or(serde_json::Value::Null);
    sha256_hex(&serde_json::to_vec(&value).unwrap_or_default())
}

/// Sign a report body: attach its content hash, the Ed25519 signature over that hash, and the public
/// key (reusing the audit signer / trust anchor).
pub fn sign_report(body: ReportBody, signer: &AuditSigner) -> SignedReport {
    let content_hash = content_hash_of_body(&body);
    let signature = signer.sign_hash(&content_hash);
    let public_key = signer.public_key_hex().to_string();
    SignedReport { body, content_hash, signature, public_key }
}

/// Verify a posted bundle (as JSON): recompute the content hash over the body (everything except the
/// three signing fields) and check it matches, then verify the signature under the bundle's public
/// key. Order-independent (both sides canonicalize object keys), so it survives a JSON round-trip.
pub fn verify_report_value(bundle: &serde_json::Value) -> bool {
    let (Some(content_hash), Some(signature), Some(public_key)) = (
        bundle.get("content_hash").and_then(|v| v.as_str()),
        bundle.get("signature").and_then(|v| v.as_str()),
        bundle.get("public_key").and_then(|v| v.as_str()),
    ) else {
        return false;
    };
    let mut body = bundle.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("content_hash");
        obj.remove("signature");
        obj.remove("public_key");
    } else {
        return false;
    }
    let recomputed = sha256_hex(&serde_json::to_vec(&body).unwrap_or_default());
    recomputed == content_hash && verify_signature(public_key, content_hash, signature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_governance::audit::{compute_hash, ts_micros, GENESIS_PREV};
    use waf_governance::rbac::Role;

    const SEED: &str = "0404040404040404040404040404040404040404040404040404040404040404";

    fn audit_rec(signer: &AuditSigner, seq: i64, prev: &str, action: &str) -> AuditRecord {
        let ts = OffsetDateTime::from_unix_timestamp(1_700_000_000 + seq).unwrap();
        let details = "{}".to_string();
        let hash = compute_hash(seq, ts_micros(ts), "admin", action, None, &details, prev);
        let signature = signer.sign_hash(&hash);
        AuditRecord {
            seq,
            ts,
            actor: "admin".into(),
            action: action.into(),
            target: None,
            details,
            prev_hash: prev.into(),
            hash,
            signature,
        }
    }

    fn chain(signer: &AuditSigner, actions: &[&str]) -> Vec<AuditRecord> {
        let mut out = Vec::new();
        let mut prev = GENESIS_PREV.to_string();
        for (i, a) in actions.iter().enumerate() {
            let r = audit_rec(signer, i as i64 + 1, &prev, a);
            prev = r.hash.clone();
            out.push(r);
        }
        out
    }

    fn user(id: i64, role: Role, source: &str, disabled: bool) -> User {
        User {
            id,
            username: format!("u{id}"),
            role,
            disabled,
            auth_source: source.into(),
            created_at: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        }
    }

    fn sample_inputs(signer: &AuditSigner, records: Vec<AuditRecord>) -> ReportInputs {
        let now = OffsetDateTime::from_unix_timestamp(1_700_100_000).unwrap();
        ReportInputs {
            period_from: now - time::Duration::days(90),
            period_to: now,
            generated_at: now,
            generated_by: "admin".into(),
            audit_public_key: signer.public_key_hex().to_string(),
            users: vec![
                user(1, Role::Admin, "local", false),
                user(2, Role::Viewer, "oidc", false),
                user(3, Role::Operator, "local", true),
            ],
            service_tokens: vec![],
            active_sessions: 2,
            audit_in_period: records.clone(),
            full_audit_chain: records,
            denied_counts: vec![("blocked".into(), 12), ("rejected".into(), 3)],
            top_rules: vec![("sqli".into(), 9), ("xss".into(), 6)],
            nodes_covered: vec!["edge-1".into(), "edge-2".into()],
            cumulative_totals: vec![("allowed".into(), 1000), ("blocked".into(), 15)],
            alerts: vec![],
        }
    }

    #[test]
    fn builds_and_signs_and_verifies() {
        let signer = AuditSigner::from_hex_seed(SEED).unwrap();
        let records = chain(&signer, &["login.success", "user.create", "rule.publish", "login.failure"]);
        let body = build_report(&sample_inputs(&signer, records));

        // Access control counts.
        assert_eq!(body.sections.access_control.total_users, 3);
        assert_eq!(body.sections.access_control.admins, 1);
        assert_eq!(body.sections.access_control.disabled_accounts, 1);
        assert_eq!(body.sections.access_control.auth_sources.local, 2);
        assert_eq!(body.sections.access_control.auth_sources.oidc, 1);

        // Audit integrity: full chain verifies; events categorized.
        let ai = &body.sections.audit_integrity;
        assert!(ai.chain_ok);
        assert_eq!(ai.verified_through_seq, 4);
        assert_eq!(ai.total_records, 4);
        assert_eq!(ai.events_in_period.logins_success, 1);
        assert_eq!(ai.events_in_period.logins_failed, 1);
        assert_eq!(ai.events_in_period.admin_actions, 1); // user.create
        assert_eq!(ai.events_in_period.rule_changes, 1); // rule.publish

        // Sign → verify round-trips through JSON.
        let signed = sign_report(body, &signer);
        let bundle = serde_json::to_value(&signed).unwrap();
        assert!(verify_report_value(&bundle), "freshly signed bundle must verify");
    }

    #[test]
    fn tampering_the_body_breaks_verification() {
        let signer = AuditSigner::from_hex_seed(SEED).unwrap();
        let records = chain(&signer, &["login.success"]);
        let signed = sign_report(build_report(&sample_inputs(&signer, records)), &signer);
        let mut bundle = serde_json::to_value(&signed).unwrap();

        // Alter a body field WITHOUT re-signing → content hash no longer matches.
        bundle["generated_by"] = serde_json::json!("attacker");
        assert!(!verify_report_value(&bundle), "a mutated body must fail verification");

        // Alter the signature alone → signature check fails.
        let mut b2 = serde_json::to_value(sign_report(
            build_report(&sample_inputs(&signer, chain(&signer, &["login.success"]))),
            &signer,
        ))
        .unwrap();
        b2["signature"] = serde_json::json!("00");
        assert!(!verify_report_value(&b2));
    }

    #[test]
    fn a_broken_audit_chain_is_reported_not_fatal() {
        let signer = AuditSigner::from_hex_seed(SEED).unwrap();
        let mut records = chain(&signer, &["login.success", "user.create", "rule.publish"]);
        // Tamper the middle record's details without re-hashing → break at seq 2.
        records[1].details = "{\"tampered\":true}".into();
        let body = build_report(&sample_inputs(&signer, records));
        let ai = &body.sections.audit_integrity;
        assert!(!ai.chain_ok);
        assert_eq!(ai.verified_through_seq, 1, "only seq 1 verified before the break");
        assert!(ai.break_reason.is_some());

        // The report still signs + verifies (the BUNDLE integrity is independent of the audit chain).
        let signed = sign_report(body, &signer);
        assert!(verify_report_value(&serde_json::to_value(&signed).unwrap()));
    }

    #[test]
    fn content_hash_is_deterministic() {
        let signer = AuditSigner::from_hex_seed(SEED).unwrap();
        let records = chain(&signer, &["login.success"]);
        let a = content_hash_of_body(&build_report(&sample_inputs(&signer, records.clone())));
        let b = content_hash_of_body(&build_report(&sample_inputs(&signer, records)));
        assert_eq!(a, b, "same inputs must hash identically");
    }
}
