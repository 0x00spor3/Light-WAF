// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! SIEM export (§9): normalize the control plane's stored events into a versioned, **ECS-like** event
//! and serialize a batch for a sink. This module is PURE (mapping + framing); the forwarder (cursor,
//! retry, batching, delivery) is in `siem_forward` (S2).
//!
//! ECS-like, NOT ECS-compliant: standard ECS field names where the mapping is obvious (`@timestamp`,
//! `event.*`, `source.ip`, `http.*`, `url.*`, `user.name`), with the WAF domain under a `waf.*`
//! namespace. The schema carries its own `version` — we promise OUR schema, not conformance to an
//! external one that evolves. `SiemFormatter` is an abstraction from day one so CEF/LEEF/syslog and
//! vendor adapters can be added as variants WITHOUT touching the forwarder.

use serde::Serialize;
use time::OffsetDateTime;

use waf_governance::model::AuditRecord;

use crate::model::{Alert, Contribution, DecisionEvent};

/// The normalized event schema version (bump on a breaking shape change).
pub const SIEM_SCHEMA_VERSION: u32 = 1;

const OBSERVER_VENDOR: &str = "Light WAF";
const OBSERVER_PRODUCT: &str = "waf";

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()
}

// ── Normalized event (ECS-like) ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct EventFields {
    pub kind: &'static str,
    pub category: Vec<&'static str>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<&'static str>,
    /// A STABLE id the SIEM dedups on (`waf-<stream>-<id>`) — the key to at-least-once safety.
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Source {
    pub ip: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HttpRequest {
    pub method: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Http {
    pub request: HttpRequest,
}

#[derive(Debug, Clone, Serialize)]
pub struct Url {
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleField {
    pub id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserField {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Observer {
    pub vendor: &'static str,
    pub product: &'static str,
    pub version: &'static str,
}

fn observer() -> Observer {
    Observer { vendor: OBSERVER_VENDOR, product: OBSERVER_PRODUCT, version: env!("CARGO_PKG_VERSION") }
}

#[derive(Debug, Clone, Serialize)]
pub struct WafScore {
    pub total: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct WafContribution {
    pub module: String,
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub points: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct WafAudit {
    pub seq: i64,
    pub hash: String,
    pub signature: String,
    pub prev_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WafAlert {
    pub rule: String,
    pub group: String,
    pub value: i64,
    pub threshold: i64,
    pub severity: String,
}

/// The `waf.*` domain namespace — only the sub-objects relevant to the event kind are present.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Waf {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<WafScore>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contributions: Vec<WafContribution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit: Option<WafAudit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert: Option<WafAlert>,
}

/// One normalized SIEM event.
#[derive(Debug, Clone, Serialize)]
pub struct SiemEvent {
    pub version: u32,
    #[serde(rename = "@timestamp")]
    pub timestamp: String,
    pub event: EventFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<Http>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserField>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    pub observer: Observer,
    pub waf: Waf,
}

// ── Mappers (pure) ──────────────────────────────────────────────────────────────────────────────

/// A denied WAF verdict → an intrusion-detection event. `id` is the `decision_events.id`.
pub fn decision_to_siem(id: i64, ev: &DecisionEvent) -> SiemEvent {
    let outcome = Some("failure"); // a denied request is a failed (blocked) outcome from the client's view
    SiemEvent {
        version: SIEM_SCHEMA_VERSION,
        timestamp: rfc3339(ev.ts),
        event: EventFields {
            kind: "alert",
            category: vec!["network", "intrusion_detection"],
            action: ev.decision.clone(),
            outcome,
            id: format!("waf-decision-{id}"),
        },
        source: ev.client_ip.clone().map(|ip| Source { ip }),
        http: ev.method.clone().map(|method| Http { request: HttpRequest { method } }),
        url: ev.path.clone().map(|path| Url { path }),
        rule: ev.rule_id.clone().map(|id| RuleField { id }),
        user: None,
        message: ev.reason.clone(),
        observer: observer(),
        waf: Waf {
            node: Some(ev.node.clone()),
            score: Some(WafScore { total: ev.score }),
            contributions: ev.contributions.iter().map(contribution).collect(),
            audit: None,
            alert: None,
        },
    }
}

fn contribution(c: &Contribution) -> WafContribution {
    WafContribution {
        module: c.module.clone(),
        rule_id: c.rule_id.clone(),
        severity: c.severity.clone(),
        points: c.points,
    }
}

/// A signed governance audit action → an IAM/configuration event. `id` is the `gov_audit_log.seq`.
pub fn audit_to_siem(rec: &AuditRecord) -> SiemEvent {
    SiemEvent {
        version: SIEM_SCHEMA_VERSION,
        timestamp: rfc3339(rec.ts),
        event: EventFields {
            kind: "event",
            category: vec!["iam", "configuration"],
            action: rec.action.clone(),
            outcome: None,
            id: format!("waf-audit-{}", rec.seq),
        },
        source: None,
        http: None,
        url: None,
        rule: None,
        user: Some(UserField { name: rec.actor.clone() }),
        message: rec.target.clone(),
        observer: observer(),
        waf: Waf {
            audit: Some(WafAudit {
                seq: rec.seq,
                hash: rec.hash.clone(),
                signature: rec.signature.clone(),
                prev_hash: rec.prev_hash.clone(),
            }),
            ..Waf::default()
        },
    }
}

/// A fired alert → an alert event. `id` is the `alerts.id`.
pub fn alert_to_siem(id: i64, a: &Alert) -> SiemEvent {
    SiemEvent {
        version: SIEM_SCHEMA_VERSION,
        timestamp: rfc3339(a.fired_at),
        event: EventFields {
            kind: "alert",
            category: vec!["intrusion_detection"],
            action: a.rule_name.clone(),
            outcome: None,
            id: format!("waf-alert-{id}"),
        },
        source: (!a.group_key.is_empty()).then(|| Source { ip: a.group_key.clone() }),
        http: None,
        url: None,
        rule: Some(RuleField { id: a.rule_name.clone() }),
        user: None,
        message: (!a.summary.is_empty()).then(|| a.summary.clone()),
        observer: observer(),
        waf: Waf {
            alert: Some(WafAlert {
                rule: a.rule_name.clone(),
                group: a.group_key.clone(),
                value: a.value,
                threshold: a.threshold,
                severity: a.severity.clone(),
            }),
            ..Waf::default()
        },
    }
}

// ── Formatter (abstract from day one) ───────────────────────────────────────────────────────────

/// Serialize a batch of normalized events into the bytes a destination ingests. v1 = ECS-like NDJSON;
/// CEF/LEEF/syslog live as sibling implementations over the SAME `SiemEvent`, never touching the forwarder.
pub trait SiemFormatter {
    fn content_type(&self) -> &'static str;
    fn format_batch(&self, events: &[SiemEvent]) -> Vec<u8>;
}

/// One JSON event per line (`application/x-ndjson`) — what Splunk HEC / Elastic bulk / collectors want.
pub struct EcsNdjsonFormatter;

impl SiemFormatter for EcsNdjsonFormatter {
    fn content_type(&self) -> &'static str {
        "application/x-ndjson"
    }
    fn format_batch(&self, events: &[SiemEvent]) -> Vec<u8> {
        let mut out = Vec::new();
        for ev in events {
            // A serialization failure on this plain data is not realistic; skip a bad line rather
            // than poison the whole batch.
            if let Ok(line) = serde_json::to_vec(ev) {
                out.extend_from_slice(&line);
                out.push(b'\n');
            }
        }
        out
    }
}

/// The formatter for a configured format (v1: only ECS).
pub fn formatter_for(format: crate::config::SiemFormat) -> Box<dyn SiemFormatter + Send + Sync> {
    match format {
        crate::config::SiemFormat::Ecs => Box::new(EcsNdjsonFormatter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(rid: &str) -> DecisionEvent {
        DecisionEvent {
            request_id: rid.into(),
            ts: OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
            node: "edge-1".into(),
            method: Some("GET".into()),
            path: Some("/x".into()),
            client_ip: Some("203.0.113.7".into()),
            decision: "blocked".into(),
            rule_id: Some("sqli-union".into()),
            reason: Some("anomaly score exceeded".into()),
            score: 6,
            contributions: vec![Contribution {
                module: "sqli".into(),
                rule_id: "sqli-union".into(),
                severity: Some("critical".into()),
                points: 6,
            }],
        }
    }

    #[test]
    fn decision_maps_to_ecs_like_event() {
        let ev = decision_to_siem(42, &decision("r1"));
        assert_eq!(ev.version, SIEM_SCHEMA_VERSION);
        assert_eq!(ev.event.id, "waf-decision-42");
        assert_eq!(ev.event.action, "blocked");
        assert_eq!(ev.event.category, vec!["network", "intrusion_detection"]);
        assert_eq!(ev.source.as_ref().unwrap().ip, "203.0.113.7");
        assert_eq!(ev.http.as_ref().unwrap().request.method, "GET");
        assert_eq!(ev.url.as_ref().unwrap().path, "/x");
        assert_eq!(ev.rule.as_ref().unwrap().id, "sqli-union");
        assert_eq!(ev.waf.score.as_ref().unwrap().total, 6);
        assert_eq!(ev.waf.contributions.len(), 1);
        assert_eq!(ev.waf.node.as_deref(), Some("edge-1"));

        // JSON uses the ECS field names + our version + waf namespace.
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert!(!v["@timestamp"].as_str().unwrap().is_empty());
        assert_eq!(v["event"]["id"], "waf-decision-42");
        assert_eq!(v["source"]["ip"], "203.0.113.7");
        assert_eq!(v["http"]["request"]["method"], "GET");
        assert_eq!(v["waf"]["score"]["total"], 6);
        assert_eq!(v["version"], 1);
    }

    #[test]
    fn audit_maps_with_signature_and_no_http() {
        let rec = AuditRecord {
            seq: 7,
            ts: OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap(),
            actor: "admin".into(),
            action: "rule.publish".into(),
            target: Some("v3".into()),
            details: "{}".into(),
            prev_hash: "aa".into(),
            hash: "bb".into(),
            signature: "cc".into(),
        };
        let ev = audit_to_siem(&rec);
        assert_eq!(ev.event.id, "waf-audit-7");
        assert_eq!(ev.event.category, vec!["iam", "configuration"]);
        assert_eq!(ev.user.as_ref().unwrap().name, "admin");
        assert!(ev.http.is_none() && ev.source.is_none());
        let a = ev.waf.audit.as_ref().unwrap();
        assert_eq!(a.seq, 7);
        assert_eq!(a.signature, "cc");
    }

    #[test]
    fn alert_maps_to_alert_event() {
        let a = Alert {
            rule_name: "block-burst".into(),
            group_key: "5.5.5.5".into(),
            fired_at: OffsetDateTime::from_unix_timestamp(1_700_000_200).unwrap(),
            severity: "critical".into(),
            value: 30,
            threshold: 20,
            summary: "burst".into(),
        };
        let ev = alert_to_siem(9, &a);
        assert_eq!(ev.event.id, "waf-alert-9");
        assert_eq!(ev.event.kind, "alert");
        assert_eq!(ev.source.as_ref().unwrap().ip, "5.5.5.5");
        let al = ev.waf.alert.as_ref().unwrap();
        assert_eq!(al.value, 30);
        assert_eq!(al.threshold, 20);
    }

    #[test]
    fn ndjson_frames_one_event_per_line() {
        let batch = vec![decision_to_siem(1, &decision("a")), decision_to_siem(2, &decision("b"))];
        let bytes = EcsNdjsonFormatter.format_batch(&batch);
        let text = String::from_utf8(bytes).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON object per line");
        // Each line is a standalone JSON object.
        for l in lines {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            assert_eq!(v["version"], 1);
        }
        assert!(text.ends_with('\n'), "NDJSON is newline-terminated");
        assert_eq!(EcsNdjsonFormatter.content_type(), "application/x-ndjson");
    }
}
