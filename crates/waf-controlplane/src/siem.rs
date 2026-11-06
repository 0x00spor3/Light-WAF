// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! SIEM export (§9): normalize the control plane's stored events into a versioned, **ECS-like** event
//! and serialize a batch for a sink. This module is PURE (mapping + framing); the forwarder (cursor,
//! retry, batching, delivery) is in `siem_forward` (S2).
//!
//! ECS-like, NOT ECS-compliant: standard ECS field names where the mapping is obvious (`@timestamp`,
//! `event.*`, `source.ip`, `http.*`, `url.*`, `user.name`), with the WAF domain under a `waf.*`
//! namespace. The schema carries its own `version` — we promise OUR schema, not conformance to an
//! external one that evolves. `SiemFormatter` is an abstraction from day one so CEF (below), LEEF and
//! vendor adapters can be added as variants WITHOUT touching the forwarder.

use std::net::IpAddr;

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use waf_governance::model::AuditRecord;

use crate::model::{Alert, Contribution, DecisionEvent};

/// The normalized event schema version (bump on a breaking shape change).
pub const SIEM_SCHEMA_VERSION: u32 = 1;

const OBSERVER_VENDOR: &str = "Light WAF";
const OBSERVER_PRODUCT: &str = "waf";

fn rfc3339(ts: OffsetDateTime) -> String {
    ts.format(&Rfc3339).unwrap_or_default()
}

/// `source.ip` is an address or absent: an alert's group key can be a rule id or empty, and sinks
/// type this field as an IP.
fn source_ip(value: &str) -> Option<Source> {
    value.parse::<IpAddr>().is_ok().then(|| Source { ip: value.to_string() })
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
        source: ev.client_ip.as_deref().and_then(source_ip),
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
        source: source_ip(&a.group_key),
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

/// Serialize a batch of normalized events into the bytes a destination ingests: ECS-like NDJSON or
/// CEF. LEEF and vendor adapters live as sibling implementations over the SAME `SiemEvent`, never
/// touching the forwarder.
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

// Value limits from the CEF Implementation Standard (v27).
const CEF_MAX_ACT: usize = 63;
const CEF_MAX_DVCHOST: usize = 100;
const CEF_MAX_EXTERNAL_ID: usize = 40;
const CEF_MAX_OUTCOME: usize = 63;
const CEF_MAX_STRING: usize = 1023;
const CEF_MAX_CUSTOM_STRING: usize = 4000;
const CEF_MAX_SIGNATURE: usize = 1023;

/// Audit records carry no severity of their own.
const CEF_AUDIT_SEVERITY: u8 = 3;

/// A header field: `\` and `|` are escaped; newlines are not allowed there at all.
fn cef_header(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '|' => out.push_str("\\|"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// An extension value. Events are one per line and paths come from the client, so a raw newline
/// here would let a request forge an event: it is always encoded.
fn cef_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '=' => out.push_str("\\="),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if c.is_control() => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

/// Clip to `max` characters. Done BEFORE escaping, so a cut never lands inside an escape sequence.
fn cef_clip(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn cef_severity_of(label: &str) -> u8 {
    match label.to_ascii_lowercase().as_str() {
        "critical" => 9,
        "error" => 7,
        "warning" => 5,
        "notice" => 3,
        _ => 0, // CEF's Unknown: alert severities are free text, and not every denial has one.
    }
}

fn cef_severity(ev: &SiemEvent) -> u8 {
    if let Some(alert) = &ev.waf.alert {
        return cef_severity_of(&alert.severity);
    }
    if ev.waf.audit.is_some() {
        return CEF_AUDIT_SEVERITY;
    }
    let contributions = ev.waf.contributions.iter().filter_map(|c| c.severity.as_deref());
    contributions.map(cef_severity_of).max().unwrap_or(0)
}

/// The stable signature id. Prefixed so an alert and a WAF rule sharing a name stay distinct.
fn cef_signature(ev: &SiemEvent) -> String {
    if let Some(alert) = &ev.waf.alert {
        format!("alert-{}", alert.rule)
    } else if ev.waf.audit.is_some() {
        format!("audit-{}", ev.event.action)
    } else {
        ev.rule.as_ref().map_or_else(|| format!("decision-{}", ev.event.action), |r| r.id.clone())
    }
}

/// The header name: a fixed set, so it stays low-cardinality and free of request data.
fn cef_name(ev: &SiemEvent) -> &'static str {
    if ev.waf.alert.is_some() {
        "Alert fired"
    } else if ev.waf.audit.is_some() {
        "Audit event"
    } else if ev.event.action == "blocked" {
        "Request blocked"
    } else if ev.event.action == "rejected" {
        "Request rejected"
    } else {
        "Request denied"
    }
}

fn cef_line(ev: &SiemEvent) -> String {
    let mut ext = Vec::new();
    let mut put = |key: &str, value: &str, max: usize| {
        ext.push(format!("{key}={}", cef_value(&cef_clip(value, max))));
    };

    put("externalId", &ev.event.id, CEF_MAX_EXTERNAL_ID);
    // `rt` takes epoch milliseconds or a fixed list of patterns; RFC 3339 is not one of them.
    if let Ok(ts) = OffsetDateTime::parse(&ev.timestamp, &Rfc3339) {
        let millis = ts.unix_timestamp_nanos() / 1_000_000;
        put("rt", &millis.to_string(), CEF_MAX_STRING);
    }
    put("act", &ev.event.action, CEF_MAX_ACT);
    put("cat", &ev.event.category.join(","), CEF_MAX_STRING);
    if let Some(outcome) = ev.event.outcome {
        put("outcome", outcome, CEF_MAX_OUTCOME);
    }
    if let Some(source) = &ev.source {
        put("src", &source.ip, CEF_MAX_STRING);
    }
    if let Some(http) = &ev.http {
        put("requestMethod", &http.request.method, CEF_MAX_STRING);
    }
    if let Some(url) = &ev.url {
        put("request", &url.path, CEF_MAX_STRING);
    }
    if let Some(user) = &ev.user {
        put("suser", &user.name, CEF_MAX_STRING);
    }
    if let Some(message) = &ev.message {
        put("msg", message, CEF_MAX_STRING);
    }
    if let Some(node) = &ev.waf.node {
        put("dvchost", node, CEF_MAX_DVCHOST);
    }
    if let Some(score) = &ev.waf.score {
        put("cn1", &score.total.to_string(), CEF_MAX_STRING);
        put("cn1Label", "score", CEF_MAX_STRING);
    }
    if !ev.waf.contributions.is_empty() {
        let contributions: Vec<String> = ev
            .waf
            .contributions
            .iter()
            .map(|c| format!("{}:{}:{}", c.module, c.rule_id, c.points))
            .collect();
        put("cs1", &contributions.join(","), CEF_MAX_CUSTOM_STRING);
        put("cs1Label", "contributions", CEF_MAX_STRING);
    }
    if let Some(alert) = &ev.waf.alert {
        put("cn1", &alert.value.to_string(), CEF_MAX_STRING);
        put("cn1Label", "value", CEF_MAX_STRING);
        put("cn2", &alert.threshold.to_string(), CEF_MAX_STRING);
        put("cn2Label", "threshold", CEF_MAX_STRING);
        if !alert.group.is_empty() {
            put("cs1", &alert.group, CEF_MAX_CUSTOM_STRING);
            put("cs1Label", "group", CEF_MAX_STRING);
        }
    }
    if let Some(audit) = &ev.waf.audit {
        put("cn1", &audit.seq.to_string(), CEF_MAX_STRING);
        put("cn1Label", "auditSeq", CEF_MAX_STRING);
        put("cs1", &audit.hash, CEF_MAX_CUSTOM_STRING);
        put("cs1Label", "auditHash", CEF_MAX_STRING);
        put("cs2", &audit.signature, CEF_MAX_CUSTOM_STRING);
        put("cs2Label", "auditSignature", CEF_MAX_STRING);
        put("cs3", &audit.prev_hash, CEF_MAX_CUSTOM_STRING);
        put("cs3Label", "auditPrevHash", CEF_MAX_STRING);
    }

    format!(
        "CEF:0|{}|{}|{}|{}|{}|{}|{}",
        cef_header(ev.observer.vendor),
        cef_header(ev.observer.product),
        cef_header(ev.observer.version),
        cef_header(&cef_clip(&cef_signature(ev), CEF_MAX_SIGNATURE)),
        cef_name(ev),
        cef_severity(ev),
        ext.join(" "),
    )
}

/// One CEF event per line, with no syslog prefix: the output is still POSTed over HTTP, and SIEMs
/// take CEF over syslog, so a collector goes in between (RUNBOOK §L).
pub struct CefFormatter;

impl SiemFormatter for CefFormatter {
    fn content_type(&self) -> &'static str {
        "text/plain; charset=utf-8"
    }
    fn format_batch(&self, events: &[SiemEvent]) -> Vec<u8> {
        let mut out = Vec::new();
        for ev in events {
            out.extend_from_slice(cef_line(ev).as_bytes());
            out.push(b'\n');
        }
        out
    }
}

/// The formatter for a configured format.
pub fn formatter_for(format: crate::config::SiemFormat) -> Box<dyn SiemFormatter + Send + Sync> {
    match format {
        crate::config::SiemFormat::Ecs => Box::new(EcsNdjsonFormatter),
        crate::config::SiemFormat::Cef => Box::new(CefFormatter),
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

    fn alert(group_key: &str, severity: &str) -> Alert {
        Alert {
            rule_name: "block-burst".into(),
            group_key: group_key.into(),
            fired_at: OffsetDateTime::from_unix_timestamp(1_700_000_200).unwrap(),
            severity: severity.into(),
            value: 30,
            threshold: 20,
            summary: "burst".into(),
        }
    }

    fn audit_record() -> AuditRecord {
        AuditRecord {
            seq: 7,
            ts: OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap(),
            actor: "admin".into(),
            action: "rule.publish".into(),
            target: Some("v3".into()),
            details: "{}".into(),
            prev_hash: "aa".into(),
            hash: "bb".into(),
            signature: "cc".into(),
        }
    }

    fn header_field(line: &str, index: usize) -> &str {
        line.split('|').nth(index).unwrap()
    }

    #[test]
    fn source_ip_is_only_ever_an_address() {
        assert_eq!(alert_to_siem(1, &alert("5.5.5.5", "critical")).source.unwrap().ip, "5.5.5.5");
        assert_eq!(alert_to_siem(1, &alert("2001:db8::1", "critical")).source.unwrap().ip, "2001:db8::1");

        // group_by = "rule_id" / "none": the group stays in waf.alert.group, not in source.ip.
        let by_rule = alert_to_siem(1, &alert("sqli-union", "critical"));
        assert!(by_rule.source.is_none());
        assert_eq!(by_rule.waf.alert.unwrap().group, "sqli-union");
        assert!(alert_to_siem(1, &alert("", "critical")).source.is_none());

        let mut ev = decision("r");
        ev.client_ip = Some("not-an-ip".into());
        assert!(decision_to_siem(1, &ev).source.is_none());
    }

    #[test]
    fn cef_decision_line() {
        let line = cef_line(&decision_to_siem(42, &decision("r1")));
        let version = env!("CARGO_PKG_VERSION");
        assert_eq!(
            line,
            format!(
                "CEF:0|Light WAF|waf|{version}|sqli-union|Request blocked|9|externalId=waf-decision-42 \
                 rt=1700000000000 act=blocked cat=network,intrusion_detection outcome=failure \
                 src=203.0.113.7 requestMethod=GET request=/x msg=anomaly score exceeded dvchost=edge-1 \
                 cn1=6 cn1Label=score cs1=sqli:sqli-union:6 cs1Label=contributions"
            )
        );
    }

    #[test]
    fn cef_alert_line_carries_the_group_and_counts() {
        let line = cef_line(&alert_to_siem(9, &alert("sqli-union", "warning")));
        assert_eq!(header_field(&line, 4), "alert-block-burst");
        assert_eq!(header_field(&line, 5), "Alert fired");
        assert_eq!(header_field(&line, 6), "5");
        assert!(line.contains("externalId=waf-alert-9 rt=1700000200000 "));
        assert!(line.contains("cn1=30 cn1Label=value cn2=20 cn2Label=threshold cs1=sqli-union cs1Label=group"));
        assert!(!line.contains("src="), "a rule id is not an address: {line}");
    }

    #[test]
    fn cef_audit_line_carries_the_signature() {
        let line = cef_line(&audit_to_siem(&audit_record()));
        assert_eq!(header_field(&line, 4), "audit-rule.publish");
        assert_eq!(header_field(&line, 5), "Audit event");
        assert_eq!(header_field(&line, 6), "3");
        assert!(line.contains("externalId=waf-audit-7 "));
        assert!(line.contains("suser=admin msg=v3 cn1=7 cn1Label=auditSeq"));
        assert!(line.contains("cs1=bb cs1Label=auditHash cs2=cc cs2Label=auditSignature cs3=aa cs3Label=auditPrevHash"));
    }

    #[test]
    fn cef_severity_mapping() {
        for (label, want) in
            [("critical", 9), ("CRITICAL", 9), ("error", 7), ("warning", 5), ("notice", 3), ("whatever", 0), ("", 0)]
        {
            assert_eq!(cef_severity(&alert_to_siem(1, &alert("", label))), want, "{label:?}");
        }

        // A decision takes its highest contribution, and Unknown when it has none.
        let mut ev = decision("r");
        ev.contributions.insert(
            0,
            Contribution { module: "m".into(), rule_id: "r".into(), severity: Some("notice".into()), points: 1 },
        );
        assert_eq!(cef_severity(&decision_to_siem(1, &ev)), 9);
        ev.contributions.clear();
        assert_eq!(cef_severity(&decision_to_siem(1, &ev)), 0);
    }

    #[test]
    fn cef_signature_falls_back_to_the_decision_kind() {
        let mut ev = decision("r");
        ev.rule_id = None;
        ev.decision = "rejected".into();
        let line = cef_line(&decision_to_siem(1, &ev));
        assert_eq!(header_field(&line, 4), "decision-rejected");
        assert_eq!(header_field(&line, 5), "Request rejected");
    }

    #[test]
    fn cef_header_escaping() {
        assert_eq!(cef_header(r"a|b\c"), r"a\|b\\c");
        assert_eq!(cef_header("a=b"), "a=b", "equals needs no escape in the header");
        assert_eq!(cef_header("a\nb\rc\td\0e"), "a b c d e", "no newlines in the header");
        // Backslash first: the `\` added for the pipe must not be doubled.
        assert_eq!(cef_header(r"\|"), r"\\\|");
    }

    #[test]
    fn cef_extension_escaping() {
        assert_eq!(cef_value(r"a=b\c"), r"a\=b\\c");
        assert_eq!(cef_value("a|b"), "a|b", "pipes need no escape in the extension");
        assert_eq!(cef_value("a\nb\rc"), r"a\nb\rc");
        assert_eq!(cef_value("a\tb\0c"), "a b c");
        // A literal backslash-n is not a newline: it must survive as two characters.
        assert_eq!(cef_value(r"a\nb"), r"a\\nb");
    }

    #[test]
    fn cef_hostile_fields_cannot_forge_an_event_or_a_key() {
        let mut ev = decision("r");
        ev.rule_id = Some("x|Evil|10|src=6.6.6.6\nCEF:0|forged".into());
        ev.path = Some("/a\r\nCEF:0|forged|waf|1|x|y|10|src=6.6.6.6".into());
        ev.reason = Some("ok suser=root".into());

        let bytes = CefFormatter.format_batch(&[decision_to_siem(1, &ev)]);
        let text = String::from_utf8(bytes).unwrap();

        assert_eq!(text.lines().count(), 1, "one event stays one line: {text}");
        assert!(text.contains(r"x\|Evil\|10\|src=6.6.6.6 CEF:0\|forged|Request blocked|"));
        assert!(text.contains(r"request=/a\r\nCEF:0|forged|waf|1|x|y|10|src\=6.6.6.6 "));
        assert!(text.contains(r"msg=ok suser\=root "));
    }

    #[test]
    fn cef_values_respect_the_spec_limits() {
        let mut ev = decision("r");
        ev.path = Some("é".repeat(2000));
        ev.node = "n".repeat(500);
        ev.decision = "d".repeat(500);
        let line = cef_line(&decision_to_siem(1, &ev));

        let value = |key: &str| line.split(&format!(" {key}=")).nth(1).unwrap().split(' ').next().unwrap();
        assert_eq!(value("request").chars().count(), CEF_MAX_STRING, "cut on a char, not a byte");
        assert_eq!(value("dvchost").chars().count(), CEF_MAX_DVCHOST);
        assert_eq!(value("act").chars().count(), CEF_MAX_ACT);
        // The longest id we can emit fits `externalId`.
        assert!(format!("waf-decision-{}", i64::MAX).len() <= CEF_MAX_EXTERNAL_ID);

        // The clip counts source characters, so an escape is never cut in half.
        assert_eq!(cef_value(&cef_clip(&"=".repeat(5), 3)), r"\=\=\=");
    }

    #[test]
    fn cef_frames_one_event_per_line() {
        let batch = vec![decision_to_siem(1, &decision("a")), decision_to_siem(2, &decision("b"))];
        let text = String::from_utf8(CefFormatter.format_batch(&batch)).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(text.lines().all(|l| l.starts_with("CEF:0|")));
        assert!(text.ends_with('\n'));
        assert_eq!(CefFormatter.content_type(), "text/plain; charset=utf-8");
        assert_eq!(formatter_for(crate::config::SiemFormat::Cef).content_type(), CefFormatter.content_type());
    }
}
