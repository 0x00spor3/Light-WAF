// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Control-plane data model — DTOs that mirror the OPEN telemetry contract, kept DECOUPLED from
//! `waf-core`. The decision-log JSON schema (frozen by the core's shape test) is the contract; the
//! control plane never links the datapath crate.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

/// One entry of the OPEN decision-log `score_contributions` array (`{module, rule_id, severity,
/// points}`). `severity` is a `String`, NOT an enum, on purpose: forward-compatible if the core
/// ever adds a severity class, and the control plane only stores/displays it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contribution {
    pub module: String,
    pub rule_id: String,
    #[serde(default)]
    pub severity: Option<String>,
    pub points: u32,
}

/// A denied-request event (blocked | rejected) reconstructed from the OPEN decision-log. This is
/// the row the drill-down reads back; `contributions` is the per-rule breakdown that produced the
/// verdict. Populated by the ingestion pipeline (Phase 2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionEvent {
    pub request_id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub node: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub client_ip: Option<String>,
    /// `"blocked"` or `"rejected"` — v1 stores only denied events (the log's enriched lines).
    pub decision: String,
    pub rule_id: Option<String>,
    pub reason: Option<String>,
    pub score: i32,
    pub contributions: Vec<Contribution>,
}

/// A captured HTTP request — the full denied request (headers/cookies/body) shipped by the node's
/// request-capture feature, joined to a [`DecisionEvent`] by `request_id` in the drill-down. Mirrors
/// the node's wire shape (`waf-capture::CapturedRequest`); the control plane never links that crate.
/// The body arrives base64-encoded (JSON cannot carry raw bytes) and is stored as `BYTEA`. Redaction
/// and truncation are already applied node-side — the control plane only persists/serves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedRequest {
    pub request_id: String,
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub query: Option<String>,
    pub http_version: String,
    pub headers: Vec<(String, String)>,
    pub cookies: Vec<(String, String)>,
    /// Base64 of the (redacted, possibly truncated) body bytes.
    pub body_b64: String,
    /// Original body size in bytes, before any truncation.
    pub body_size: u64,
    /// True when the stored body was capped node-side.
    pub body_truncated: bool,
    /// Names redacted node-side (drives the UI banner). Never carries the redacted values.
    pub redacted: Vec<String>,
}

/// A point-in-time count of one decision class scraped from a node's `/metrics`
/// (`waf_requests_total{decision}`), kept for long-term retention / time-series dashboards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricRollup {
    #[serde(with = "time::serde::rfc3339")]
    pub ts: OffsetDateTime,
    pub node: String,
    pub decision: String,
    pub count: i64,
}

/// A fired alert (v2): a rule's (per-group) denied-event count crossed its threshold. Stored and
/// exposed via `GET /api/alerts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    pub rule_name: String,
    /// The group value that fired (e.g. a `client_ip`/`rule_id`), or empty for an ungrouped rule.
    pub group_key: String,
    #[serde(with = "time::serde::rfc3339")]
    pub fired_at: OffsetDateTime,
    pub severity: String,
    pub value: i64,
    pub threshold: i64,
    pub summary: String,
}

/// An immutable published ruleset version (§7 write-path, v3). `content` is the raw managed SecRule
/// `.conf` text; each publish appends one row and `rule_current` selects the live one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleVersion {
    pub id: i64,
    pub content: String,
    pub author: String,
    pub note: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// Version metadata without the (possibly large) `content`, plus whether it is the current/live one
/// — the shape returned by the versions list (`GET /api/rules/versions`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleVersionMeta {
    pub id: i64,
    pub author: String,
    pub note: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    /// Whether this version is the current (live) one.
    pub current: bool,
}

/// The version a node reports it has applied and the outcome of its last apply — the per-node
/// convergence view (`GET /api/rules/nodes`). `applied_version` is `None` until the node reports one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRuleStatus {
    pub node: String,
    pub applied_version: Option<i64>,
    /// Free-form agent-reported outcome, e.g. `"applied"` | `"rejected"` | `"error"`.
    pub status: String,
    pub detail: String,
    #[serde(with = "time::serde::rfc3339")]
    pub reported_at: OffsetDateTime,
}
