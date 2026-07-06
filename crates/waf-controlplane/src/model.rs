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
