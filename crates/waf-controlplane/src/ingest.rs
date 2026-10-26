// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Decision-log ingestion. A log shipper POSTs the OPEN JSON decision-log (NDJSON). Two line kinds
//! matter, correlated by `request_id`:
//!   - `→ request` (info) — carries `method` / `path` / `client_ip`;
//!   - `request blocked` / `request rejected` (warn) — carry `rule_id` / `score` /
//!     `score_contributions` (the per-rule breakdown; a JSON-string field).
//!
//! We join them in a bounded in-memory buffer, then store one `DecisionEvent` per denied request.
//! Node identity is supplied by the caller (the shipper), never by the core — zero-core.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::warn;

use crate::error::Result;
use crate::model::{Contribution, DecisionEvent};
use crate::store::Store;

/// Request-line context awaiting a matching decision line.
#[derive(Clone)]
struct ReqCtx {
    method: Option<String>,
    path: Option<String>,
    client_ip: Option<String>,
}

/// Bounded FIFO map `request_id → ReqCtx`. A `→ request` line inserts; a decision line takes the
/// entry (join). Benign requests (no decision line) age out under the cap — memory is bounded, and
/// no user input becomes an unbounded label (the §7 cardinality rule).
struct Correlator {
    map: HashMap<String, ReqCtx>,
    order: VecDeque<String>,
    cap: usize,
}

impl Correlator {
    fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), cap }
    }

    fn insert(&mut self, request_id: String, ctx: ReqCtx) {
        if self.map.insert(request_id.clone(), ctx).is_none() {
            self.order.push_back(request_id);
            while self.order.len() > self.cap {
                if let Some(old) = self.order.pop_front() {
                    self.map.remove(&old);
                }
            }
        }
    }

    fn take(&mut self, request_id: &str) -> Option<ReqCtx> {
        self.map.remove(request_id)
    }
}

/// Look up a field in the tracing JSON: event fields are nested under `"fields"`, but tolerate a
/// flattened layout too (`parsed[name]`).
fn field<'a>(v: &'a Value, name: &str) -> Option<&'a Value> {
    v.get("fields").and_then(|f| f.get(name)).or_else(|| v.get(name))
}

fn field_str(v: &Value, name: &str) -> Option<String> {
    field(v, name).and_then(|x| x.as_str()).map(str::to_string)
}

/// Parse the `score_contributions` field: the core emits it as a JSON-STRING (a serialized array),
/// but tolerate an already-parsed array too. Unparseable → empty (never fail ingestion on it).
fn parse_contributions(v: &Value) -> Vec<Contribution> {
    let Some(f) = field(v, "score_contributions") else {
        return Vec::new();
    };
    let parsed = match f {
        Value::String(s) => serde_json::from_str::<Vec<Contribution>>(s).ok(),
        Value::Array(_) => serde_json::from_value::<Vec<Contribution>>(f.clone()).ok(),
        _ => None,
    };
    parsed.unwrap_or_default()
}

fn parse_ts(v: &Value) -> OffsetDateTime {
    field_str(v, "timestamp")
        .and_then(|s| OffsetDateTime::parse(&s, &Rfc3339).ok())
        .unwrap_or_else(OffsetDateTime::now_utc)
}

/// Pure parse + correlate for ONE line. A `→ request` line updates `correlator` and yields `None`;
/// a `request blocked`/`request rejected` line yields the `DecisionEvent` to store (joined with the
/// buffered request context, if any). Anything else → `None`. No I/O, so it is unit-testable and the
/// (std) lock is never held across an `.await`.
fn correlate_line(node: &str, line: &str, correlator: &mut Correlator) -> Option<DecisionEvent> {
    let v = serde_json::from_str::<Value>(line).ok()?;
    let message = field_str(&v, "message").unwrap_or_default();
    let request_id = field_str(&v, "request_id")?;

    match message.as_str() {
        "→ request" => {
            correlator.insert(
                request_id,
                ReqCtx {
                    method: field_str(&v, "method"),
                    path: field_str(&v, "path"),
                    client_ip: field_str(&v, "client_ip"),
                },
            );
            None
        }
        "request blocked" | "request rejected" => {
            let (method, path, client_ip) = match correlator.take(&request_id) {
                Some(c) => (c.method, c.path, c.client_ip),
                None => (None, None, None),
            };
            Some(DecisionEvent {
                request_id,
                ts: parse_ts(&v),
                node: node.to_string(),
                method,
                path,
                client_ip,
                decision: if message == "request blocked" { "blocked" } else { "rejected" }
                    .to_string(),
                rule_id: field_str(&v, "rule_id"),
                reason: field_str(&v, "reason"),
                score: field(&v, "score").and_then(Value::as_i64).unwrap_or(0) as i32,
                contributions: parse_contributions(&v),
            })
        }
        _ => None,
    }
}

/// Ingests decision-log lines into the store, correlating request/decision lines.
pub struct Ingestor {
    store: Store,
    correlator: Mutex<Correlator>,
}

impl Ingestor {
    /// Default correlation buffer size (bounded memory; a request/decision pair is microseconds apart).
    pub const DEFAULT_CAP: usize = 10_000;

    pub fn new(store: Store) -> Self {
        Self { store, correlator: Mutex::new(Correlator::new(Self::DEFAULT_CAP)) }
    }

    /// Ingest an NDJSON batch attributed to `node`; returns how many `DecisionEvent`s were stored.
    /// A line that fails to store is skipped (logged), never failing the batch.
    pub async fn ingest_ndjson(&self, node: &str, body: &str) -> Result<usize> {
        let mut stored = 0;
        for line in body.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            // Correlate under the lock (sync, fast); release BEFORE the async store insert.
            let event = {
                let mut c = self.correlator.lock().unwrap();
                correlate_line(node, line, &mut c)
            };
            if let Some(event) = event {
                match self.store.insert_decision_event(&event).await {
                    Ok(()) => stored += 1,
                    Err(e) => warn!(error = %e, request_id = %event.request_id, "ingest: failed to store event"),
                }
            }
        }
        Ok(stored)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQ_LINE: &str = r#"{"timestamp":"2026-07-05T10:00:00.000000Z","fields":{"message":"→ request","request_id":"req-42","method":"GET","path":"/?q=1%20UNION%20SELECT","client_ip":"203.0.113.7"}}"#;
    const BLOCK_LINE: &str = r#"{"timestamp":"2026-07-05T10:00:00.001000Z","fields":{"message":"request blocked","request_id":"req-42","rule_id":"sqli-union-select","reason":"anomaly score exceeded","score":5,"score_contributions":"[{\"module\":\"sqli\",\"rule_id\":\"sqli-union-select\",\"severity\":\"critical\",\"points\":5}]"}}"#;

    #[test]
    fn request_then_block_join_into_a_full_event() {
        let mut c = Correlator::new(1000);
        assert!(correlate_line("edge-1", REQ_LINE, &mut c).is_none(), "request line stores no event");
        let ev = correlate_line("edge-1", BLOCK_LINE, &mut c).expect("block line yields an event");
        assert_eq!(ev.request_id, "req-42");
        assert_eq!(ev.node, "edge-1");
        assert_eq!(ev.decision, "blocked");
        assert_eq!(ev.method.as_deref(), Some("GET")); // joined from the request line
        assert_eq!(ev.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(ev.rule_id.as_deref(), Some("sqli-union-select"));
        assert_eq!(ev.score, 5);
        assert_eq!(ev.contributions.len(), 1);
        assert_eq!(ev.contributions[0].module, "sqli");
        assert_eq!(ev.ts, OffsetDateTime::parse("2026-07-05T10:00:00.001000Z", &Rfc3339).unwrap());
    }

    #[test]
    fn block_without_a_prior_request_still_yields_an_event_with_no_context() {
        let mut c = Correlator::new(1000);
        let ev = correlate_line("n", BLOCK_LINE, &mut c).expect("event even without request line");
        assert!(ev.method.is_none() && ev.path.is_none() && ev.client_ip.is_none());
        assert_eq!(ev.contributions.len(), 1, "contributions come from the block line itself");
    }

    #[test]
    fn non_decision_lines_and_garbage_yield_nothing() {
        let mut c = Correlator::new(1000);
        assert!(correlate_line("n", "not json", &mut c).is_none());
        assert!(correlate_line("n", r#"{"fields":{"message":"← response","request_id":"x"}}"#, &mut c).is_none());
        assert!(correlate_line("n", r#"{"fields":{"message":"request blocked"}}"#, &mut c).is_none(), "no request_id → skip");
    }

    #[test]
    fn parses_contributions_from_json_string_field() {
        let v: Value = serde_json::from_str(BLOCK_LINE).unwrap();
        let c = parse_contributions(&v);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].severity.as_deref(), Some("critical"));
    }

    #[test]
    fn field_lookup_prefers_nested_then_flat() {
        let nested: Value = serde_json::from_str(r#"{"fields":{"request_id":"a"}}"#).unwrap();
        assert_eq!(field_str(&nested, "request_id").as_deref(), Some("a"));
        let flat: Value = serde_json::from_str(r#"{"request_id":"b"}"#).unwrap();
        assert_eq!(field_str(&flat, "request_id").as_deref(), Some("b"));
    }

    #[test]
    fn correlator_evicts_oldest_over_cap() {
        let mut c = Correlator::new(2);
        for id in ["r1", "r2", "r3"] {
            c.insert(id.into(), ReqCtx { method: None, path: None, client_ip: None });
        }
        assert!(c.take("r1").is_none(), "oldest evicted at cap");
        assert!(c.take("r3").is_some());
    }

    // Full parse→correlate→store path against a live Postgres. Env-gated on WAF_CP_DATABASE_URL
    // (skipped when unset), like the store roundtrip and the Redis integration tests.
    #[tokio::test]
    async fn ingest_ndjson_stores_joined_event_env_gated() {
        let Ok(url) = std::env::var("WAF_CP_DATABASE_URL") else {
            eprintln!("skipping: WAF_CP_DATABASE_URL not set");
            return;
        };
        let store = Store::connect(&url).await.expect("connect");
        store.migrate().await.expect("migrate");
        let ingestor = Ingestor::new(store.clone());

        let rid = format!("req-ing-{}", OffsetDateTime::now_utc().unix_timestamp_nanos());
        let req = format!(
            r#"{{"timestamp":"2026-07-05T10:00:00.000000Z","fields":{{"message":"→ request","request_id":"{rid}","method":"GET","path":"/x","client_ip":"203.0.113.9"}}}}"#
        );
        let block = format!(
            r#"{{"timestamp":"2026-07-05T10:00:00.001000Z","fields":{{"message":"request blocked","request_id":"{rid}","rule_id":"sqli-union-select","score":5,"score_contributions":"[{{\"module\":\"sqli\",\"rule_id\":\"sqli-union-select\",\"severity\":\"critical\",\"points\":5}}]"}}}}"#
        );
        let stored = ingestor.ingest_ndjson("edge-1", &format!("{req}\n{block}\n")).await.expect("ingest");
        assert_eq!(stored, 1, "the block line stores one event; the request line stores none");

        let ev = store.get_decision_event(&rid).await.expect("get").expect("present");
        assert_eq!(ev.node, "edge-1");
        assert_eq!(ev.method.as_deref(), Some("GET"), "joined from the correlated request line");
        assert_eq!(ev.client_ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(ev.contributions.len(), 1);
        assert_eq!(ev.contributions[0].module, "sqli");
    }
}
