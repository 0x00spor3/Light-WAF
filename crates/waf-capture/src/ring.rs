// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! A bounded, TTL'd in-memory ring of [`CapturedRequest`]s keyed by `request_id`.
//!
//! The capture module ([`crate::CaptureModule`]) inserts on the request path (the hot side); the
//! verdict-join `tracing::Layer` (C2) takes on the decision path (the rare side — only denied
//! requests). Everything not taken ages out, so the ring holds only a few seconds of recent traffic.
//!
//! Three independent bounds keep memory flat under any load: **entry count** (`capacity`), **total
//! bytes** (`max_bytes`), and **age** (`ttl`). Insert evicts expired-then-oldest; the newest capture
//! is always kept (a single oversized capture is never self-evicted). The lock is poison-tolerant:
//! a panicked holder must not wedge the datapath.

use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::CapturedRequest;

struct Entry {
    req: CapturedRequest,
    inserted: Instant,
    bytes: usize,
}

#[derive(Default)]
struct RingInner {
    map: HashMap<String, Entry>,
    /// Insertion order (FIFO) of live keys — `take` keeps it consistent by removing the key.
    order: VecDeque<String>,
    total_bytes: usize,
}

/// Bounded ring buffer of captures. Cheap to clone the `Arc` around it; interior-mutable so the
/// capture module can insert through a shared `&self`.
pub struct CaptureRing {
    inner: Mutex<RingInner>,
    capacity: usize,
    max_bytes: usize,
    ttl: Duration,
}

impl CaptureRing {
    /// Create a ring bounded by `capacity` entries, `max_bytes` total, and `ttl` age.
    pub fn new(capacity: usize, max_bytes: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(RingInner::default()),
            capacity: capacity.max(1),
            max_bytes,
            ttl,
        }
    }

    /// Poison-tolerant lock: a panicked holder must never wedge the request path.
    fn lock(&self) -> MutexGuard<'_, RingInner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Insert (or replace) the capture for its `request_id`. Evicts expired entries first, then the
    /// oldest while over the count/byte budget — but never the just-inserted newest.
    pub fn insert(&self, req: CapturedRequest) {
        let bytes = req.estimated_bytes();
        let key = req.request_id.clone();
        let mut g = self.lock();
        self.evict_expired(&mut g);

        // Replace a same-id entry (retry / duplicate) without leaving a stale order slot.
        if let Some(old) = g.map.remove(&key) {
            g.total_bytes -= old.bytes;
            g.order.retain(|k| k != &key);
        }

        g.total_bytes += bytes;
        g.map.insert(key.clone(), Entry { req, inserted: Instant::now(), bytes });
        g.order.push_back(key);

        while g.map.len() > self.capacity || (g.total_bytes > self.max_bytes && g.map.len() > 1) {
            match g.order.pop_front() {
                Some(oldest) => {
                    if let Some(e) = g.map.remove(&oldest) {
                        g.total_bytes -= e.bytes;
                    }
                }
                None => break,
            }
        }
    }

    /// Remove and return the capture for `request_id`, if still present (not yet evicted). Called by
    /// the verdict-join on a denied request.
    pub fn take(&self, request_id: &str) -> Option<CapturedRequest> {
        let mut g = self.lock();
        self.evict_expired(&mut g);
        let e = g.map.remove(request_id)?;
        g.total_bytes -= e.bytes;
        g.order.retain(|k| k != request_id);
        Some(e.req)
    }

    /// Number of live captures currently held (test/observability).
    pub fn len(&self) -> usize {
        self.lock().map.len()
    }

    /// Whether the ring currently holds no captures.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pop expired entries from the front (oldest). `order` is FIFO by insert time, so once the front
    /// is within `ttl` nothing behind it can be older — stop.
    fn evict_expired(&self, g: &mut RingInner) {
        while let Some(front) = g.order.front().cloned() {
            match g.map.get(&front) {
                Some(e) if e.inserted.elapsed() > self.ttl => {
                    let bytes = e.bytes;
                    g.map.remove(&front);
                    g.total_bytes -= bytes;
                    g.order.pop_front();
                }
                _ => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(id: &str, body_len: usize) -> CapturedRequest {
        CapturedRequest {
            request_id: id.to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            query: None,
            http_version: "HTTP/1.1".to_string(),
            headers: vec![],
            cookies: vec![],
            body_b64: "A".repeat(body_len),
            body_size: body_len,
            body_truncated: false,
            redacted: vec![],
        }
    }

    #[test]
    fn insert_then_take_roundtrips_and_removes() {
        let ring = CaptureRing::new(8, 1 << 20, Duration::from_secs(5));
        ring.insert(cap("r1", 10));
        assert_eq!(ring.len(), 1);
        let got = ring.take("r1").expect("present");
        assert_eq!(got.request_id, "r1");
        assert!(ring.take("r1").is_none(), "taken once");
        assert!(ring.is_empty());
    }

    #[test]
    fn evicts_oldest_over_capacity_keeping_newest() {
        let ring = CaptureRing::new(2, 1 << 20, Duration::from_secs(5));
        ring.insert(cap("r1", 1));
        ring.insert(cap("r2", 1));
        ring.insert(cap("r3", 1)); // evicts r1
        assert_eq!(ring.len(), 2);
        assert!(ring.take("r1").is_none(), "oldest evicted");
        assert!(ring.take("r2").is_some());
        assert!(ring.take("r3").is_some(), "newest kept");
    }

    #[test]
    fn evicts_over_byte_budget_but_keeps_the_newest() {
        // Budget only fits ~one 100-byte capture.
        let ring = CaptureRing::new(100, 120, Duration::from_secs(5));
        ring.insert(cap("r1", 100));
        ring.insert(cap("r2", 100)); // pushes total over budget → r1 evicted
        assert_eq!(ring.len(), 1);
        assert!(ring.take("r1").is_none());
        assert!(ring.take("r2").is_some(), "newest always survives");
    }

    #[test]
    fn expired_entries_are_evicted() {
        let ring = CaptureRing::new(8, 1 << 20, Duration::from_millis(1));
        ring.insert(cap("r1", 10));
        std::thread::sleep(Duration::from_millis(5));
        // Any operation triggers expiry sweep.
        assert!(ring.take("r1").is_none(), "expired before take");
        assert!(ring.is_empty());
    }

    #[test]
    fn reinsert_same_id_does_not_double_count_bytes() {
        let ring = CaptureRing::new(8, 1 << 20, Duration::from_secs(5));
        ring.insert(cap("r1", 10));
        ring.insert(cap("r1", 20)); // replaces
        assert_eq!(ring.len(), 1);
        let got = ring.take("r1").unwrap();
        assert_eq!(got.body_b64.len(), 20, "latest value wins");
    }
}
