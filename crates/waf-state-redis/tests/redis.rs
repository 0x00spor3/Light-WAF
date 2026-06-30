// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Integration tests for the distributed Redis StateStore. These need a live
//! Redis and are ENV-GATED on `WAF_REDIS_URL` (skipped with a note otherwise),
//! mirroring the WASM smoke-test discipline:
//!
//!   docker run -d -p 6379:6379 redis
//!   WAF_REDIS_URL=redis://127.0.0.1:6379 cargo test -p waf-state-redis
//!
//! What they prove:
//! - equivalence of the ALLOW/DENY decision vs the in-memory oracle (same params,
//!   same controlled clock) — the §-discipline "the in-memory store is the oracle";
//! - atomicity: N threads hammering one bucket grant EXACTLY capacity (no
//!   cluster-wide over-allow / TOCTOU) — the whole reason the Redis store exists;
//! - NOSCRIPT recovery after `SCRIPT FLUSH`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use waf_core::{BucketParams, InMemoryStateStore, ManualClock, StateStore};
use waf_state_redis::RedisStore;

fn redis_url() -> Option<String> {
    std::env::var("WAF_REDIS_URL").ok().filter(|s| !s.is_empty())
}

/// Unique key per test invocation so a previous (possibly aborted) run never
/// pollutes a fresh bucket.
fn unique_key(tag: &str) -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("waf:test:{tag}:{nanos}:{}", N.fetch_add(1, Ordering::Relaxed))
}

macro_rules! require_redis {
    () => {
        match redis_url() {
            Some(u) => u,
            None => {
                eprintln!("skipping: WAF_REDIS_URL not set");
                return;
            }
        }
    };
}

#[test]
fn allow_deny_matches_in_memory_oracle() {
    let url = require_redis!();
    let store = RedisStore::connect(&url).expect("connect");
    let key = unique_key("equiv");

    let params = BucketParams { capacity: 5.0, refill_per_sec: 2.0 };

    // In-memory oracle driven by a manual clock; redis driven by the same `now`
    // via the deterministic override. We compare the security-relevant decision
    // (allowed) at each step; exact fractional tokens may differ by rounding.
    let clock = Arc::new(ManualClock::new());
    let mem = InMemoryStateStore::with_clock(clock.clone());

    // A scenario that exercises drain → deny → refill → allow.
    // (delta seconds to advance BEFORE the attempt, cost)
    let steps: &[(f64, f64)] = &[
        (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), (0.0, 1.0), // drain the 5
        (0.0, 1.0), // empty -> deny
        (1.0, 1.0), // +2 tokens -> allow
        (0.0, 1.0), // 1 left -> allow
        (0.0, 1.0), // empty -> deny
        (10.0, 5.0), // long idle -> refilled to cap, take 5 -> allow
    ];

    let mut now = 1_000_000.0_f64;
    for (i, (delta, cost)) in steps.iter().enumerate() {
        now += *delta;
        if *delta > 0.0 {
            clock.advance(std::time::Duration::from_secs_f64(*delta));
        }
        let r = store.try_acquire_at(&key, *cost, params, now);
        let m = mem.try_acquire(&key, *cost, params);
        assert_eq!(
            r.allowed, m.allowed,
            "step {i}: redis allowed={} vs in-memory allowed={}",
            r.allowed, m.allowed
        );
    }
}

#[test]
fn concurrent_grants_exactly_capacity() {
    let url = require_redis!();
    let store = Arc::new(RedisStore::connect(&url).expect("connect"));
    let key = unique_key("atomic");

    // No refill ⇒ exactly `capacity` grants total, regardless of timing.
    let params = BucketParams { capacity: 50.0, refill_per_sec: 0.0 };
    let threads = 8;
    let attempts_each = 25; // 200 attempts contend for 50 tokens

    let granted = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for _ in 0..threads {
        let store = Arc::clone(&store);
        let key = key.clone();
        let granted = Arc::clone(&granted);
        handles.push(std::thread::spawn(move || {
            for _ in 0..attempts_each {
                if store.try_acquire(&key, 1.0, params).allowed {
                    granted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(
        granted.load(Ordering::Relaxed),
        50,
        "atomic script must grant EXACTLY capacity across all threads (no over-allow)"
    );
}

#[test]
fn survives_script_flush_noscript() {
    let url = require_redis!();
    let store = RedisStore::connect(&url).expect("connect");
    let key = unique_key("noscript");
    let params = BucketParams { capacity: 5.0, refill_per_sec: 1.0 };

    assert!(store.try_acquire(&key, 1.0, params).allowed, "first call works");

    // Evict the cached script server-side (simulates restart / failover).
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_connection().unwrap();
    redis::cmd("SCRIPT").arg("FLUSH").query::<()>(&mut conn).unwrap();

    // EVALSHA now NOSCRIPTs; redis::Script must transparently EVAL + retry.
    assert!(
        store.try_acquire(&key, 1.0, params).allowed,
        "must recover from NOSCRIPT via EVAL fallback"
    );
}
