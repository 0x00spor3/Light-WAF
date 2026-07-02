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

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use std::time::Duration;

use waf_core::{BucketParams, InMemoryStateStore, ManualClock, StateStore};
use waf_state_redis::{
    CertCipher, DistributedLock, RedisStore, Reputation, ReputationStore, ReputationWriter,
    SharedCert, SharedCertStore,
};

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
fn reputation_reads_seeded_values() {
    let url = require_redis!();
    let store = RedisStore::connect(&url).expect("connect");

    // Seed RAW via the documented key format `rep:<ip>` — there is intentionally NO
    // production seed API in the crate (the feed §6 owns writes; tests/redis-cli seed raw).
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_connection().unwrap();
    let bad: IpAddr = "203.0.113.7".parse().unwrap();
    let sus: IpAddr = "203.0.113.8".parse().unwrap();
    let unknown: IpAddr = "203.0.113.9".parse().unwrap();
    redis::cmd("SET").arg(format!("rep:{bad}")).arg("malicious").query::<()>(&mut conn).unwrap();
    redis::cmd("SET").arg(format!("rep:{sus}")).arg("suspicious").query::<()>(&mut conn).unwrap();
    redis::cmd("DEL").arg(format!("rep:{unknown}")).query::<()>(&mut conn).unwrap();

    assert_eq!(store.reputation(bad), Reputation::Malicious);
    assert_eq!(store.reputation(sus), Reputation::Suspicious);
    assert_eq!(store.reputation(unknown), Reputation::Unknown, "no entry ⇒ Unknown");

    redis::cmd("DEL")
        .arg(format!("rep:{bad}"))
        .arg(format!("rep:{sus}"))
        .query::<()>(&mut conn)
        .unwrap();
}

#[test]
fn feed_write_is_read_back_by_reputation_and_expires_to_unknown() {
    // THE F1 contract on the wire: what the feed WRITES (`apply_snapshot`) is exactly what the
    // datapath READS (`reputation`) — same key (`rep_key`) and value (`as_wire`/`from_wire`), so
    // populate-but-never-match is impossible. Plus: a short TTL ages the entry back to Unknown.
    let url = require_redis!();
    let store = RedisStore::connect(&url).expect("connect");

    // Use a unique third octet so parallel test runs never collide on these IPs.
    let tag = unique_key("feed");
    let n: u16 = (tag.len() % 250 + 1) as u16;
    let bad: IpAddr = format!("198.51.100.{n}").parse().unwrap();
    let sus: IpAddr = format!("198.51.100.{}", n + 1).parse().unwrap();
    let unk: IpAddr = format!("198.51.100.{}", n + 2).parse().unwrap();

    // A snapshot with an overlap (bad listed twice, strongest wins) + an Unknown (never written).
    let entries = [
        (bad, Reputation::Suspicious),
        (bad, Reputation::Malicious),
        (sus, Reputation::Suspicious),
        (unk, Reputation::Unknown),
    ];
    let written = store.apply_snapshot(&entries, Duration::from_secs(30));
    assert_eq!(written, 2, "two keys written (bad + sus); Unknown skipped, dup collapsed");

    assert_eq!(store.reputation(bad), Reputation::Malicious, "feed write read back as Malicious");
    assert_eq!(store.reputation(sus), Reputation::Suspicious, "feed write read back as Suspicious");
    assert_eq!(store.reputation(unk), Reputation::Unknown, "Unknown was never written");

    // TTL semantics (F2): a 1s entry is gone shortly after — reputation falls back to Unknown.
    let ttl_ip: IpAddr = format!("198.51.100.{}", n + 3).parse().unwrap();
    assert_eq!(store.apply_snapshot(&[(ttl_ip, Reputation::Malicious)], Duration::from_secs(1)), 1);
    assert_eq!(store.reputation(ttl_ip), Reputation::Malicious, "present right after write");
    std::thread::sleep(Duration::from_millis(1300));
    assert_eq!(store.reputation(ttl_ip), Reputation::Unknown, "entry aged out to Unknown");

    // Cleanup.
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_connection().unwrap();
    redis::cmd("DEL")
        .arg(format!("rep:{bad}"))
        .arg(format!("rep:{sus}"))
        .query::<()>(&mut conn)
        .unwrap();
}

#[test]
fn feed_lock_is_single_writer_owner_scoped_and_expires() {
    // F4 on the wire: the feed's DistributedLock is single-holder, release is owner-scoped, and a
    // dead leader's lock frees via PX expiry so the next cycle another node acquires. Its own
    // `feed_lock:` namespace ⇒ never collides with a cert issuance lock.
    let url = require_redis!();
    let store = RedisStore::connect(&url).expect("connect");
    let name = unique_key("feedlock");

    assert!(store.acquire(&name, "node-A", Duration::from_secs(30)), "A acquires the free lock");
    assert!(!store.acquire(&name, "node-B", Duration::from_secs(30)), "B blocked while A holds");

    store.release(&name, "node-B"); // non-owner release is a no-op
    assert!(!store.acquire(&name, "node-B", Duration::from_secs(30)), "still A's after bogus release");
    store.release(&name, "node-A");
    assert!(store.acquire(&name, "node-B", Duration::from_secs(30)), "B acquires after A releases");
    store.release(&name, "node-B");

    // Dead-leader takeover via TTL (no release, no heartbeat — F4).
    assert!(store.acquire(&name, "node-A", Duration::from_millis(800)), "A acquires short-TTL");
    assert!(!store.acquire(&name, "node-B", Duration::from_secs(30)), "B blocked while A's lock lives");
    std::thread::sleep(Duration::from_millis(1100));
    assert!(store.acquire(&name, "node-B", Duration::from_secs(30)), "B takes over the expired lock");
    store.release(&name, "node-B");
}

// ── SharedCertStore (cert TLS multi-nodo): lock CAS semantics + encrypted round-trip ──

fn cert_store(url: &str) -> RedisStore {
    RedisStore::connect(url)
        .expect("connect")
        .with_cert_cipher(CertCipher::from_secret("integration-test-secret"))
}

#[test]
fn issuance_lock_is_single_writer_and_owner_scoped() {
    let url = require_redis!();
    let store = cert_store(&url);
    let key = unique_key("lock");
    let ttl = Duration::from_secs(30);

    // First holder wins; a different holder cannot take it while held (single writer).
    assert!(store.try_lock(&key, "node-A", ttl), "A acquires the free lock");
    assert!(!store.try_lock(&key, "node-B", ttl), "B must NOT take A's held lock");

    // extend only works for the owner (compare-and-pexpire).
    assert!(store.extend_lock(&key, "node-A", ttl), "owner A extends its lock");
    assert!(!store.extend_lock(&key, "node-B", ttl), "non-owner B cannot extend");

    // unlock by a non-owner is a no-op; the owner can still release.
    store.unlock(&key, "node-B");
    assert!(!store.try_lock(&key, "node-B", ttl), "B still cannot take A's lock after a bogus unlock");
    store.unlock(&key, "node-A");
    assert!(store.try_lock(&key, "node-B", ttl), "B acquires after A releases");
    store.unlock(&key, "node-B");
}

#[test]
fn dead_leader_lock_expires_on_the_wire() {
    // R5, wire-level: a leader that acquires the lock and dies (no unlock, no heartbeat) must not
    // deadlock the cluster — Redis PX expiry frees the lock so another node takes over.
    let url = require_redis!();
    let store = cert_store(&url);
    let key = unique_key("ttl");

    assert!(store.try_lock(&key, "node-A", Duration::from_millis(800)), "A acquires");
    assert!(!store.try_lock(&key, "node-B", Duration::from_secs(30)), "B blocked while A's lock lives");

    // A "dies": no unlock, no extend. Wait past the short TTL.
    std::thread::sleep(Duration::from_millis(1100));

    assert!(store.try_lock(&key, "node-B", Duration::from_secs(30)), "B takes over the expired lock");
    store.unlock(&key, "node-B");
}

#[test]
fn store_cert_requires_the_lock_and_round_trips_encrypted() {
    let url = require_redis!();
    let store = cert_store(&url);
    let key = unique_key("cert");
    let ttl = Duration::from_secs(30);

    let cert = SharedCert {
        chain_pem: "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----\n".into(),
        key_pem: "-----BEGIN PRIVATE KEY-----\nMIIsecret\n-----END PRIVATE KEY-----\n".into(),
        not_after_unix: 1_900_000_000,
    };

    // No lock held ⇒ store is refused (defense in depth: only the writer may publish).
    assert!(!store.store_cert(&key, "node-A", &cert), "store without the lock must fail");
    assert!(store.load_cert(&key).is_none(), "nothing was written");

    // Hold the lock, then a non-holder still cannot store, but the holder can.
    assert!(store.try_lock(&key, "node-A", ttl));
    assert!(!store.store_cert(&key, "node-B", &cert), "a non-holder cannot store even while A holds");
    assert!(store.store_cert(&key, "node-A", &cert), "the lock holder stores the cert");

    // The blob round-trips, including private-key decryption (proves encryption-at-rest works).
    let got = store.load_cert(&key).expect("cert is present");
    assert_eq!(got, cert, "loaded cert matches (chain + decrypted key + expiry)");

    store.unlock(&key, "node-A");

    // A store WITHOUT a cipher attached must not write (and would not be able to encrypt).
    let plain = RedisStore::connect(&url).expect("connect");
    assert!(store.try_lock(&key, "node-C", ttl));
    assert!(!plain.store_cert(&key, "node-C", &cert), "no cipher ⇒ store no-ops");
    store.unlock(&key, "node-C");

    // Cleanup.
    let client = redis::Client::open(url.as_str()).unwrap();
    let mut conn = client.get_connection().unwrap();
    redis::cmd("DEL").arg(format!("cert:{key}")).query::<()>(&mut conn).unwrap();
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
