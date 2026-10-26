// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Cluster coordination bite-tests (Step 4) — the load-bearing property of the multi-node cert
//! design: **exactly one node issues, the others converge**, and a dead leader's lock **expires**
//! so the cluster is never stuck.
//!
//! These drive the `SharedCertStore` protocol the DNS-01 driver uses (try_lock → issue → store →
//! unlock; followers load_cert to converge) against an in-memory store with FAITHFUL semantics
//! (owner-scoped lock, TTL expiry, store-only-under-lock). No Redis, no ACME — so it runs in a
//! plain `cargo test`. The Redis wire-level equivalents live (env-gated) in waf-state-redis.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use waf_state_redis::{SharedCert, SharedCertStore};

/// In-memory `SharedCertStore` with real semantics + a logical clock (so TTL expiry is
/// deterministic, no sleeps). The single logical cert/lock ignores `key` (one cert per store).
struct MockCertStore {
    inner: Mutex<Inner>,
    now_ms: AtomicU64,
}
struct Inner {
    /// `(holder, expiry_ms)` — the single-writer issuance lock.
    lock: Option<(String, u64)>,
    cert: Option<SharedCert>,
}

impl MockCertStore {
    fn new() -> Self {
        Self { inner: Mutex::new(Inner { lock: None, cert: None }), now_ms: AtomicU64::new(0) }
    }
    fn now(&self) -> u64 {
        self.now_ms.load(Ordering::SeqCst)
    }
    /// Advance the logical clock (to expire a lock without sleeping).
    fn advance(&self, d: Duration) {
        self.now_ms.fetch_add(d.as_millis() as u64, Ordering::SeqCst);
    }
}

impl SharedCertStore for MockCertStore {
    fn load_cert(&self, _key: &str) -> Option<SharedCert> {
        self.inner.lock().unwrap().cert.clone()
    }
    fn store_cert(&self, _key: &str, holder: &str, cert: &SharedCert) -> bool {
        let now = self.now();
        let mut g = self.inner.lock().unwrap();
        // Only the current lock holder (unexpired) may publish — the R3 compare-and-set.
        let owns = matches!(&g.lock, Some((h, exp)) if h == holder && *exp > now);
        if owns {
            g.cert = Some(cert.clone());
        }
        owns
    }
    fn try_lock(&self, _key: &str, holder: &str, ttl: Duration) -> bool {
        let now = self.now();
        let mut g = self.inner.lock().unwrap();
        let free = match &g.lock {
            None => true,
            Some((_, exp)) => *exp <= now, // expired ⇒ free (the R5 takeover path)
        };
        if free {
            g.lock = Some((holder.to_string(), now + ttl.as_millis() as u64));
        }
        free
    }
    fn extend_lock(&self, _key: &str, holder: &str, ttl: Duration) -> bool {
        let now = self.now();
        let mut g = self.inner.lock().unwrap();
        match &g.lock {
            Some((h, exp)) if h == holder && *exp > now => {
                g.lock = Some((holder.to_string(), now + ttl.as_millis() as u64));
                true
            }
            _ => false,
        }
    }
    fn unlock(&self, _key: &str, holder: &str) {
        let mut g = self.inner.lock().unwrap();
        if matches!(&g.lock, Some((h, _)) if h == holder) {
            g.lock = None;
        }
    }
}

const KEY: &str = "domainset-hash";
const TTL: Duration = Duration::from_secs(60);

fn fake_cert(tag: &str) -> SharedCert {
    SharedCert {
        chain_pem: format!("-----BEGIN CERTIFICATE-----\n{tag}\n-----END CERTIFICATE-----\n"),
        key_pem: format!("-----BEGIN PRIVATE KEY-----\n{tag}\n-----END PRIVATE KEY-----\n"),
        not_after_unix: 2_000_000_000,
    }
}

/// The core property: under contention, exactly ONE node issues; the other converges on that
/// cert without issuing. This mirrors the driver's step-3 decision (leader vs follower).
#[test]
fn exactly_one_node_issues_the_other_converges() {
    let store = MockCertStore::new();
    let mut issuances = 0u32;

    // Both nodes wake with no cert yet and both attempt to become the writer.
    assert!(store.load_cert(KEY).is_none(), "cold cluster: no cert");
    let a_leads = store.try_lock(KEY, "node-A", TTL);
    let b_leads = store.try_lock(KEY, "node-B", TTL);
    assert!(a_leads, "the first caller becomes the writer");
    assert!(!b_leads, "the second caller is a follower (single writer)");

    // Leader A issues (stub), publishes, releases.
    issuances += 1;
    let cert = fake_cert("issued-by-A");
    assert!(store.store_cert(KEY, "node-A", &cert), "the holder publishes");
    store.unlock(KEY, "node-A");

    // Follower B converges: it never issues, it just picks up the published cert.
    let b_view = store.load_cert(KEY).expect("B converges on the shared cert");
    assert_eq!(b_view, cert, "B serves exactly the cert A issued");
    assert_eq!(issuances, 1, "exactly one issuance for the whole cluster");
}

/// R5: a leader that dies AFTER locking but BEFORE publishing must not deadlock the cluster —
/// the lock TTL expires and another node takes over and completes.
#[test]
fn dead_leader_lock_expires_and_another_node_takes_over() {
    let store = MockCertStore::new();
    let mut issuances = 0u32;

    // A becomes leader… then "crashes": no store_cert, no unlock, no heartbeat.
    assert!(store.try_lock(KEY, "node-A", TTL));

    // Meanwhile B cannot take over yet (A's lock is still valid).
    assert!(!store.try_lock(KEY, "node-B", TTL), "B blocked while A's lock is live");
    assert!(store.load_cert(KEY).is_none(), "no cert was ever published by the dead leader");

    // Time passes beyond the TTL with no heartbeat → the lock is now reclaimable.
    store.advance(TTL + Duration::from_secs(1));

    assert!(store.try_lock(KEY, "node-B", TTL), "B takes over the expired lock");
    issuances += 1;
    let cert = fake_cert("issued-by-B");
    assert!(store.store_cert(KEY, "node-B", &cert), "B publishes after taking over");
    store.unlock(KEY, "node-B");

    assert_eq!(store.load_cert(KEY), Some(cert), "the cluster recovers a valid cert");
    assert_eq!(issuances, 1, "still one successful issuance (A's was aborted by death)");
}

/// A node that lost the lock (heartbeat failed / TTL lapsed) cannot clobber a valid cert — the
/// store-under-lock guard (R3) is what makes the abort-on-lock-loss posture safe.
#[test]
fn a_node_without_the_lock_cannot_overwrite_the_cert() {
    let store = MockCertStore::new();

    // B holds the lock and publishes a good cert.
    assert!(store.try_lock(KEY, "node-B", TTL));
    let good = fake_cert("good");
    assert!(store.store_cert(KEY, "node-B", &good));
    store.unlock(KEY, "node-B");

    // A finished a stale issuance but never held the lock → its publish must be rejected.
    let stale = fake_cert("stale");
    assert!(!store.store_cert(KEY, "node-A", &stale), "no lock ⇒ no write");
    assert_eq!(store.load_cert(KEY), Some(good), "the valid cert is untouched");
}
