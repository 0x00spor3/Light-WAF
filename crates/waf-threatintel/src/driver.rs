// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The feed **driver** (ARCHITECTURE_ENTERPRISE §6): a background task that periodically pulls the
//! configured [`ReputationFeed`] sources and publishes a snapshot via
//! [`ReputationWriter`](waf_state_redis::ReputationWriter), gated by a per-cycle single-writer lock.
//!
//! ## Frozen decisions this driver encodes
//! - **F4 — single-writer, per-cycle lock, no heartbeat**: each cycle a node tries to `acquire` the
//!   [`DistributedLock`]; only the winner (leader) fetches + writes, so N nodes don't each hit the
//!   (possibly-metered) source. Followers do nothing and re-poll next cycle — they never leave the
//!   loop. A dead leader just means another node acquires next cycle; **liveness is the entries'
//!   TTL (F2), not lock ownership**, so no heartbeat/extend is needed.
//! - **F2 — TTL snapshot**: the leader writes with `entry_ttl` (a few refresh cycles wide); a
//!   missed cycle never drops still-listed IPs, and a fully-down feed lets everything age out to
//!   `Unknown` (fail-to-no-opinion).
//! - Source fetch errors are **isolated**: one source failing keeps the others (never clears).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, warn};
use waf_state_redis::{DistributedLock, ReputationWriter};

use crate::ReputationFeed;

/// The lock name (namespaced to `feed_lock:` inside the store) all nodes contend on so exactly one
/// publishes per cycle.
const FEED_LOCK_NAME: &str = "reputation-feed";

/// Runtime tunables for the feed driver (wired from `[enterprise.reputation.feed]`).
#[derive(Clone, Copy, Debug)]
pub struct FeedConfig {
    /// Sleep between cycles.
    pub refresh_interval: Duration,
    /// TTL applied to each written `rep:<ip>` entry — sized a few refresh cycles wide (F2) so a
    /// single missed/failed cycle never drops still-listed IPs.
    pub entry_ttl: Duration,
    /// TTL of the per-cycle single-writer lock — roughly the worst-case fetch+write time (F4).
    pub lock_ttl: Duration,
}

impl Default for FeedConfig {
    fn default() -> Self {
        let refresh = Duration::from_secs(300);
        Self {
            refresh_interval: refresh,
            entry_ttl: refresh * 3,
            lock_ttl: Duration::from_secs(90),
        }
    }
}

/// A per-process holder token for the lock: distinct enough across nodes that `release`'s
/// compare-and-delete only ever frees our own lock. Process id + a wall-clock nonce.
fn make_node_id() -> String {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{}-{}", std::process::id(), nanos)
}

/// Run a single feed cycle. Returns `true` if we were the leader (acquired the lock and published),
/// `false` if a follower this cycle. Factored out of the loop so the single-writer + fetch-isolation
/// behaviour is bite-tested deterministically, without spawning or sleeping.
async fn run_cycle(
    sources: &[Box<dyn ReputationFeed>],
    writer: &dyn ReputationWriter,
    lock: &dyn DistributedLock,
    cfg: &FeedConfig,
    node_id: &str,
) -> bool {
    if !lock.acquire(FEED_LOCK_NAME, node_id, cfg.lock_ttl) {
        // Follower: another node is publishing this cycle. Do nothing — the existing entries stay
        // valid via their TTL. Never leave the loop.
        return false;
    }
    // Leader: gather every source. A failing source is isolated (keep the rest); we never clear a
    // snapshot because a feed hiccuped.
    let mut entries = Vec::new();
    for source in sources {
        match source.fetch().await {
            Ok(mut e) => entries.append(&mut e),
            Err(err) => {
                warn!(source = source.name(), error = %err, "reputation feed: source fetch failed — keeping previous snapshot");
            }
        }
    }
    // The writer dedups (strongest verdict per IP) and drops `Unknown` internally, so we can hand it
    // the raw concatenation of all sources.
    let written = writer.apply_snapshot(&entries, cfg.entry_ttl);
    lock.release(FEED_LOCK_NAME, node_id);
    info!(node = node_id, sources = sources.len(), written, "reputation feed: snapshot published");
    true
}

/// Spawn the feed driver as a background task. Each `refresh_interval` a single node (the lock
/// winner) refreshes the `rep:<ip>` snapshot the reputation module reads. `sources`, `writer` and
/// `lock` are typically all backed by the SAME `RedisStore`. Returns the task handle (drop to keep
/// it running for the process lifetime).
pub fn start_reputation_feed(
    sources: Vec<Box<dyn ReputationFeed>>,
    writer: Arc<dyn ReputationWriter>,
    lock: Arc<dyn DistributedLock>,
    cfg: FeedConfig,
) -> JoinHandle<()> {
    let node_id = make_node_id();
    info!(node = %node_id, sources = sources.len(), "reputation feed: starting driver");
    tokio::spawn(async move {
        loop {
            run_cycle(&sources, writer.as_ref(), lock.as_ref(), &cfg, &node_id).await;
            sleep(cfg.refresh_interval).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use waf_state_redis::Reputation;

    use super::*;
    use crate::FeedError;

    /// A shared in-memory lock with faithful single-holder semantics (owner-scoped release), enough
    /// to prove the driver's leader/follower behaviour without Redis.
    #[derive(Default)]
    struct MockLock {
        holder: Mutex<Option<String>>,
    }
    impl DistributedLock for MockLock {
        fn acquire(&self, _name: &str, holder: &str, _ttl: Duration) -> bool {
            let mut h = self.holder.lock().unwrap();
            if h.is_none() {
                *h = Some(holder.to_string());
                true
            } else {
                false
            }
        }
        fn release(&self, _name: &str, holder: &str) {
            let mut h = self.holder.lock().unwrap();
            if h.as_deref() == Some(holder) {
                *h = None;
            }
        }
    }

    /// Records every `apply_snapshot` call so a test can assert who wrote (and what).
    #[derive(Default)]
    struct MockWriter {
        calls: Mutex<Vec<Vec<(IpAddr, Reputation)>>>,
    }
    impl ReputationWriter for MockWriter {
        fn apply_snapshot(&self, entries: &[(IpAddr, Reputation)], _ttl: Duration) -> usize {
            self.calls.lock().unwrap().push(entries.to_vec());
            entries.len()
        }
    }

    struct OkFeed(&'static str, Vec<(IpAddr, Reputation)>);
    #[async_trait]
    impl ReputationFeed for OkFeed {
        fn name(&self) -> &str {
            self.0
        }
        async fn fetch(&self) -> Result<Vec<(IpAddr, Reputation)>, FeedError> {
            Ok(self.1.clone())
        }
    }

    struct ErrFeed;
    #[async_trait]
    impl ReputationFeed for ErrFeed {
        fn name(&self) -> &str {
            "err"
        }
        async fn fetch(&self) -> Result<Vec<(IpAddr, Reputation)>, FeedError> {
            Err(FeedError::Http("boom".into()))
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// THE contention bite-test (the feed analogue of the cert single-writer test): with the lock
    /// already held by another node, a node's cycle is a FOLLOWER and writes nothing; once free, a
    /// node's cycle is LEADER and publishes. Exactly one writer acts per cycle.
    #[tokio::test]
    async fn only_the_lock_holder_publishes_per_cycle() {
        let lock = MockLock::default();
        let writer = MockWriter::default();
        let cfg = FeedConfig::default();
        let sources: Vec<Box<dyn ReputationFeed>> =
            vec![Box::new(OkFeed("s", vec![(ip("1.2.3.4"), Reputation::Malicious)]))];

        // Node B tries while "other" holds the lock ⇒ follower, no write.
        assert!(lock.acquire(FEED_LOCK_NAME, "other", cfg.lock_ttl), "someone else holds it");
        let was_leader = run_cycle(&sources, &writer, &lock, &cfg, "B").await;
        assert!(!was_leader, "B must be a follower while the lock is held");
        assert!(writer.calls.lock().unwrap().is_empty(), "a follower must NOT write");

        // Free the lock; now node A's cycle is the leader and publishes exactly once.
        lock.release(FEED_LOCK_NAME, "other");
        let was_leader = run_cycle(&sources, &writer, &lock, &cfg, "A").await;
        assert!(was_leader, "A must lead once the lock is free");
        let calls = writer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "leader publishes exactly one snapshot");
        assert_eq!(calls[0], vec![(ip("1.2.3.4"), Reputation::Malicious)]);
    }

    /// A leader releases the lock at the end of its cycle, so the next cycle can be led by anyone
    /// (including a different node) — no permanent ownership.
    #[tokio::test]
    async fn leader_releases_so_next_cycle_is_contendable() {
        let lock = MockLock::default();
        let writer = MockWriter::default();
        let cfg = FeedConfig::default();
        let sources: Vec<Box<dyn ReputationFeed>> = vec![Box::new(OkFeed("s", vec![]))];

        assert!(run_cycle(&sources, &writer, &lock, &cfg, "A").await, "A leads");
        assert!(run_cycle(&sources, &writer, &lock, &cfg, "B").await, "B can lead next cycle");
    }

    /// Fetch isolation: one source erroring keeps the others — the snapshot is the surviving
    /// entries, never cleared because a feed hiccuped.
    #[tokio::test]
    async fn a_failing_source_does_not_sink_the_others() {
        let lock = MockLock::default();
        let writer = MockWriter::default();
        let cfg = FeedConfig::default();
        let good = (ip("9.9.9.9"), Reputation::Suspicious);
        let sources: Vec<Box<dyn ReputationFeed>> =
            vec![Box::new(ErrFeed), Box::new(OkFeed("good", vec![good])), Box::new(ErrFeed)];

        assert!(run_cycle(&sources, &writer, &lock, &cfg, "A").await);
        let calls = writer.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], vec![good], "only the surviving source's entries are published");
    }
}
