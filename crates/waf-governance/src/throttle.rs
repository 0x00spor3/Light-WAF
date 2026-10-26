// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! In-memory login brute-force throttle (v2). Per-key (username) sliding-window failure counting: at
//! or above `max_failures` within `window`, the key is locked for `lockout`. A success clears it.
//!
//! Per-process (single control-plane instance); a cluster-wide throttle on a shared store is a
//! follow-on. The time source is a parameter (`now`) so the logic is deterministic in tests.

use std::collections::HashMap;
use std::sync::Mutex;

use time::{Duration, OffsetDateTime};

#[derive(Default)]
struct Attempts {
    /// Failure timestamps within the current window.
    failures: Vec<OffsetDateTime>,
    /// When set and in the future, the key is locked out.
    locked_until: Option<OffsetDateTime>,
}

/// Tracks recent failed logins per key and decides whether a key is currently locked out.
pub struct LoginThrottle {
    max_failures: u32,
    window: Duration,
    lockout: Duration,
    state: Mutex<HashMap<String, Attempts>>,
}

impl LoginThrottle {
    /// `max_failures` failures within `window_secs` → locked out for `lockout_secs`.
    pub fn new(max_failures: u32, window_secs: u64, lockout_secs: u64) -> Self {
        Self {
            max_failures,
            window: Duration::seconds(window_secs as i64),
            lockout: Duration::seconds(lockout_secs as i64),
            state: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `key` is allowed to attempt a login at `now` (false = currently locked out).
    pub fn allowed(&self, key: &str, now: OffsetDateTime) -> bool {
        let state = self.state.lock().unwrap();
        !matches!(state.get(key).and_then(|a| a.locked_until), Some(until) if until > now)
    }

    /// Record a failed attempt for `key`; locks the key if the window threshold is reached.
    pub fn record_failure(&self, key: &str, now: OffsetDateTime) {
        let mut state = self.state.lock().unwrap();
        let a = state.entry(key.to_string()).or_default();
        let cutoff = now - self.window;
        a.failures.retain(|&t| t > cutoff);
        a.failures.push(now);
        if a.failures.len() as u32 >= self.max_failures {
            a.locked_until = Some(now + self.lockout);
            a.failures.clear();
        }
    }

    /// Clear a key's failures + lock (called on a successful login).
    pub fn record_success(&self, key: &str) {
        self.state.lock().unwrap().remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000 + secs).unwrap()
    }

    #[test]
    fn locks_after_threshold_then_unlocks() {
        // 3 failures in 60s → locked for 300s.
        let th = LoginThrottle::new(3, 60, 300);
        assert!(th.allowed("bob", t(0)));
        th.record_failure("bob", t(1));
        th.record_failure("bob", t(2));
        assert!(th.allowed("bob", t(3)), "not yet at threshold");
        th.record_failure("bob", t(3)); // 3rd → lock until t(303)
        assert!(!th.allowed("bob", t(4)), "locked out");
        assert!(!th.allowed("bob", t(300)), "still locked");
        assert!(th.allowed("bob", t(304)), "lockout expired");
    }

    #[test]
    fn old_failures_fall_out_of_window() {
        let th = LoginThrottle::new(3, 60, 300);
        th.record_failure("ann", t(0));
        th.record_failure("ann", t(1));
        // This failure is >60s after the first → the first is dropped, so only 2 in-window: no lock.
        th.record_failure("ann", t(120));
        assert!(th.allowed("ann", t(121)));
    }

    #[test]
    fn success_clears_failures() {
        let th = LoginThrottle::new(2, 60, 300);
        th.record_failure("cat", t(0));
        th.record_success("cat");
        th.record_failure("cat", t(1));
        assert!(th.allowed("cat", t(2)), "one failure after a reset is fine");
    }

    #[test]
    fn keys_are_independent() {
        let th = LoginThrottle::new(1, 60, 300);
        th.record_failure("x", t(0)); // locks x
        assert!(!th.allowed("x", t(1)));
        assert!(th.allowed("y", t(1)), "y is unaffected");
    }
}
