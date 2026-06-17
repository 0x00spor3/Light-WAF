use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::warn;
use waf_core::{Config, Decision, Phase, RateLimitAction, RateLimitKey, RequestContext, WafModule};

// ── clock (injectable for deterministic tests) ────────────────────────────────

/// Monotonic time source. `Instant` is opaque in Rust, so `ManualClock` starts
/// from a real `Instant::now()` and advances by adding `Duration` — it never
/// constructs arbitrary instants.
pub trait Clock: Send + Sync {
    fn now(&self) -> Instant;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Test clock: advances explicitly via `advance`.
pub struct ManualClock {
    base: Instant,
    offset: Mutex<Duration>,
}

impl ManualClock {
    pub fn new() -> Self {
        Self { base: Instant::now(), offset: Mutex::new(Duration::ZERO) }
    }
    pub fn advance(&self, by: Duration) {
        *self.offset.lock().unwrap() += by;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.base + *self.offset.lock().unwrap()
    }
}

// ── token bucket ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Bucket {
    tokens: f64,
    last: Instant,
}

struct RlState {
    buckets: HashMap<String, Bucket>,
}

// ── module ────────────────────────────────────────────────────────────────────

pub struct RateLimitModule {
    enabled: bool,
    capacity: f64,
    refill_per_sec: f64,
    action: RateLimitAction,
    score: u32,
    key: RateLimitKey,
    max_tracked_keys: usize,
    clock: Arc<dyn Clock>,
    state: Mutex<RlState>,
}

impl Default for RateLimitModule {
    fn default() -> Self {
        Self::with_clock(Arc::new(SystemClock))
    }
}

impl RateLimitModule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with a custom clock (used by tests).
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            enabled: false,
            capacity: 0.0,
            refill_per_sec: 0.0,
            action: RateLimitAction::Block,
            score: 0,
            key: RateLimitKey::ClientIp,
            max_tracked_keys: 0,
            clock,
            state: Mutex::new(RlState { buckets: HashMap::new() }),
        }
    }

    /// Number of currently tracked keys (for tests/metrics).
    pub fn tracked_keys(&self) -> usize {
        self.state.lock().unwrap().buckets.len()
    }

    fn key_for(&self, ctx: &RequestContext) -> String {
        match self.key {
            // Peer socket address. Behind an LB/CDN this is the proxy IP — see
            // ARCHITECTURE §8 (X-Forwarded-For + trusted hops is the extension).
            RateLimitKey::ClientIp => ctx.client_ip.to_string(),
        }
    }

    /// Seconds until at least one token is available again (>= 1).
    fn retry_after(&self, tokens: f64) -> u64 {
        if self.refill_per_sec <= 0.0 {
            return 1;
        }
        ((1.0 - tokens) / self.refill_per_sec).ceil().max(1.0) as u64
    }

    /// Drop idle (fully refilled) buckets. A bucket whose elapsed time exceeds
    /// the full-refill duration is back at capacity — indistinguishable from a
    /// fresh key — so it is safe to evict.
    fn sweep_full_buckets(&self, buckets: &mut HashMap<String, Bucket>, now: Instant) {
        if self.refill_per_sec <= 0.0 {
            return;
        }
        let full_refill = Duration::from_secs_f64(self.capacity / self.refill_per_sec);
        buckets.retain(|_, b| now.duration_since(b.last) < full_refill);
    }
}

impl WafModule for RateLimitModule {
    fn id(&self) -> &str {
        "rate_limit"
    }

    fn phase(&self) -> Phase {
        Phase::Connection
    }

    fn init(&mut self, cfg: &Config) {
        let rl = &cfg.rate_limit;
        self.enabled = rl.enabled;
        self.capacity = rl.burst.unwrap_or(rl.requests).max(1) as f64;
        let window = rl.window_seconds.max(1) as f64;
        self.refill_per_sec = rl.requests as f64 / window;
        self.action = rl.action;
        self.score = rl.score;
        self.key = rl.key;
        self.max_tracked_keys = rl.max_tracked_keys.max(1);
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.enabled {
            return Decision::Allow;
        }

        let key = self.key_for(ctx);
        let now = self.clock.now();

        let tokens_after = {
            let mut state = self.state.lock().unwrap();

            // Bound memory: before tracking a brand-new key at the cap, evict
            // idle (fully refilled) buckets.
            if !state.buckets.contains_key(&key) && state.buckets.len() >= self.max_tracked_keys {
                self.sweep_full_buckets(&mut state.buckets, now);
            }

            let bucket = state.buckets.entry(key.clone()).or_insert(Bucket {
                tokens: self.capacity,
                last: now,
            });

            // Refill based on elapsed time.
            let elapsed = now.duration_since(bucket.last).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
            bucket.last = now;

            if bucket.tokens >= 1.0 {
                bucket.tokens -= 1.0;
                return Decision::Allow;
            }
            bucket.tokens
        };

        // Over budget.
        match self.action {
            RateLimitAction::Block => {
                let retry = self.retry_after(tokens_after);
                warn!(
                    request_id = %ctx.request_id,
                    key = %key,
                    retry_after = retry,
                    "rate limit exceeded (block)"
                );
                Decision::Reject {
                    rule_id: "rate-limit".to_string(),
                    reason: "rate limit exceeded".to_string(),
                    status: 429,
                    retry_after: Some(retry),
                }
            }
            RateLimitAction::Score => {
                warn!(
                    request_id = %ctx.request_id,
                    key = %key,
                    points = self.score,
                    "rate limit exceeded (score)"
                );
                Decision::Score {
                    rule_id: "rate-limit-exceeded".to_string(),
                    points: self.score,
                }
            }
        }
    }
}
