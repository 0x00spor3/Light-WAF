// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Distributed rate-limit [`StateStore`] backed by Redis — the ENTERPRISE
//! implementation of the core's `waf_core::StateStore` seam (BOUNDARY.md §2.1/§4).
//!
//! The OPEN core ships `InMemoryStateStore` (single-node). This crate plugs a
//! cluster-wide token bucket into the SAME trait, injected via `Proxy::builder`
//! WITHOUT forking the core. Decisions (see crate README / plan):
//!
//! - **Atomic** refill-then-consume in a single Lua script ⇒ no cluster-wide
//!   over-allow (TOCTOU). Time = Redis `TIME`; memory bounded by per-key TTL —
//!   both kept out of the trait ABI, exactly as the A0 design intends.
//! - **Fail-OPEN** on a runtime Redis error (the trait returns `Acquired`, not a
//!   `Result`, so the store owns its resilience): a down limiter must not block
//!   legitimate traffic. The opposite of the security modules' fail-closed,
//!   because state is infrastructure, not detection. A misconfigured URL is
//!   caught at boot ([`RedisStore::connect`] pings) so it never silently degrades.
//! - **NOSCRIPT recovery** via `redis::Script` (EVALSHA → EVAL on cache miss).
//! - **Sync-on-async**: the blocking pooled call is wrapped in `block_in_place`
//!   when a multi-thread runtime is present, so a slow Redis cannot starve the
//!   worker.

use std::fmt;
use std::time::Duration;

use r2d2::Pool;
use redis::{Client, Script};
use tracing::warn;
use waf_core::{Acquired, BucketParams, StateStore};

/// Token-bucket step, executed atomically server-side.
///
/// `KEYS[1]` = bucket key. `ARGV` = capacity, refill/s, cost, ttl(s), now_override
/// (seconds; `0` ⇒ use Redis `TIME`, any positive value is a deterministic
/// test clock). Returns `{allowed(0|1), tokens_remaining(string)}` — tokens is
/// returned as a string so the fractional level survives Redis' Lua→int coercion.
const BUCKET_LUA: &str = r#"
local capacity = tonumber(ARGV[1])
local refill   = tonumber(ARGV[2])
local cost     = tonumber(ARGV[3])
local ttl      = tonumber(ARGV[4])
local now_override = tonumber(ARGV[5])

local now
if now_override > 0 then
  now = now_override
else
  local t = redis.call('TIME')
  now = tonumber(t[1]) + (tonumber(t[2]) / 1000000.0)
end

local data = redis.call('HMGET', KEYS[1], 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = capacity
  ts = now
end

local elapsed = now - ts
if elapsed < 0 then elapsed = 0 end
tokens = math.min(capacity, tokens + (elapsed * refill))

local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end

redis.call('HSET', KEYS[1], 'tokens', tokens, 'ts', now)
if ttl > 0 then
  redis.call('EXPIRE', KEYS[1], ttl)
end

return {allowed, tostring(tokens)}
"#;

/// Default connection pool size. Each in-flight rate-limited request borrows one
/// connection for the duration of the (blocking) round-trip.
const DEFAULT_POOL_SIZE: u32 = 16;

/// How long a borrow waits for a connection before giving up — short on purpose:
/// when Redis is unreachable this bounds the fail-open latency on the datapath.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Tunables for [`RedisStore`] (wired from `[enterprise]` in the config file).
/// Defaults: a pool of [`DEFAULT_POOL_SIZE`] and **fail-open** on runtime Redis
/// errors (a down limiter must not block legitimate traffic).
#[derive(Clone, Copy, Debug)]
pub struct RedisStoreOptions {
    /// Max pooled connections (one is borrowed per in-flight rate-limited request).
    pub pool_size: u32,
    /// Posture when Redis errors at runtime: `true` ⇒ allow (fail-open), `false` ⇒
    /// deny (fail-closed). Boot-time unreachability is always fatal regardless.
    pub fail_open: bool,
}

impl Default for RedisStoreOptions {
    fn default() -> Self {
        Self { pool_size: DEFAULT_POOL_SIZE, fail_open: true }
    }
}

/// A distributed token-bucket [`StateStore`] over Redis.
pub struct RedisStore {
    pool: Pool<Client>,
    script: Script,
    fail_open: bool,
}

impl RedisStore {
    /// Connect with default options and **validate eagerly** (PING). See
    /// [`Self::connect_with_options`].
    pub fn connect(url: &str) -> Result<Self, ConnectError> {
        Self::connect_with_options(url, RedisStoreOptions::default())
    }

    /// Connect with explicit options and **validate eagerly**: an explicitly-configured
    /// Redis that cannot be reached is a BOOT error (the operator asked for distributed
    /// state; silently degrading to in-memory would be "looks-protected-but-isn't").
    /// Runtime errors after a successful connect follow `options.fail_open`.
    pub fn connect_with_options(url: &str, options: RedisStoreOptions) -> Result<Self, ConnectError> {
        let store = Self::connect_lazy_with_options(url, options)?;
        store.ping().map_err(ConnectError::Ping)?;
        Ok(store)
    }

    /// Lazy connect (no eager ping) with default options. Useful when the proxy should
    /// start even if Redis is momentarily down and rely on the per-request posture;
    /// also the seam the fail-open/closed tests use against a dead address.
    pub fn connect_lazy(url: &str) -> Result<Self, ConnectError> {
        Self::connect_lazy_with_options(url, RedisStoreOptions::default())
    }

    /// Lazy connect (no eager ping) with explicit options.
    pub fn connect_lazy_with_options(url: &str, options: RedisStoreOptions) -> Result<Self, ConnectError> {
        let client = Client::open(url).map_err(ConnectError::Client)?;
        // `build_unchecked` does not test connections at build time — we control
        // validation explicitly (eager `ping` in `connect*`, posture at runtime).
        let pool = Pool::builder()
            .max_size(options.pool_size.max(1))
            .connection_timeout(CONNECT_TIMEOUT)
            .build_unchecked(client);
        Ok(Self { pool, script: Script::new(BUCKET_LUA), fail_open: options.fail_open })
    }

    fn ping(&self) -> redis::RedisResult<()> {
        let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
        redis::cmd("PING").query(&mut *conn)
    }

    /// Bucket TTL: long enough for an idle bucket to fully refill, then it is safe to
    /// drop (a fresh key starts at capacity — indistinguishable). No refill ⇒ a fixed
    /// fallback so keys are never immortal.
    fn ttl_secs(params: &BucketParams) -> u64 {
        if params.refill_per_sec > 0.0 {
            (params.capacity / params.refill_per_sec).ceil() as u64 + 1
        } else {
            3600
        }
    }

    /// Run the atomic script. `now_override` is `0.0` in production (server `TIME`),
    /// positive only from deterministic tests.
    fn run(
        &self,
        key: &str,
        cost: f64,
        params: BucketParams,
        now_override: f64,
    ) -> redis::RedisResult<(i64, String)> {
        let exec = || {
            let mut conn = self.pool.get().map_err(pool_to_redis_err)?;
            self.script
                .key(key)
                .arg(params.capacity)
                .arg(params.refill_per_sec)
                .arg(cost)
                .arg(Self::ttl_secs(&params))
                .arg(now_override)
                .invoke::<(i64, String)>(&mut *conn)
        };
        // The seam is sync but the datapath is async: yield the worker to other tasks
        // for the duration of the blocking round-trip when a multi-thread runtime is
        // present. Outside a runtime (unit tests) just block directly.
        match tokio::runtime::Handle::try_current() {
            Ok(_) => tokio::task::block_in_place(exec),
            Err(_) => exec(),
        }
    }

    fn acquire(&self, key: &str, cost: f64, params: BucketParams, now_override: f64) -> Acquired {
        match self.run(key, cost, params, now_override) {
            Ok((allowed, remaining)) => Acquired {
                allowed: allowed == 1,
                tokens_remaining: remaining.parse().unwrap_or(0.0),
            },
            // Posture per `fail_open`. Loud either way so the operator sees the
            // degraded state. Default fail-open: a down limiter must not take the
            // site down (the opposite of the security modules' fail-closed —
            // correct because state is infrastructure, not detection).
            Err(e) if self.fail_open => {
                warn!(error = %e, key = %key, "redis StateStore error — FAILING OPEN (request allowed)");
                Acquired { allowed: true, tokens_remaining: params.capacity }
            }
            Err(e) => {
                warn!(error = %e, key = %key, "redis StateStore error — FAILING CLOSED (request denied)");
                Acquired { allowed: false, tokens_remaining: 0.0 }
            }
        }
    }

    /// Test seam: identical to [`StateStore::try_acquire`] but with an explicit `now`
    /// (seconds) so the token-bucket arithmetic is deterministic against the in-memory
    /// oracle. Production always uses `try_acquire` (server `TIME`).
    pub fn try_acquire_at(&self, key: &str, cost: f64, params: BucketParams, now_secs: f64) -> Acquired {
        self.acquire(key, cost, params, now_secs)
    }
}

impl StateStore for RedisStore {
    fn try_acquire(&self, key: &str, cost: f64, params: BucketParams) -> Acquired {
        self.acquire(key, cost, params, 0.0)
    }
}

/// Map an r2d2 pool error (exhausted / unreachable) into a redis error so the
/// fail-open path in [`RedisStore::acquire`] handles it uniformly.
fn pool_to_redis_err(e: r2d2::Error) -> redis::RedisError {
    redis::RedisError::from((
        redis::ErrorKind::IoError,
        "redis pool unavailable",
        e.to_string(),
    ))
}

/// Why constructing a [`RedisStore`] failed (boot-time only; runtime errors fail-open).
#[derive(Debug)]
pub enum ConnectError {
    /// Malformed connection URL.
    Client(redis::RedisError),
    /// URL parsed but Redis did not answer the eager `PING`.
    Ping(redis::RedisError),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(e) => write!(f, "invalid Redis URL: {e}"),
            Self::Ping(e) => write!(f, "cannot reach Redis (PING failed): {e}"),
        }
    }
}

impl std::error::Error for ConnectError {}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_core::StateStore;

    #[test]
    fn fails_open_when_redis_unreachable() {
        // Nothing listens on this port → every try_acquire must ALLOW (fail-open).
        // Lazy connect (no eager ping) so construction itself does not error here.
        let store = RedisStore::connect_lazy("redis://127.0.0.1:1").expect("url parses");
        let params = BucketParams { capacity: 3.0, refill_per_sec: 1.0 };
        for _ in 0..5 {
            let a = store.try_acquire("any-key", 1.0, params);
            assert!(a.allowed, "rate-limit store MUST fail open when Redis is down");
        }
    }

    #[test]
    fn fails_closed_when_configured() {
        // Same dead port, but fail_open=false → every try_acquire must DENY.
        let opts = RedisStoreOptions { fail_open: false, ..Default::default() };
        let store = RedisStore::connect_lazy_with_options("redis://127.0.0.1:1", opts)
            .expect("url parses");
        let params = BucketParams { capacity: 3.0, refill_per_sec: 1.0 };
        let a = store.try_acquire("any-key", 1.0, params);
        assert!(!a.allowed, "fail_open=false must DENY when Redis is down");
    }

    #[test]
    fn ttl_covers_full_refill() {
        let p = BucketParams { capacity: 100.0, refill_per_sec: 10.0 };
        assert_eq!(RedisStore::ttl_secs(&p), 11); // ceil(100/10)+1
        let none = BucketParams { capacity: 5.0, refill_per_sec: 0.0 };
        assert_eq!(RedisStore::ttl_secs(&none), 3600);
    }
}
