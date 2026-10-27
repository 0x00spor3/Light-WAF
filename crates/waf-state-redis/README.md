# waf-state-redis

Distributed state for **[Light WAF](https://github.com/0x00spor3/Light-WAF)** over Redis. One
`RedisStore` (one connection pool) provides:

- **cluster-wide rate limiting** — an implementation of the core's `waf_core::StateStore` trait,
  so every WAF node throttles the same client from the same token bucket;
- **IP reputation** — the `ReputationStore` (read) and `ReputationWriter` (write) traits used by
  [`waf-threatintel`](https://crates.io/crates/waf-threatintel);
- **a shared certificate store** — `SharedCertStore` + `DistributedLock`, used by
  [`waf-tls-managed`](https://crates.io/crates/waf-tls-managed) so one node issues an ACME
  certificate and every node serves it (private key encrypted at rest with AES-256-GCM).

## Usage

Inject it into the proxy through the core's builder — no fork of the core:

```rust
use std::sync::Arc;
use waf_state_redis::{RedisStore, RedisStoreOptions};

let store = Arc::new(RedisStore::connect_with_options("redis://10.0.0.5:6379", RedisStoreOptions::default())?);
let proxy = waf_proxy::Proxy::builder(&config)
    .state_store(store)          // the rate-limit policy still comes from [rate_limit]
    .build()
    .await?;
```

The `waf-enterprise` binary does this for you from the `[enterprise]` config table
(`redis_url`, `pool_size`, `fail_open`; `WAF_REDIS_URL` overrides the URL).

## Behavior

- **Atomic**: refill-then-consume runs in a single server-side Lua script, so two nodes can never
  both allow from the same bucket. Time comes from Redis `TIME`; memory is bounded by per-key TTL.
- **Fail-open at runtime (default, configurable)**: if Redis errors, the request is allowed with a
  warning — a down rate limiter must not block legitimate traffic. Set `fail_open = false` to deny
  instead. An unreachable Redis at **boot** is always fatal, so the store never silently degrades
  to single-node.
- **Reload-safe**: the buckets live in Redis, so a node reload or restart does not reset them.

## License

Apache-2.0. Part of [Light WAF](https://github.com/0x00spor3/Light-WAF); see
[`ARCHITECTURE_ENTERPRISE.md`](https://github.com/0x00spor3/Light-WAF/blob/main/ARCHITECTURE_ENTERPRISE.md) §3.
