# waf-enterprise — the enterprise binary

Implementations of the **at-scale** seams that the core leaves as traits. See
[`BOUNDARY.md`](../../BOUNDARY.md) §2/§4: the core defines the extension points, the
enterprise crates provide the distributed/governed implementations — **injected via
`Proxy::builder` without forking the core**.

The enterprise crates only ever use the core's public API (they never reach into its
internals), so they stay a library on top of the core even though both now live in the
same workspace.

## Documentation

- **[Operator Guide](../../docs/README.md)** — the functional/operational manual: concepts, getting started,
  full WAF + control-plane configuration, rule management, governance, compliance, SIEM, and day-2 ops.
- [`ARCHITECTURE_ENTERPRISE.md`](../../ARCHITECTURE_ENTERPRISE.md) / [`BOUNDARY.md`](../../BOUNDARY.md) — design
  rationale and the enterprise/core boundary.
- [`scripts/*/RUNBOOK.md`](../../scripts) — per-feature copy-paste runbooks.
- [`examples/enterprise.toml`](../../examples/enterprise.toml) — a complete sample configuration.

## Crates

| Crate | What it is | Seam (core trait) |
|---|---|---|
| `waf-state-redis` | Distributed rate-limit `StateStore` backed by Redis (cluster-wide token bucket) | `waf_core::StateStore` (BOUNDARY §2.1) |
| `waf-tls-managed` | Managed TLS: hitless ACME server certs (TLS-ALPN-01) + mTLS client auth | `waf_proxy::tls::TlsCertSource` `resolver()`/`client_verifier()` (BOUNDARY §3.2) |
| `waf-enterprise`  | Thin binary that wires the seams via `Proxy::builder` + SIGHUP | — |

The published OPEN binary (`waf`) calls `Proxy::bind` directly, so it cannot load
enterprise seams. `waf-enterprise` exists precisely because the **builder is the
only extension point** (BOUNDARY §4): it reuses `waf_proxy::config` for loading,
then injects the Redis store when configured.

## Configuration

Enterprise settings live in an **`[enterprise]`** table of the **same** config file.
The OPEN `waf_core::Config` ignores that table (it has no enterprise fields and no
`deny_unknown_fields`); `waf-enterprise` re-parses the file to read it — so the
enterprise knobs stay out of the OPEN schema while living in one file.

```toml
# … the usual [proxy] / [waf] / [rate_limit] sections (the bucket policy —
#    requests / window_seconds / burst — comes from [rate_limit], unchanged) …

[rate_limit]
enabled = true            # required for the Redis store to be wired
requests = 100
window_seconds = 60

[enterprise]
redis_url = "redis://10.0.0.5:6379"   # absent ⇒ in-memory single-node store
pool_size = 32                        # optional; default 16
fail_open  = true                     # Redis error at runtime ⇒ allow (default).
                                      # false ⇒ deny (fail-closed).
```

The Redis store sets only **where** the token-bucket state lives; the **policy**
(capacity / refill / burst) is the OPEN `[rate_limit]` section, untouched.

`WAF_REDIS_URL` (env) **overrides** `[enterprise].redis_url` for ops/CI; pool size
and posture still come from the file.

## Run (distributed rate limiting)

```sh
docker run -d -p 6379:6379 redis            # reachable by every WAF node
cargo run -p waf-enterprise -- --config prod.toml   # [enterprise].redis_url set
```

- With `redis_url` set, the rate-limit bucket is **cluster-wide**: two WAF processes
  sharing the same Redis throttle the same client IP jointly.
- Without it, the proxy falls back to the OPEN in-memory store (single-node) — the
  builder with no override equals `Proxy::bind`.

## Design notes (verbale)

- **Atomicity (no cluster-wide over-allow).** `try_acquire` runs a single Lua script
  (refill-by-elapsed + try-consume + TTL) so two nodes can never both allow from the
  same bucket (no TOCTOU). Server time comes from Redis `TIME`; memory is bounded by
  per-key TTL — both outside the core ABI, as the trait intends.
- **Fail-OPEN on Redis error (default; configurable).** `StateStore::try_acquire` has no
  error channel, so the store owns its resilience: if Redis errors at runtime, the request
  is **allowed** (loud warn). A down rate-limiter must not block legitimate traffic — the
  opposite of the security modules' fail-closed, correct because state is infrastructure,
  not detection. Set `[enterprise].fail_open = false` to deny instead. A misconfigured /
  unreachable Redis at **boot** is always fatal, so it never silently degrades to single-node.
- **NOSCRIPT recovery.** Uses `redis::Script`, which retries with `EVAL` if Redis lost
  the cached script (restart / `SCRIPT FLUSH` / replica failover).
- **Sync seam on an async datapath.** `try_acquire` is synchronous (the core's atomic
  ABI); the blocking pooled Redis call is wrapped in `tokio::task::block_in_place` when
  a multi-threaded runtime is present, so a slow Redis does not starve other tasks on
  the worker. The per-request round-trip is the declared cost of the distributed tier
  (size `worker_threads` accordingly); a local best-effort cache in front of Redis is a
  roadmap item.
- **Reload survival.** An injected `state_store` survives `SIGHUP` (it lives in the
  proxy's process-lifetime state and is reused by the reloader) — so distributed rate
  limiting is not silently reset to single-node on a config reload.
