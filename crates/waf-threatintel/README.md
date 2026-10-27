# waf-threatintel

Threat intelligence for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**: cluster-wide IP
reputation, in two halves.

- **Read** — `ReputationModule`, a detection module that runs at the connection phase, looks up the
  client IP in a `ReputationStore` and adds a severity to the request's anomaly score
  (`Malicious` / `Suspicious`; `Unknown` adds nothing). It uses the same cumulative scoring as every
  other module — no separate blocking logic.
- **Write** — `start_reputation_feed`, a background driver that polls reputation sources
  (`FileFeed`, `HttpListFeed`: one IP per line, one verdict per source) and populates the store.
  A per-cycle distributed lock makes a single node fetch and write per cycle; entries carry a TTL,
  so a de-listed IP ages out and a feed that goes down lets everything expire back to `Unknown`.

The store is normally a [`waf-state-redis`](https://crates.io/crates/waf-state-redis)
`RedisStore`, the same one that backs cluster-wide rate limiting.

## Usage

```rust
use std::sync::Arc;
use waf_threatintel::{ReputationConfig, ReputationModule};

// `store`: an Arc<RedisStore> (it implements ReputationStore)
let module = ReputationModule::new(store.clone(), ReputationConfig::default());
let proxy = waf_proxy::Proxy::builder(&config)
    .add_module(Box::new(module))
    .build()
    .await?;
```

With the `waf-enterprise` binary: `[enterprise.reputation]` (`enabled`, `malicious_severity`,
`suspicious_severity`) and `[enterprise.reputation.feed]` (`refresh_interval_secs`,
`entry_ttl_secs`, `sources = [{ kind, location, verdict }]`). A node can run the feed without the
module, as a pure writer for the others.

## Behavior

- **Fail to no opinion**: if Redis is unreachable the lookup returns `Unknown` and the request is
  inspected as usual — a reputation outage neither blocks nor unblocks traffic.
- **Exact IPs only** for now: CIDR entries in a feed are skipped with a warning.

## License

Apache-2.0. Part of [Light WAF](https://github.com/0x00spor3/Light-WAF); see
[`ARCHITECTURE_ENTERPRISE.md`](https://github.com/0x00spor3/Light-WAF/blob/main/ARCHITECTURE_ENTERPRISE.md) §3 and §6.
