<!-- SPDX-License-Identifier: BUSL-1.1 -->
# Runbook — env-gated tests for §3 (distributed state on Redis)

Proves ARCHITECTURE_ENTERPRISE **§3** (+ the §6 feed that populates it) against a real Redis:

1. **Distributed rate-limit** `StateStore` — cluster-wide token bucket, atomic (no over-allow).
2. **IP-reputation read** — `ReputationStore` lookups of the `rep:<ip>` keyspace.
3. **Threat-intel feed (write)** — `ReputationWriter` + single-writer `DistributedLock` that
   *populate* `rep:<ip>`.

Two layers of proof:
- **A. Integration tests** (`cargo test`, env-gated on `WAF_REDIS_URL`) — atomicity, oracle parity,
  the feed write≡read contract, the feed lock. Deterministic, seconds to run.
- **B. Two-node live** (`two_node_ratelimit_429.sh`) — two real WAF processes sharing one Redis
  drain **one** budget. The wire proof that the store is cluster-wide.
- **C. Feed end-to-end** (manual) — a running node's feed populates `rep:<ip>`, verified with
  `redis-cli`.

Everything is opt-in and default-off; none of it touches the OPEN datapath (validation stays 10/10).

---

## 0. Prerequisites

- **Docker** (for Redis) and optionally `redis-cli`.
- `bash` + `curl` (for the two-node script).
- Build once: `cargo build -p waf-enterprise` (repo root: `enterprise/`).

## 1. Start a Redis

```sh
docker run -d --rm --name waf-redis -p 6379:6379 redis:7
docker exec waf-redis redis-cli ping    # -> PONG
```

`--rm` makes it ephemeral (removed on stop). Use a persistent one if you want the keys to survive.

---

## A. Integration tests (deterministic, env-gated)

The suite lives in `enterprise/crates/waf-state-redis/tests/redis.rs`. Without `WAF_REDIS_URL` every
test **skips** with a note (so the normal `cargo test` stays green offline). With it set, they run.

```sh
cd enterprise
WAF_REDIS_URL=redis://127.0.0.1:6379 cargo test -p waf-state-redis --test redis
# expect: test result: ok. 9 passed
```

Run a subset by name filter (cargo runs any test whose name contains an argument):

```sh
# just the feed tests:
WAF_REDIS_URL=redis://127.0.0.1:6379 cargo test -p waf-state-redis --test redis feed
# just reputation + rate-limit (skip the cert ones):
WAF_REDIS_URL=redis://127.0.0.1:6379 cargo test -p waf-state-redis --test redis reputation allow concurrent survives
```

What each test proves:

| Test | §  | Proves |
|------|----|--------|
| `allow_deny_matches_in_memory_oracle`            | 3 | Redis decisions == the in-memory oracle under the same controlled clock (the store is a faithful distributed version of OPEN). |
| `concurrent_grants_exactly_capacity`             | 3 | **Atomicity**: 8 threads × 25 attempts on capacity 50 grant **exactly 50** — no cluster-wide over-allow / TOCTOU (the whole reason the Lua script exists). |
| `survives_script_flush_noscript`                 | 3 | NOSCRIPT recovery: after `SCRIPT FLUSH`, `EVALSHA`→`EVAL` fallback keeps working (failover-safe). |
| `reputation_reads_seeded_values`                 | 3 | Reputation read: seeded `rep:<ip>` = `malicious`/`suspicious`/absent → the right verdict. |
| `feed_write_is_read_back_by_reputation_and_expires_to_unknown` | 6→3 | **F1 contract on the wire**: what the feed writes (`apply_snapshot`) is exactly what the datapath reads (`reputation`) — same key, same value — and a short-TTL entry ages back to `Unknown` (**F2**). |
| `feed_lock_is_single_writer_owner_scoped_and_expires` | 6→3 | **F4**: the `feed_lock:` lock is single-holder, release is owner-scoped, and a dead leader's lock frees via PX expiry (own namespace ⇒ never collides with a cert lock). |

> The same file also carries the **§5** cert-store wire tests (`issuance_lock_*`,
> `dead_leader_lock_expires_on_the_wire`, `store_cert_requires_the_lock_and_round_trips_encrypted`).
> They run in the same command and prove the SharedCertStore lock/CAS + encryption-at-rest — useful
> as a regression check whenever `certstore.rs` changes.

---

## B. Two-node live rate-limit (cluster-wide proof)

Driver script (OPEN tree, drives HTTP only): `scripts/redis/two_node_ratelimit_429.sh`.
It fires the same concurrent load at two nodes until **both** return `429`, then reports totals.

### B.1 A dummy backend (so un-limited requests get a 200, not a 502)

```sh
python3 -m http.server 3000        # any simple HTTP server on :3000
```

### B.2 Two node configs (identical rate-limit + network, DISTINCT ports)

`node-a.toml`:
```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode = "blocking"                  # detection-only would LOG, not 429

[rate_limit]
enabled        = true
requests       = 50
window_seconds = 60                # ~0.83 tok/s refill — slow vs the burst, so 429 lands
burst          = 50

[network]
trusted_proxies = []               # both nodes resolve the SAME client IP ⇒ SAME bucket key

[metrics]
enabled = true
listen  = "127.0.0.1:9090"         # GOTCHA: metrics port MUST differ between nodes (else AddrInUse)

[enterprise]
redis_url = "redis://127.0.0.1:6379"
```

`node-b.toml` = copy of `node-a.toml` with `listen = "127.0.0.1:8081"` and
`[metrics].listen = "127.0.0.1:9091"`. Everything else identical.

```sh
# generate node-b from node-a:
sed -e 's/8080/8081/' -e 's/9090/9091/' node-a.toml > node-b.toml
```

### B.3 Run

```sh
# two terminals (or background them):
WAF_CONFIG=node-a.toml cargo run -p waf-enterprise
WAF_CONFIG=node-b.toml cargo run -p waf-enterprise

# a third terminal — drive both to 429:
PORT_A=8080 PORT_B=8081 CONCURRENCY=25 scripts/redis/two_node_ratelimit_429.sh
```

### B.4 What to observe

- **With Redis (as above)** — the two nodes share ONE bucket: first `429` lands after **~50**
  admitted requests across BOTH nodes combined (`sum` in the report ≈ one budget). This is the
  cluster-wide signature.
- **Control, WITHOUT Redis** — comment out `[enterprise].redis_url` on both nodes (they fall back to
  the OPEN in-memory store) and re-run: budgets are independent, so **~2×** admitted (`sum` ≈ two
  budgets) before both 429. The difference (~1× vs ~2×) is the proof.
- No `sum` above one budget with Redis on ⇒ **atomic** across processes (the wire version of
  `concurrent_grants_exactly_capacity`).

---

## C. Feed end-to-end (manual — the write path through config + wiring)

Proves the §6 feed populates `rep:<ip>` for real (not just the unit round-trip). Uses a fast refresh
so you see it within seconds.

### C.1 A blocklist file

```sh
printf '203.0.113.66\n# a comment\n198.51.100.9\n' > /tmp/blocklist.txt
```

### C.2 A node config with reputation + a file feed source

`feed-node.toml`:
```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"
[waf]
mode = "blocking"

[enterprise]
redis_url = "redis://127.0.0.1:6379"

[enterprise.reputation]
enabled = true

[enterprise.reputation.feed]
enabled               = true
refresh_interval_secs = 5          # fast, just for the demo
lock_ttl_secs         = 10

[[enterprise.reputation.feed.sources]]
kind     = "file"
location = "/tmp/blocklist.txt"
verdict  = "malicious"
```

### C.3 Run and verify

```sh
WAF_CONFIG=feed-node.toml cargo run -p waf-enterprise
# log: "starting threat-intel reputation feed (single-writer)" then "snapshot published"

# after one cycle (~5s):
docker exec waf-redis redis-cli GET rep:203.0.113.66     # -> "malicious"
docker exec waf-redis redis-cli TTL rep:203.0.113.66     # -> ~15 (3× refresh)
docker exec waf-redis redis-cli GET rep:198.51.100.9     # -> "malicious"
```

- Remove an IP from `/tmp/blocklist.txt`, wait past `entry_ttl` (3× refresh ≈ 15s): its key ages out
  (`GET` → nil) → back to `Unknown` (**F2**, de-listing via TTL).
- Multi-node: start a second node with the SAME feed config against the SAME Redis — only ONE logs
  `snapshot published` per cycle; the other is a follower (**F4**, single-writer). A dedicated
  feed-writer node can even set `[enterprise.reputation].enabled = false` (it only populates).

---

## Cleanup

```sh
docker stop waf-redis          # --rm ⇒ auto-removed
rm -f node-a.toml node-b.toml feed-node.toml /tmp/blocklist.txt
```

## Troubleshooting

- **Tests all "skipping: WAF_REDIS_URL not set"** — the env var isn't exported into the `cargo`
  process. Set it inline: `WAF_REDIS_URL=redis://127.0.0.1:6379 cargo test …`.
- **`cannot reach Redis (PING failed)`** at node boot — a configured-but-unreachable Redis is
  **fatal by design** (silently degrading would be "looks-protected-but-isn't"). Start Redis first.
- **Two-node script TIMEOUTs (never 429)** — refill is outpacing the burst. Lower `requests` /
  raise `window_seconds`, or raise `CONCURRENCY`. Confirm both nodes are `mode = "blocking"`.
- **Second node dies with `AddrInUse`** — the `[metrics].listen` port is shared. Give each node its
  own metrics port (the proxy `listen` differing is not enough).
- **`sum` ≈ 2× even with Redis** — the two nodes aren't resolving the same client IP (different
  `[network]` trusted-proxy config ⇒ different bucket keys), or one node isn't actually pointed at
  Redis. Make `[rate_limit]` and `[network]` identical and both `redis_url` the same.
- **Feed: `rep:<ip>` never appears** — check the node logged `snapshot published` (leader) vs
  `converged`/nothing (follower); verify the source path/URL and `verdict = malicious|suspicious`;
  confirm `[enterprise.reputation.feed].enabled = true` AND a `redis_url` is set.
