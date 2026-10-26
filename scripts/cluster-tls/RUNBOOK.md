<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — live multi-node cert-sharing (SharedCertStore), Step 5

Proves the multi-node seam end-to-end: two WAF nodes, `[tls.acme].cluster = true`, one shared
Redis. **One** node issues the DNS-01 certificate for the cluster; the other **converges** on it.
Both then serve the *same* certificate — a single Let's Encrypt order, no N× rate-limit, no Route53
TXT clobber.

Everything below is env-gated / manual (needs a real domain + AWS + LE), exactly like the
single-node DNS-01 live run. The code is complete and green; this is just the wire test.

---

## 0. Prerequisites (once)

- A real domain in Route 53 whose delegation matches its hosted zone (see the single-node runbook
  in `project_dns01_plan`: `dig +short NS <domain> @1.1.1.1` must equal
  `aws route53 get-hosted-zone --query DelegationSet.NameServers`).
- An IAM key with **`route53:ChangeResourceRecordSets`** on that hosted zone.
- Docker (for Redis), `openssl`, and optionally `redis-cli` (the verify script cross-checks Redis).
- Build the enterprise binary once: `cargo build -p waf-enterprise`.

## 1. Shared Redis (the coordination point)

```sh
docker run -d --name waf-redis -p 6379:6379 redis:7
```

## 2. Environment (identical on BOTH nodes)

```sh
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
# The cert-store secret MUST be identical on every node — it decrypts the shared private key.
# Generate once and reuse everywhere:
export WAF_CERT_STORE_KEY="$(openssl rand -hex 32)"
```

> If `WAF_CERT_STORE_KEY` differs between nodes, the follower cannot decrypt the shared key and
> logs `key decryption failed (wrong WAF_CERT_STORE_KEY?)` — it will never converge. Same secret
> everywhere is the rule.

## 3. Configs — node A and node B

Edit `enterprise/acme-dns01-cluster.toml`: set `[tls.acme.dns].zone_id` to your `Z...` hosted-zone
id (and the `domains`/`email` if not `lightwaf.org`). That file **is node A**.

Generate node B by copying it and changing only the two listen ports and the local cache dir:

```sh
sed -e 's/0.0.0.0:8443/0.0.0.0:8444/' \
    -e 's/127.0.0.1:9090/127.0.0.1:9091/' \
    -e 's/acme-cache-a/acme-cache-b/' \
    acme-dns01-cluster.toml > node-b.toml
```

(The metrics ports MUST differ, or the second process fails to bind — `AddrInUse`. The cache dirs
are per-node local warm caches; the shared source of truth is Redis.)

## 4. Run the two nodes

Two terminals (same host), both with the env from step 2:

```sh
# terminal A
WAF_CONFIG=acme-dns01-cluster.toml cargo run -p waf-enterprise
# terminal B
WAF_CONFIG=node-b.toml            cargo run -p waf-enterprise
```

### What you should see (the seam working)

- On **one** node (the leader): `acquired issuance lock (leader)` → the usual DNS-01 flow
  (`TXT visible on authoritative NS` → `certificate issued and installed`) →
  `published issued cert to shared store`.
- On the **other** node (the follower): `issuance in progress elsewhere; waiting to converge`,
  then `converged on shared certificate`. It never runs its own DNS-01 order.
- Which node wins the lock is a race — either is fine.

## 5. Verify convergence

```sh
./scripts/cluster-tls/verify_shared_cert.sh
```

Expected: **both nodes serve the SAME SHA-256 fingerprint** → `[OK] … cluster cert-sharing works`,
and Redis shows `cert blobs=1`, `live issuance locks=0` (when idle).

### Control (see the seam actually do something)

Re-run with cluster OFF and watch the fingerprints DIFFER:

```sh
sed 's/cluster   = true/cluster   = false/' acme-dns01-cluster.toml > node-a-solo.toml
sed 's/cluster   = true/cluster   = false/' node-b.toml            > node-b-solo.toml
# (also give them distinct domains or expect Route53 TXT contention — this is the very problem
#  cluster mode fixes) then run both and verify:
PORT_A=8443 PORT_B=8444 ./scripts/cluster-tls/verify_shared_cert.sh   # → [FAIL] different certs (expected here)
```

## 6. Bonus checks

- **Failover (R5):** kill the leader mid-life after it has published, `docker restart waf-redis` is
  NOT needed; just stop the leader process. The follower keeps serving the cached cert and, when the
  renewal window opens, acquires the lock and renews. To see the *lock* failover specifically, kill
  the leader while it holds the lock (during issuance) — after `lock_ttl` (~60s) the other node
  takes over (this is exactly what the `dead_leader_lock_expires_*` tests assert).
- **Warm restart:** stop and restart a node — it serves its local `acme-cache-*` cert immediately
  and converges on Redis without re-issuing.

## 7. Cleanup

```sh
docker rm -f waf-redis
rm -f node-b.toml node-a-solo.toml node-b-solo.toml
rm -rf acme-cache-a acme-cache-b
# optional: delete any leftover _acme-challenge TXT in Route 53 (the driver cleans up on all paths,
# but check once): dig +short TXT _acme-challenge.<domain> @1.1.1.1   # expect empty
```

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Follower logs `key decryption failed` | `WAF_CERT_STORE_KEY` differs between nodes — make it identical. |
| `[tls.acme].cluster = true but no redis_url … refusing to start` | Set `[enterprise].redis_url` (or `WAF_REDIS_URL`). |
| `requires the WAF_CERT_STORE_KEY environment variable` | Export the secret before starting. |
| Both nodes issue (two orders) | Not in cluster mode — check `cluster = true` AND `strategy = "dns-01"` AND `[tls].enabled = true` (a warn is logged if cluster is ignored). |
| `TXT not visible … within 180s` | DNS delegation/propagation, not a cluster issue — see the single-node DNS-01 runbook. |
| Second node `AddrInUse` | The two nodes share a `[metrics].listen` (or proxy listen) port — they must differ. |
