<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: BUSL-1.1 -->

# 3. WAF configuration

The proxy reads one TOML file (`--config`). This chapter is a reference to that file, grouped by task.
The OPEN sections (`[proxy]`, `[tls]`, `[waf]`, `[rate_limit]`, `[network]`, `[limits]`, `[modules.*]`)
are read by the core; the `[enterprise.*]` sections are read by the enterprise binary. They live in the
same file — the core simply ignores tables it doesn't know.

> Every enterprise section is **default-off**. A file with no `[enterprise.*]` tables (or all disabled)
> behaves exactly like the OPEN core.

- [Proxy & backend](#proxy--backend)
- [TLS](#tls)
- [Detection & the block threshold](#detection--the-block-threshold)
- [Rate limiting](#rate-limiting)
- [Client-IP resolution](#client-ip-resolution)
- [Request limits](#request-limits)
- [Detection modules](#detection-modules)
- [Managed rules (CRS)](#managed-rules-crs)
- [Resilience](#resilience)
- [Enterprise modules](#enterprise-modules)

## Proxy & backend

```toml
[proxy]
listen  = "0.0.0.0:8080"          # where the WAF accepts client traffic
backend = "http://127.0.0.1:8000" # your origin; the WAF forwards allowed requests here
```

## TLS

TLS termination is **off by default** — the listener serves cleartext (HTTP/1.1 + h2c). When you turn
it on, the listener serves **only** TLS on that port (no cleartext fallback), and an unreadable
certificate at boot is **fatal** (fail-closed, never a silent downgrade).

### Certificate from a file (OPEN)

```toml
[tls]
enabled   = true
cert_path = "/etc/waf/tls/cert.pem"   # PEM chain, leaf first
key_path  = "/etc/waf/tls/key.pem"    # PKCS#8 / PKCS#1 / SEC1
alpn      = ["h2", "http/1.1"]
```

### Managed ACME certificates (enterprise)

`waf-tls-managed` obtains and rotates certificates automatically — **hitless** (no acceptor rebuild on
renewal). When enabled, `cert_path`/`key_path` are ignored; `[tls].enabled` still governs on/off.

```toml
[tls.acme]
enabled   = true
domains   = ["waf.example.com"]      # SANs; dns-01 supports wildcards "*.example.com"
email     = "ops@example.com"
strategy  = "tls-alpn-01"            # "tls-alpn-01" (default) | "dns-01"
cache_dir = "acme-cache"             # persists the account + cert across restarts
staging   = true                     # true = CA staging (avoid Let's Encrypt prod rate limits)
```

- **`tls-alpn-01`** proves control on the same port via the `acme-tls/1` ALPN. Needs a reachable
  public IP on that port.
- **`dns-01`** proves control by publishing a TXT record — works behind NAT and for **wildcards**. It
  needs a provider block and credentials in the environment (never in the file):

  ```toml
  [tls.acme]
  strategy = "dns-01"
  provider = "cloudflare"              # "cloudflare" | "route53"

  [tls.acme.dns]
  zone_id                  = "<zone or hosted-zone id>"
  propagation_timeout_secs = 120       # wait for the TXT to appear on the authoritative NS
  renewal_days             = 60        # renew ahead of the ~90-day LE lifetime
  ```

  | Provider | Environment variables |
  |---|---|
  | `cloudflare` | `CF_API_TOKEN` |
  | `route53` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`, `AWS_REGION`) |

  **Clustered DNS-01** (`cluster = true`) coordinates multiple nodes through Redis so exactly one node
  issues for the whole cluster and the others converge. It requires `[enterprise].redis_url` and
  `WAF_CERT_STORE_KEY` (encrypts the private key at rest).

### Mutual TLS (client certificates)

```toml
[tls.mtls]
enabled = true
ca_path = "/etc/waf/clients-ca.pem"   # PEM bundle of trusted client CAs
```

With `enabled = false` there is no client authentication — exactly the OPEN behavior.

## Detection & the block threshold

```toml
[waf]
mode            = "blocking"   # "blocking" (enforce) | "detection" (observe only)
block_threshold = 5            # deny when the anomaly score reaches this
paranoia_level  = 1            # 1..=4 — higher activates more (and noisier) rules
```

### Severity scores

This table maps each rule's severity to the points it adds to the score. **This, together with
`block_threshold`, is your main tuning surface** (see [Concepts](01-concepts.md#points-come-from-severity)).

```toml
[waf.severity_scores]
critical = 6   # a single critical (6) blocks on its own at threshold 5
error    = 4
warning  = 3   # two warnings (3+3) also block
notice   = 2   # a lone notice never blocks
```

To make the WAF stricter, lower `block_threshold` or raise severities. To reduce false positives on a
noisy rule class, lower that severity so it only contributes in combination.

## Rate limiting

An L7 token bucket applied at connection time, keyed per client.

```toml
[rate_limit]
enabled        = true
key            = "client_ip"
requests       = 100        # tokens per window
window_seconds = 60
burst          = 100        # bucket capacity (default = requests)
action         = "block"    # "block" → 429 | "score" → add `score` points instead
score          = 5          # points when action = "score"
max_tracked_keys = 100000   # memory cap; idle buckets are swept
```

`[rate_limit]` sets the **policy** (capacity/refill). *Where* the bucket state lives — single-node
memory vs cluster-wide Redis — is decided by [`[enterprise].redis_url`](#cluster-wide-rate-limiting).

## Client-IP resolution

The client IP is derived **once** and reused by rate limiting, logging, and reputation. It is
fail-safe: with `trusted_proxies` empty, the `X-Forwarded-For` header is **always ignored** and the
peer socket address is used — an unconfigured deploy cannot be spoofed.

```toml
[network]
trusted_proxies  = ["10.0.0.0/8", "::1"]   # CIDRs of YOUR proxies/LBs/CDNs
client_ip_header = "X-Forwarded-For"
trusted_hops     = 1                        # hops to trust counting from the RIGHT (never the first IP)
```

> If your WAF sits behind a load balancer or CDN and you do **not** set `trusted_proxies`, every
> request appears to come from the LB's IP — and per-IP rate limiting throttles everyone together. Set
> `trusted_proxies` to your infrastructure's ranges.

## Request limits

Structural caps that reject malformed or oversized requests before content inspection (a `rejected`
verdict).

```toml
[limits]
max_body_size   = 1048576   # 1 MiB
max_header_size = 8192      # per header
max_headers     = 100
max_params      = 100
max_cookies     = 50
max_json_depth  = 20
```

## Detection modules

Native rule modules, each toggled on/off. All are on by default in the sample config. They contribute
to the anomaly score by severity — none blocks unilaterally.

```toml
[modules.sqli]            { enabled = true }   # SQL injection
[modules.xss]             { enabled = true }   # cross-site scripting
[modules.path_traversal]  { enabled = true }
[modules.rce]             { enabled = true }   # remote command execution
[modules.lfi_rfi]         { enabled = true }   # local/remote file inclusion
[modules.ssrf]            { enabled = true }   # server-side request forgery
[modules.ldap]            { enabled = true }   # LDAP injection
[modules.nosql]           { enabled = true }   # NoSQL injection
[modules.mail]            { enabled = true }   # mail-header injection
[modules.ssti]            { enabled = true }   # server-side template injection
[modules.scanner]         { enabled = true }   # scanner/tool fingerprint on User-Agent
[modules.ssi]             { enabled = true }   # server-side includes
[modules.xxe]             { enabled = true }   # XML external entity
[modules.header_injection]{ enabled = true }
[modules.request_smuggling]{ enabled = true }  # HTTP framing validation (structural)
```

(TOML requires each module on its own `[modules.name]` line with `enabled = true`; the compact form
above is just for the overview.)

### Structural protocol protections (opt-in)

GraphQL and gRPC caps guard the **shape** of an operation (depth/aliases/fields/batch), not its
content — like `request_smuggling`. They are endpoint-specific, so they default off and need tuning.

```toml
[modules.graphql]
enabled             = false
paths               = ["/graphql"]
max_depth           = 15
max_aliases         = 30
max_fields          = 1000
max_directives      = 50
max_batch           = 10
block_introspection = false        # true → __schema/__type return 403

[modules.grpc]
enabled           = false
max_message_bytes = 4194304        # 4 MiB
max_fields        = 4096
max_depth         = 16
on_compressed     = "reject"       # opaque compressed payload: "reject" | "passthrough"
```

## Managed rules (CRS)

The CRS engine loads SecRule `.conf` files. This is also the file the [node agent](05-rule-management.md)
manages when you use governed rule management.

```toml
[modules.crs]
enabled = true
files   = ["/etc/waf/managed.conf"]   # one or more SecRule .conf files
```

## Resilience

Explicit posture for when the **WAF itself** is in trouble — see also
[Operations](08-operations.md#resilience-posture).

```toml
[resilience]
on_upstream_error   = "fail_closed"   # origin down/timeout → 502 (closed) | 503 (open, retryable)
on_internal_error   = "fail_open"     # a module panic must not take down the site
on_config_error     = "fail_open"     # a bad reload → keep last-good config
on_parser_limit     = "fail_closed"   # normalization failed → 400 (closed) | forward un-inspected (open)
upstream_timeout_ms = 30000
```

## Enterprise modules

All default-off, all opt-in, all additive to the same anomaly score.

### Cluster-wide rate limiting

Share one rate-limit budget across all WAF nodes via Redis (atomic server-side `try_acquire`). Sets
only *where* the bucket state lives; the policy stays in [`[rate_limit]`](#rate-limiting).

```toml
[enterprise]
redis_url = "redis://10.0.0.5:6379"   # absent ⇒ in-memory single-node store
pool_size = 32
fail_open = true                       # Redis error at RUNTIME: true = allow | false = deny.
                                       # An unreachable Redis at BOOT is always fatal.
```

`WAF_REDIS_URL` overrides `redis_url` for ops/CI. See the [enterprise README](../README.md) for the
atomicity and fail-open rationale.

### IP reputation + threat-intel feed

A `Phase::Connection` module reads the client IP's reputation from the same Redis (keyspace
`rep:<ip>`) and contributes to the score. A background **feed** populates that keyspace from IP lists.
Both require `redis_url`.

```toml
[enterprise.reputation]
enabled             = true
malicious_severity  = "critical"   # a malicious IP alone can cross the threshold
suspicious_severity = "warning"

[enterprise.reputation.feed]
enabled               = true
refresh_interval_secs = 300         # single-writer: one node per cycle fetches (distributed lock)
lock_ttl_secs         = 90

[[enterprise.reputation.feed.sources]]
kind     = "http"                   # "file" (local path) | "http" (HTTPS URL)
location = "https://example.com/blocklist.txt"
verdict  = "malicious"              # malicious | suspicious
```

Entries expire (TTL) so a de-listed IP ages out and a dead feed degrades to *Unknown* (fail-safe).
v1 handles exact IPs only (CIDRs are skipped with a warning).

### Curated premium CRS content

Loads curated premium rule content (CVE/app/evasion signatures: Log4Shell, Spring4Shell, cloud-metadata
SSRF, webshells, `.git`/`.env` exposure, …) through the OPEN CRS engine. Additive to the same score.

```toml
[enterprise.crs_curated]
enabled = true
```

### GraphQL / gRPC schema enforcement

Validate every operation against your app's **real schema**. A field/type/method the real client never
sends is a probing signal → adds to the score (schema *governance*, not baseline detection). The schema
file is mandatory when enabled, and validated at boot (fatal if missing/invalid).

```toml
[enterprise.schema_enforcement]
enabled                = true
schema_path            = "/etc/waf/app.graphql"   # SDL; boot-fatal if missing/invalid
paths                  = ["/graphql"]
parse_error_severity   = "warning"
unknown_field_severity = "critical"

[enterprise.grpc_schema_enforcement]
enabled                 = true
descriptor_path         = "/etc/waf/app.bin"      # FileDescriptorSet from protoc/buf
unknown_method_severity = "critical"
decode_error_severity   = "warning"
flag_unknown_fields     = false                    # opt-in (protobuf tolerates unknown fields by design)
```

### Bot / client-integrity detection

Native cross-header heuristics. v1 flags **browser impersonation**: a User-Agent that claims a modern
browser but sends no `Sec-Fetch-*` headers is a client pretending to be a browser (a curl/requests bot
doesn't send Fetch-Metadata). Additive (never a hard reject).

```toml
[enterprise.bot_detection]
enabled                        = true
browser_impersonation_severity = "critical"
```

### Signed WASM plugins

The OPEN `[modules.wasm]` runtime loads unsigned `.wasm` best-effort. This adds a **trust gate**:
verify a detached minisign (ed25519) signature against `trusted_keys` before loading. A signed plugin
that fails verification is **boot-fatal** (fail-closed).

```toml
[enterprise.wasm]
enabled      = true
exclusive    = true                         # reject any populated OPEN [modules.wasm] (lockdown)
trusted_keys = ["RWQ...base64-minisign-pubkey..."]

[[enterprise.wasm.plugins]]
wasm_path = "/etc/waf/denylist.wasm"
sig_path  = "/etc/waf/denylist.wasm.minisig"
config    = "block=/admin"
```

Sign with `minisign -Sm plugin.wasm` (→ `plugin.wasm.minisig`); the `trusted_keys` entry is the base64
line from the `.pub`.

### Request capture

Capture the **full denied request** (method/path/query, headers, cookies, body) so the control-plane
event drill-down can show exactly what was blocked — not just the metadata the decision-log carries.
Optional, **off by default**, and it does **not** touch the data path: a pure observer buffers each
request in a bounded ring off-path, and a background shipper posts the captured denied requests to the
control plane on a **dedicated side-channel** (never the decision-log/Vector — the body never travels
in logs). Overflow is dropped, never back-pressured onto the proxy.

It is **raw by default**, so treat it like a secret store: redact sensitive names here, keep the
control-plane retention short (see [§4](04-control-plane.md)), and know that viewing a capture is
RBAC-gated (`ViewCaptures`, operator+) and written to the signed audit log.

```toml
[enterprise.capture]
enabled          = true
controlplane_url = "http://waf-controlplane:9600"  # the shipper appends /ingest/captures
token_env        = "WAF_CAPTURE_TOKEN"             # env holding the ingest bearer — never the token here
max_body_bytes   = 65536                            # bodies over this are truncated + flagged
ring_capacity    = 1024                             # ring bounds: entries …
ring_bytes       = 33554432                         #   … total bytes (32 MiB) …
ring_ttl_ms      = 5000                             #   … and TTL before an unshipped capture is evicted
queue_capacity   = 256                              # shipper backlog; full ⇒ drop (never block the proxy)

# Names replaced with ***REDACTED*** node-side (case-insensitive). Empty = raw. The redacted VALUE
# never leaves the node — only the redacted names are reported, to drive the UI banner.
[enterprise.capture.redaction]
headers     = ["cookie", "authorization", "set-cookie"]
body_fields = ["password", "token", "secret", "card"]
```

The ingest bearer comes from the environment (`WAF_CAPTURE_TOKEN`), matching the control plane's
`WAF_CP_API_TOKEN` (ingest is bearer-gated). Enabling capture without a `controlplane_url` is
boot-fatal (a capture that can never ship is a silent misconfiguration).

**Scope:** connection-phase rejects (rate limit) and parser-limit `400`s happen *before* inspection, so
those events keep metadata only — there is no captured body for them.

Next: [Control plane & dashboard](04-control-plane.md).
