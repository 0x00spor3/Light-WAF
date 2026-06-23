# Example configurations

Ready-to-adapt `config.toml` profiles, from "observe only" to "high security",
plus two deployment-shaped variants. Every file is a complete, valid config — copy
one, edit `[proxy]` `listen`/`backend`, and point the proxy at it:

```sh
cargo run -p waf-proxy -- --config examples/balanced.toml
# or:  WAF_CONFIG=examples/balanced.toml cargo run -p waf-proxy
```

## Aggressiveness ladder

| File | Mode | Paranoia | Threshold | When to use |
|---|---|---|---|---|
| [`detection-only.toml`](detection-only.toml) | detection-only | PL1 | 5 (logged) | **Start here.** Shadow mode: logs every decision, blocks nothing. Run for a few days, confirm zero false positives on your traffic, then graduate. |
| [`balanced.toml`](balanced.toml) | blocking | PL2 | 5 | **Recommended baseline.** A single high-confidence (Critical) rule blocks; weak signals only accumulate. Sane default for a normal app. |
| [`strict.toml`](strict.toml) | blocking | PL4 | 3 | **High-value targets** (admin panels, finance/health). Activates every rule and blocks on accumulated weak signals. ⚠️ Higher false-positive risk — validate first. |

## Deployment variants

| File | Use case |
|---|---|
| [`behind-cdn.toml`](behind-cdn.toml) | The WAF sits **behind a CDN / LB / reverse proxy** (Cloudflare, ALB, nginx). Enables safe client-IP resolution from `X-Forwarded-For` (fail-safe: trusted only when the peer is in `trusted_proxies`). Replace the placeholder CIDRs with your proxy's real ranges. |
| [`api-json.toml`](api-json.toml) | A **JSON / REST API backend**. Tunes the defensive limits for API-shaped traffic (bigger bodies, deeper nesting, more fields). A JSON-transport GraphQL query is inspected the same way. HTTP/2 is served (Phase 12); gRPC *content* inspection (protobuf de-framing) is a later phase. |

## TLS termination (`[tls]`)

Off by default — terminate TLS upstream (CDN/LB) and run cleartext, or terminate at the WAF:

```toml
[tls]
enabled   = true
cert_path = "/etc/waf/tls/cert.pem"   # PEM chain, leaf first
key_path  = "/etc/waf/tls/key.pem"    # PEM key (PKCS#8 / PKCS#1 / SEC1)
alpn      = ["h2", "http/1.1"]         # one port serves HTTP/2 and HTTP/1.1 by ALPN
```

When enabled the listener serves **only** TLS — there is no cleartext fallback, and an
unreadable cert is a fatal boot error (fail-closed). Cert management at scale (ACME, rotation,
mTLS) is an enterprise concern; the OPEN core reads a cert from file.

## How the knobs map to aggressiveness

- **`mode`** — `detection-only` logs but never blocks; `blocking` enforces (403/429).
- **`paranoia_level` (1–4)** — higher activates *more* (and noisier) rules. PL1 = only
  high-confidence; PL4 = everything.
- **`block_threshold`** — the cumulative anomaly score that triggers a block. With the C2
  weights (`critical=6, error=4, warning=3, notice=2`), threshold `5` means one Critical
  blocks alone while two Warnings (3+3) accumulate; lowering it makes weaker/accumulated
  signals block (more coverage, more false positives).
- **`[rate_limit]`** — `block` returns 429; `score` feeds the anomaly score instead.
- **`[resilience]`** — per-scenario `fail_open` (stay available) vs `fail_closed` (deny on
  trouble). `strict.toml` leans closed; the others keep `on_internal_error = fail_open` so a
  WAF bug can't take the site down.
- **`[limits]`** — defensive parser caps; tighter = rejects oversized/over-nested input
  earlier (anti-DoS), looser = accommodates large API payloads.

> Full schema and field-by-field defaults: `ARCHITECTURE.md` §9. The self-documented
> reference lives in the repo-root `config.toml`.

## Recommended rollout

1. **`detection-only.toml`** for a few days → read the JSON logs (and
   `cargo run -p waf-corpus --example report`) to spot any false positives on *your* traffic.
2. Move to **`balanced.toml`** (add `behind-cdn.toml`'s `[network]` block if you're behind a
   proxy).
3. Only escalate to **`strict.toml`** for sensitive surfaces, after allow-listing the
   legitimate patterns detection-only revealed.
