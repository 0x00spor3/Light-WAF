# waf-tls-managed

Managed TLS for Light WAF — the **enterprise** implementation of the core's
`waf_proxy::tls::TlsCertSource` seam (BOUNDARY §3.2/§4). Injected via
`Proxy::builder(&cfg).cert_source(..)` **without forking the core**.

Two capabilities, both plugged into the SAME trait via the additive seams added in **core
0.2** (`TlsCertSource::resolver` / `client_verifier` — defaulted methods, so the OPEN
`FileCertSource` path is unchanged):

| Capability | Seam | What it does |
|---|---|---|
| **ACME, hitless** | `resolver()` | Server-cert provisioning + background renewal that rotates the live cert **without restarting the acceptor**. **TLS-ALPN-01** (single-port, via `rustls-acme`) or **DNS-01** (wildcards / no inbound `:443` needed, via `instant-acme` + a DNS provider). |
| **mTLS / managed PKI** | `client_verifier()` | Requires + verifies client certs against a configured CA bundle. Via rustls `WebPkiClientVerifier`. |

## Config (`[tls.acme]` / `[tls.mtls]`, in the same file)

The OPEN `waf_core::Config` ignores these tables; `waf-enterprise` re-parses the file to
read them. `[tls].enabled` (OPEN) must be on for any TLS at all.

```toml
[tls]
enabled = true                      # OPEN: turn on TLS termination

[tls.acme]
enabled    = true
domains    = ["example.com"]
email      = "ops@example.com"
strategy   = "tls-alpn-01"          # "tls-alpn-01" (default, single-port) | "dns-01"
cache_dir  = "/var/lib/waf/acme"    # caches the ACME account + issued cert (warm restarts)
staging    = true                   # staging CA (default) — flip to false for production
# directory_url = "https://localhost:14000/dir"   # override CA (e.g. a Pebble test server)
# provider   = "cloudflare"         # DNS-01 only: "cloudflare" | "route53"

# DNS-01 only. Wildcards (`*.example.com`) and works behind NAT (the CA never connects to you).
[tls.acme.dns]
zone_id                  = "Z123…"  # Cloudflare zone id, or Route 53 hosted-zone id
propagation_timeout_secs = 120      # max wait for the TXT on the AUTHORITATIVE nameservers
poll_interval_secs       = 5
grace_secs               = 10       # courtesy delay after first sighting (multi-vantage CAs)
renewal_days             = 60

[tls.mtls]
enabled = true
ca_path = "/etc/waf/clients-ca.pem" # PEM bundle of trusted client CAs
```

- **ACME off, mTLS on**: the server cert still comes from the OPEN `[tls].cert_path`/
  `key_path` (a file fallback); mTLS only adds client verification.
- **ACME on**: the resolver owns the server cert (the file pair is not needed) and the core
  advertises `acme-tls/1` so the TLS-ALPN-01 challenge negotiates on the same `:443`.
- **`fail-closed at boot`**: a missing CA file or an ACME start error refuses to start —
  never a silent downgrade.

## DNS-01 providers

With `strategy = "dns-01"`, pick the DNS provider with `[tls.acme].provider`. The provider
publishes the `_acme-challenge.<domain>` TXT, the driver waits for it to appear on the zone's
**authoritative nameservers** (not the system resolver — avoids a stale-cache false "ready")
plus a grace delay, then asks the CA to validate. **Secrets come from the environment, never
the config file.**

| `provider` | Record model | Secrets (env) | Notes |
|---|---|---|---|
| `cloudflare` | per-record (create/delete by record id) | `CF_API_TOKEN` | `zone_id` = Cloudflare zone id. Token scope `Zone:DNS:Edit`. |
| `route53` | rrset (read-modify-write the value set) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` (+ optional `AWS_SESSION_TOKEN`, `AWS_REGION`) | `zone_id` = the hosted-zone id. Official `aws-sdk-route53` (SigV4). |

Both keep **apex + wildcard** values that share one `_acme-challenge.<base>` name coexisting:
Cloudflare adds/removes each value as its own record; Route 53 UPSERTs the full value set.

## Posture notes

- **Rotation**: the hitless path is the SERVER cert (ACME resolver — both TLS-ALPN-01 and
  DNS-01). The mTLS client-CA roots are loaded once at boot (rotation = restart), like the
  acceptor.
- **DNS-01 cache**: `cache_dir` persists the ACME account (so a restart reuses it instead of
  re-registering) and the issued cert/key (served immediately on restart while renewal runs).
- **Strategy is global** to `[tls.acme]`: a domain can't run under both TLS-ALPN-01 and DNS-01
  at once.

## Verifying ACME end-to-end (manual / CI, against Pebble)

The mTLS handshake and the resolver/ALPN wiring are covered by `cargo test`. The live ACME
issuance needs a test CA and inbound reachability, so it is a manual/CI step:

```sh
# Pebble = Let's Encrypt's test ACME server
docker run -d --name pebble -p 14000:14000 -p 15000:15000 letsencrypt/pebble
# point a config at it: [tls.acme].directory_url = https://localhost:14000/dir, staging=true,
# a domain that resolves to this host, and [tls].enabled = true. Pebble must be able to
# reach the WAF's TLS port for the TLS-ALPN-01 challenge.
WAF_CONFIG=acme.toml cargo run -p waf-enterprise
# then: curl --cacert <pebble-root> https://<domain>/   → handshake uses the ACME cert
```

**DNS-01** needs no inbound reachability, so it tests well against a real zone:

```sh
# config: strategy="dns-01", provider="route53" (or "cloudflare"), staging=true,
#         domains=["*.example.com"], [tls.acme.dns].zone_id=<hosted-zone>
export AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…        # or CF_API_TOKEN=… for cloudflare
WAF_CONFIG=acme-dns01.toml cargo run -p waf-enterprise
# the driver UPSERTs the _acme-challenge TXT, waits for authoritative propagation, then issues.
```

A fully local DNS-01 run uses Pebble + `pebble-challtestsrv` (the mock-DNS provider sets the
TXT); see the env-gated `tests/dns01_pebble.rs` probe for the exact container setup.
