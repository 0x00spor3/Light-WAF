# waf-tls-managed

Managed TLS for Light WAF — the **enterprise** implementation of the core's
`waf_proxy::tls::TlsCertSource` seam (BOUNDARY §3.2/§4). Injected via
`Proxy::builder(&cfg).cert_source(..)` **without forking the core**.

Two capabilities, both plugged into the SAME trait via the additive seams added in **core
0.2** (`TlsCertSource::resolver` / `client_verifier` — defaulted methods, so the OPEN
`FileCertSource` path is unchanged):

| Capability | Seam | What it does |
|---|---|---|
| **ACME, hitless** | `resolver()` | TLS-ALPN-01 server-cert provisioning + background renewal that rotates the live cert **without restarting the acceptor**. Via `rustls-acme`. |
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
strategy   = "tls-alpn-01"          # default; single-port, hitless. "dns-01" = follow-on
cache_dir  = "/var/lib/waf/acme"
staging    = true                   # staging CA (default) — flip to false for production
# directory_url = "https://localhost:14000/dir"   # override CA (e.g. a Pebble test server)

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

## Posture notes

- **DNS-01** is recognised (`strategy = "dns-01"`, for wildcards / when the CA can't reach
  `:443`) but its provider integration is a **follow-on**; selecting it today errors clearly
  rather than silently doing nothing.
- **Rotation**: the hitless path is the SERVER cert (ACME resolver). The mTLS client-CA roots
  are loaded once at boot (rotation = restart), like the acceptor.

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
