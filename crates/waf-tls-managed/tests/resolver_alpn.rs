// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! L1 seam integration (no network): when a `ManagedTlsCertSource` exposes an ACME
//! `resolver()`, the core's `build_server_config` must (a) use the resolver and NOT call
//! `load()` (so no server-cert file is needed), and (b) advertise the `acme-tls/1` ALPN so
//! a TLS-ALPN-01 challenge can negotiate on the same listener.
//!
//! The live CA issuance (rustls-acme TLS-ALPN-01 against Pebble) is an env-gated / CI
//! concern; this test pins the wiring between the enterprise resolver and the core.

use std::sync::Arc;

use tokio_rustls::rustls::server::{ClientHello, ResolvesServerCert};
use tokio_rustls::rustls::sign::CertifiedKey;
use waf_proxy::tls::build_server_config;
use waf_tls_managed::ManagedTlsCertSource;

/// A resolver that never actually has a cert — enough to exercise the core's resolver
/// branch (we are testing the wiring, not certificate issuance).
#[derive(Debug)]
struct DummyResolver;

impl ResolvesServerCert for DummyResolver {
    fn resolve(&self, _client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        None
    }
}

#[test]
fn resolver_path_advertises_acme_tls_alpn_and_needs_no_cert_file() {
    // No file fallback set: if the core tried to call load() this would fail. It must not,
    // because the resolver takes over the server-cert path.
    let managed = ManagedTlsCertSource::builder().resolver(Arc::new(DummyResolver)).build();

    let cfg = build_server_config(&managed, &["h2".to_string(), "http/1.1".to_string()])
        .expect("resolver path builds a ServerConfig without any cert file");

    // The configured ALPN is preserved…
    assert!(cfg.alpn_protocols.iter().any(|p| p == b"h2"));
    assert!(cfg.alpn_protocols.iter().any(|p| p == b"http/1.1"));
    // …and `acme-tls/1` is appended so TLS-ALPN-01 can negotiate on this same listener.
    assert!(
        cfg.alpn_protocols.iter().any(|p| p == b"acme-tls/1"),
        "resolver path must advertise acme-tls/1 for TLS-ALPN-01"
    );
    // (The negative — FileCertSource path adds no extra ALPN — is pinned by the core's
    // matrix test `server_config_sets_alpn_from_config` in waf-proxy/tests/tls.rs.)
}
