// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Managed TLS for [Light WAF](https://github.com/0x00spor3/Light-WAF): an implementation of the
//! core's `waf_proxy::tls::TlsCertSource` trait, injected with `Proxy::builder(&cfg).cert_source(..)`
//! without forking the core (which itself only ships a static certificate from disk).
//!
//! - **ACME, hitless** (`resolver()`): server certificates via TLS-ALPN-01 ([`acme`]) or DNS-01 with
//!   Cloudflare/Route53 ([`acme_dns01`], [`dns`]), with background renewal that rotates the live
//!   certificate without rebuilding the acceptor. In cluster mode one node issues and renews and every
//!   node serves the same certificate from a shared store (`waf-state-redis`).
//! - **mTLS** (`client_verifier()`): require and verify client certificates against a configured CA
//!   bundle ([`mtls`]).
//!
//! A source may carry either, both, or neither (with a file fallback for the server certificate when
//! ACME is off but mTLS is on).

pub mod acme;
pub mod acme_dns01;
pub mod dns;
pub mod mtls;

use std::path::Path;
use std::sync::Arc;

use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::server::ResolvesServerCert;
use waf_proxy::tls::{FileCertSource, TlsCertSource, TlsError, TlsMaterial};

pub use acme::{AcmeError, AcmeParams, ChallengeStrategy};
pub use mtls::{verifier_from_ca_file, MtlsError};

/// A `TlsCertSource` that provides managed server certs (ACME resolver) and/or mTLS client
/// verification, composed from the pieces in [`acme`]/[`mtls`]. Build it with
/// [`ManagedTlsCertSource::builder`].
pub struct ManagedTlsCertSource {
    resolver: Option<Arc<dyn ResolvesServerCert>>,
    verifier: Option<Arc<dyn ClientCertVerifier>>,
    /// Server-cert fallback for the mTLS-only case (ACME off): the core's resolver-less
    /// path still calls `load()`, so we serve the configured file cert there.
    file_fallback: Option<FileCertSource>,
}

impl ManagedTlsCertSource {
    pub fn builder() -> ManagedTlsBuilder {
        ManagedTlsBuilder::default()
    }
}

impl TlsCertSource for ManagedTlsCertSource {
    fn load(&self) -> Result<TlsMaterial, TlsError> {
        // With a resolver set the core never calls this (it uses `resolver()`); it is only
        // reached in the mTLS-only case, where we serve the configured file cert.
        match &self.file_fallback {
            Some(fs) => fs.load(),
            None => Err(TlsError::NoCertificates(Path::new(
                "<managed TLS: a server cert requires either ACME ([tls.acme]) or a file cert>",
            )
            .to_path_buf())),
        }
    }

    fn resolver(&self) -> Option<Arc<dyn ResolvesServerCert>> {
        self.resolver.clone()
    }

    fn client_verifier(&self) -> Option<Arc<dyn ClientCertVerifier>> {
        self.verifier.clone()
    }
}

/// Builder for [`ManagedTlsCertSource`].
#[derive(Default)]
pub struct ManagedTlsBuilder {
    resolver: Option<Arc<dyn ResolvesServerCert>>,
    verifier: Option<Arc<dyn ClientCertVerifier>>,
    file_fallback: Option<FileCertSource>,
}

impl ManagedTlsBuilder {
    /// ACME server-cert resolver (hitless rotation). See [`acme::start_resolver`].
    pub fn resolver(mut self, resolver: Arc<dyn ResolvesServerCert>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// mTLS client-cert verifier. See [`mtls::verifier_from_ca_file`].
    pub fn client_verifier(mut self, verifier: Arc<dyn ClientCertVerifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Server-cert file fallback, used by `load()` when no ACME resolver is set (mTLS-only).
    pub fn file_fallback(mut self, source: FileCertSource) -> Self {
        self.file_fallback = Some(source);
        self
    }

    pub fn build(self) -> ManagedTlsCertSource {
        ManagedTlsCertSource {
            resolver: self.resolver,
            verifier: self.verifier,
            file_fallback: self.file_fallback,
        }
    }
}
