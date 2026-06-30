// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Managed TLS for Light WAF — the ENTERPRISE implementation of the core's
//! `waf_proxy::tls::TlsCertSource` seam (BOUNDARY.md §3.2/§4).
//!
//! The OPEN core ships `FileCertSource` (a static cert from disk). This crate plugs two
//! at-scale capabilities into the SAME trait, via the additive seams added in core 0.2,
//! injected with `Proxy::builder(&cfg).cert_source(..)` WITHOUT forking the core:
//!
//! - **ACME, hitless** (`resolver()`): TLS-ALPN-01 server-cert provisioning + background
//!   renewal that rotates the live cert without rebuilding the acceptor. See [`acme`].
//! - **mTLS / managed PKI** (`client_verifier()`): require + verify client certs against a
//!   configured CA bundle. See [`mtls`].
//!
//! A source may carry either, both, or neither (with a file fallback for the server cert
//! when ACME is off but mTLS is on).

pub mod acme;
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
