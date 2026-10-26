// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! mTLS / managed-PKI client-certificate verification — the L2 enterprise seam
//! (`TlsCertSource::client_verifier`). Builds a rustls `WebPkiClientVerifier` from a
//! configured CA bundle so the listener requires and verifies client certificates.
//!
//! v1: roots come from a PEM file (rotation = restart, like the acceptor — the hitless
//! path is the SERVER cert via the ACME resolver, not the client roots).

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::RootCertStore;

/// Why building the client-cert verifier failed (all fatal at boot — a required mTLS
/// that cannot be built must stop the proxy, never silently disable client auth).
#[derive(Debug)]
pub enum MtlsError {
    Io { path: PathBuf, source: std::io::Error },
    NoRoots(PathBuf),
    Verifier(tokio_rustls::rustls::server::VerifierBuilderError),
}

impl fmt::Display for MtlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } =>
                write!(f, "cannot read client-CA file {}: {source}", path.display()),
            Self::NoRoots(p) =>
                write!(f, "no usable CA certificates in {}", p.display()),
            Self::Verifier(e) => write!(f, "client-cert verifier build error: {e}"),
        }
    }
}

impl std::error::Error for MtlsError {}

/// Build a client-certificate verifier from a PEM file of trusted CA certificates.
/// Uses the `ring` crypto provider explicitly (no process-global default), matching
/// the core.
pub fn verifier_from_ca_file(ca_path: &Path) -> Result<Arc<dyn ClientCertVerifier>, MtlsError> {
    let data = std::fs::read(ca_path)
        .map_err(|source| MtlsError::Io { path: ca_path.to_path_buf(), source })?;
    let mut reader: &[u8] = &data;

    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut reader) {
        let cert = cert.map_err(|source| MtlsError::Io { path: ca_path.to_path_buf(), source })?;
        // A malformed entry is skipped rather than fatal; "zero usable roots" below is the
        // real failure (an empty/garbage bundle must not silently accept every client).
        let _ = roots.add(cert);
    }
    if roots.is_empty() {
        return Err(MtlsError::NoRoots(ca_path.to_path_buf()));
    }

    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::new(ring::default_provider()))
        .build()
        .map_err(MtlsError::Verifier)
}
