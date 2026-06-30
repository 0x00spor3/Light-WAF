// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Inbound TLS termination (Phase 12).
//!
//! **Basic, cert-from-file termination is OPEN core** (`BOUNDARY.md` §3.2): it makes a
//! single node self-sufficient for `https://`. Cert management *at scale* — ACME/Let's
//! Encrypt, rotation, centralized multi-node certs, **mTLS with managed PKI** — is
//! ENTERPRISE (governance/scale) and plugs in behind the [`TlsCertSource`] seam, the §4
//! boundary pattern: the OPEN tier ships [`FileCertSource`]; an enterprise crate provides
//! an at-scale impl of the SAME trait.
//!
//! ALPN advertises `h2` + `http/1.1` (config-driven) so an h2-capable client (e.g.
//! gRPC-over-TLS, a later phase) negotiates HTTP/2 while an h1-only client falls back
//! cleanly — both then flow through the SAME protocol-neutral `handle()`.
//!
//! **No silent downgrade**: when TLS is enabled the listener serves ONLY TLS. A required
//! cert that cannot be loaded is a fatal boot error (`acceptor_from_config` returns `Err`,
//! the proxy refuses to bind) — never a fallback to cleartext on the same port.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::danger::ClientCertVerifier;
use tokio_rustls::rustls::server::ResolvesServerCert;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use waf_core::TlsConfig;

/// Server certificate material: a leaf-first chain + its private key, as rustls DER types.
pub struct TlsMaterial {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

/// Source of the server's TLS certificate material — the §4 boundary seam. [`FileCertSource`]
/// is the OPEN implementation; ACME/rotation/managed-PKI are enterprise implementations of
/// this same trait (the core depends only on the trait, never on the at-scale impl).
///
/// `load()` is the single-cert path (the OPEN baseline). The two *defaulted* hooks below are
/// additive extension points (compatible with the BOUNDARY §5 freeze, like
/// `WafModule::structural()`): an enterprise source overrides them to take over server-cert
/// resolution (hitless ACME rotation) or to require client certificates (mTLS / managed PKI),
/// while every existing impl keeps `load()` + no client auth unchanged.
pub trait TlsCertSource: Send + Sync {
    /// Load a single server certificate chain + key. Used unless [`Self::resolver`]
    /// returns `Some` (in which case the core never calls this).
    fn load(&self) -> Result<TlsMaterial, TlsError>;

    /// Optional dynamic server-cert resolver. When `Some`, the core builds the
    /// `ServerConfig` with this resolver INSTEAD of `load()` (so the cert can rotate
    /// at runtime without rebuilding the acceptor — enterprise hitless ACME), and
    /// advertises the `acme-tls/1` ALPN so an on-listener TLS-ALPN-01 challenge can
    /// negotiate on the same port. Default `None` → the OPEN single-cert path.
    fn resolver(&self) -> Option<Arc<dyn ResolvesServerCert>> {
        None
    }

    /// Optional client-certificate verifier. When `Some`, the listener requires and
    /// verifies client certificates (mTLS / managed PKI). Default `None` → no client
    /// auth, exactly as before.
    fn client_verifier(&self) -> Option<Arc<dyn ClientCertVerifier>> {
        None
    }
}

/// Why building the TLS terminator failed. All variants are fatal at boot (a required TLS
/// that cannot be built must stop the proxy, never degrade to cleartext).
#[derive(Debug)]
pub enum TlsError {
    Io { path: PathBuf, source: std::io::Error },
    NoCertificates(PathBuf),
    NoPrivateKey(PathBuf),
    Rustls(tokio_rustls::rustls::Error),
}

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } =>
                write!(f, "cannot read TLS file {}: {source}", path.display()),
            Self::NoCertificates(p) =>
                write!(f, "no PEM certificates found in {}", p.display()),
            Self::NoPrivateKey(p) =>
                write!(f, "no PEM private key found in {}", p.display()),
            Self::Rustls(e) => write!(f, "TLS configuration error: {e}"),
        }
    }
}

impl std::error::Error for TlsError {}

/// OPEN cert source: read a PEM certificate chain + private key from two files.
pub struct FileCertSource {
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl FileCertSource {
    pub fn new(cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        Self { cert_path: cert_path.into(), key_path: key_path.into() }
    }
}

impl TlsCertSource for FileCertSource {
    fn load(&self) -> Result<TlsMaterial, TlsError> {
        Ok(TlsMaterial {
            cert_chain: load_certs(&self.cert_path)?,
            private_key: load_key(&self.key_path)?,
        })
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Io { path: path.to_path_buf(), source })?;
    let mut reader: &[u8] = &data;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<_, _>>()
        .map_err(|source| TlsError::Io { path: path.to_path_buf(), source })?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificates(path.to_path_buf()));
    }
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data = std::fs::read(path).map_err(|source| TlsError::Io { path: path.to_path_buf(), source })?;
    let mut reader: &[u8] = &data;
    rustls_pemfile::private_key(&mut reader)
        .map_err(|source| TlsError::Io { path: path.to_path_buf(), source })?
        .ok_or_else(|| TlsError::NoPrivateKey(path.to_path_buf()))
}

/// Build a rustls [`ServerConfig`] from a cert source + ALPN list. Uses the `ring` crypto
/// provider explicitly (no process-global `install_default`, so multiple configs — e.g. in
/// tests — never race over the default).
pub fn build_server_config(source: &dyn TlsCertSource, alpn: &[String]) -> Result<ServerConfig, TlsError> {
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?;

    // Client auth: an injected verifier (enterprise mTLS / managed PKI) or none (OPEN).
    let builder = match source.client_verifier() {
        Some(verifier) => builder.with_client_cert_verifier(verifier),
        None => builder.with_no_client_auth(),
    };

    // Server cert: a dynamic resolver (enterprise hitless rotation / ACME) takes over and
    // bypasses load(); otherwise the single cert from load() (the OPEN FileCertSource path,
    // byte-identical to before).
    let mut cfg = match source.resolver() {
        Some(resolver) => builder.with_cert_resolver(resolver),
        None => {
            let material = source.load()?;
            builder
                .with_single_cert(material.cert_chain, material.private_key)
                .map_err(TlsError::Rustls)?
        }
    };

    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    // TLS-ALPN-01: when a resolver drives ACME on this same listener, the challenge is
    // negotiated via the `acme-tls/1` ALPN — advertise it so the validation handshake can
    // select it (the resolver serves the challenge cert for it). Only when a resolver is set,
    // so the normal (None) path keeps exactly the configured ALPN list.
    if source.resolver().is_some() {
        cfg.alpn_protocols.push(b"acme-tls/1".to_vec());
    }
    Ok(cfg)
}

/// Build the [`TlsAcceptor`] with an **injected** cert source, or `Ok(None)` when TLS is
/// off. `tls.enabled` (operator switch) and `tls.alpn` still come from config; the source
/// only governs cert *provenance* — when `Some`, the file paths in config are ignored, so
/// an enterprise ACME/managed-PKI source needs no `cert_path`/`key_path`. `None` falls back
/// to the OPEN [`FileCertSource`]. An enabled-but-unbuildable terminator is `Err` → the
/// proxy fails to bind (fatal boot, no silent cleartext fallback).
pub fn acceptor_from_source(
    tls: &TlsConfig,
    source: Option<Arc<dyn TlsCertSource>>,
) -> Result<Option<TlsAcceptor>, TlsError> {
    if !tls.enabled {
        return Ok(None);
    }
    let cfg = match source {
        Some(s) => build_server_config(s.as_ref(), &tls.alpn)?,
        None => build_server_config(&FileCertSource::new(&tls.cert_path, &tls.key_path), &tls.alpn)?,
    };
    Ok(Some(TlsAcceptor::from(Arc::new(cfg))))
}

/// Build the [`TlsAcceptor`] from config with the default OPEN [`FileCertSource`]. Thin
/// wrapper over [`acceptor_from_source`] with no injected source.
pub fn acceptor_from_config(tls: &TlsConfig) -> Result<Option<TlsAcceptor>, TlsError> {
    acceptor_from_source(tls, None)
}
