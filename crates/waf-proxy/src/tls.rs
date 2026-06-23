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
pub trait TlsCertSource: Send + Sync {
    fn load(&self) -> Result<TlsMaterial, TlsError>;
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
    let material = source.load()?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Rustls)?
        .with_no_client_auth()
        .with_single_cert(material.cert_chain, material.private_key)
        .map_err(TlsError::Rustls)?;
    cfg.alpn_protocols = alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    Ok(cfg)
}

/// Build the [`TlsAcceptor`] from config, or `Ok(None)` when TLS is off (cleartext). An
/// enabled-but-unbuildable terminator is `Err` → the proxy fails to bind (fatal boot, no
/// silent cleartext fallback). Uses [`FileCertSource`]; swap the source for an enterprise
/// one without touching this signature.
pub fn acceptor_from_config(tls: &TlsConfig) -> Result<Option<TlsAcceptor>, TlsError> {
    if !tls.enabled {
        return Ok(None);
    }
    let source = FileCertSource::new(&tls.cert_path, &tls.key_path);
    let cfg = build_server_config(&source, &tls.alpn)?;
    Ok(Some(TlsAcceptor::from(Arc::new(cfg))))
}
