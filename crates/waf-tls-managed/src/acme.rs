// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! ACME server-cert provisioning — the L1 enterprise seam (`TlsCertSource::resolver`).
//!
//! Default strategy **TLS-ALPN-01** via `rustls-acme`: validation and renewal happen on
//! the SAME :443 listener (the `acme-tls/1` ALPN the core advertises when a resolver is
//! set), and the returned `ResolvesServerCert` rotates the live cert **without restarting
//! the acceptor** (hitless). A background task drives ordering/renewal.
//!
//! **DNS-01** is recognised as a second-tier strategy (wildcards / when the CA cannot reach
//! :443) but its provider integration is a follow-on (`rustls-acme` is TLS-ALPN-01 only;
//! DNS-01 needs `instant-acme` + a provider API + a custom resolver). Selecting it today
//! returns a clear error rather than silently doing nothing.

use std::path::PathBuf;
use std::sync::Arc;

use futures::StreamExt;
use rustls_acme::{caches::DirCache, AcmeConfig};
use tokio_rustls::rustls::server::ResolvesServerCert;
use tracing::{error, info};

/// ACME challenge strategy. `TlsAlpn01` is the default (single-port, hitless).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ChallengeStrategy {
    #[default]
    TlsAlpn01,
    /// Provider-driven DNS-01 (follow-on). Carries the provider name for diagnostics.
    Dns01 { provider: Option<String> },
}

/// Inputs for the ACME resolver.
#[derive(Debug, Clone)]
pub struct AcmeParams {
    pub domains: Vec<String>,
    pub email: Option<String>,
    pub cache_dir: PathBuf,
    /// `true` ⇒ Let's Encrypt staging (or, with `directory_url`, that test CA).
    pub staging: bool,
    /// Override the ACME directory URL (e.g. a Pebble test server). When `None`, uses
    /// Let's Encrypt (staging or production per `staging`).
    pub directory_url: Option<String>,
    pub strategy: ChallengeStrategy,
}

/// Why the ACME resolver could not be started.
#[derive(Debug)]
pub enum AcmeError {
    NoDomains,
    /// DNS-01 selected but its provider integration is not implemented yet.
    Dns01NotImplemented,
}

impl std::fmt::Display for AcmeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoDomains => write!(f, "[tls.acme] requires at least one domain"),
            Self::Dns01NotImplemented => write!(
                f,
                "[tls.acme] strategy = \"dns-01\" is not implemented yet (use \"tls-alpn-01\")"
            ),
        }
    }
}

impl std::error::Error for AcmeError {}

/// Start the ACME background driver and return the server-cert resolver to hand to the
/// core via `TlsCertSource::resolver`. MUST be called inside a tokio runtime (it spawns
/// the renewal task).
pub fn start_resolver(params: &AcmeParams) -> Result<Arc<dyn ResolvesServerCert>, AcmeError> {
    if params.domains.is_empty() {
        return Err(AcmeError::NoDomains);
    }
    if let ChallengeStrategy::Dns01 { .. } = params.strategy {
        return Err(AcmeError::Dns01NotImplemented);
    }

    let mut config = AcmeConfig::new(params.domains.clone()).cache(DirCache::new(params.cache_dir.clone()));
    if let Some(email) = &params.email {
        config = config.contact_push(format!("mailto:{email}"));
    }
    let config = match &params.directory_url {
        Some(url) => config.directory(url.clone()),
        None => config.directory_lets_encrypt(!params.staging), // production = !staging
    };

    let mut state = config.state();
    let resolver = state.resolver();
    info!(domains = ?params.domains, "ACME (TLS-ALPN-01) resolver started; ordering/renewal in background");
    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(ok)) => info!(event = ?ok, "ACME"),
                Some(Err(e)) => error!(error = %e, "ACME error"),
                None => break,
            }
        }
    });
    Ok(resolver)
}
