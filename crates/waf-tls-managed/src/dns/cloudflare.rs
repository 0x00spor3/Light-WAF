// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! [`CloudflareDns`] — a real [`DnsProvider`] over the Cloudflare DNS API. It satisfies the
//! frozen additive contract by creating each TXT as its OWN record and deleting it **by
//! record id**, so apex + wildcard values on the same `_acme-challenge.<base>` never clobber
//! each other (the [`TxtHandle::provider_ref`](super::TxtHandle) carries the Cloudflare id).
//!
//! Auth is a scoped API token (`Zone:DNS:Edit`), supplied by the caller (the wiring layer
//! reads it from the `CF_API_TOKEN` env var — never the config file). One [`CloudflareDns`]
//! targets one zone (`zone_id`); apex + wildcard of the same apex share that zone. The HTTPS
//! client uses a `ring`-based rustls config (no aws-lc-rs/cmake), matching the core.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_rustls::rustls::crypto::ring;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

use super::{DnsError, DnsProvider, TxtHandle};

const DEFAULT_API_BASE: &str = "https://api.cloudflare.com/client/v4";

/// A DNS-01 provider backed by the Cloudflare API, scoped to a single zone.
pub struct CloudflareDns {
    api_base: String,
    zone_id: String,
    api_token: String,
    http: reqwest::Client,
}

impl CloudflareDns {
    /// Build a provider for `zone_id`, authenticating with `api_token`. Fails (boot-fatal) if
    /// the HTTPS client cannot be built.
    pub fn new(api_token: impl Into<String>, zone_id: impl Into<String>) -> Result<Self, DnsError> {
        Self::with_base(DEFAULT_API_BASE, api_token, zone_id)
    }

    /// Same as [`new`](Self::new) but with an overridable API base URL (for tests / a mock).
    pub fn with_base(
        api_base: impl Into<String>,
        api_token: impl Into<String>,
        zone_id: impl Into<String>,
    ) -> Result<Self, DnsError> {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        // `ring` explicitly — reqwest carries no provider (`rustls-no-provider`), and this
        // matches the core's crypto provider.
        let tls = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| DnsError::Config(format!("rustls client config: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .build()
            .map_err(|e| DnsError::Config(format!("cloudflare http client: {e}")))?;
        Ok(Self {
            api_base: api_base.into(),
            zone_id: zone_id.into(),
            api_token: api_token.into(),
            http,
        })
    }
}

/// Request body for creating a TXT record.
#[derive(Serialize)]
struct NewTxt<'a> {
    r#type: &'a str,
    name: &'a str,
    content: &'a str,
    ttl: u32,
}

/// Cloudflare's standard envelope. We only need `success`/`errors` and the record id.
#[derive(Deserialize)]
struct CfEnvelope<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CfError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
struct CfRecord {
    id: String,
}

fn errors_to_string(errors: &[CfError]) -> String {
    if errors.is_empty() {
        return "unknown error".to_string();
    }
    errors.iter().map(|e| format!("{} ({})", e.message, e.code)).collect::<Vec<_>>().join("; ")
}

#[async_trait]
impl DnsProvider for CloudflareDns {
    async fn add_txt(&self, name: &str, value: &str) -> Result<TxtHandle, DnsError> {
        let url = format!("{}/zones/{}/dns_records", self.api_base, self.zone_id);
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.api_token)
            .json(&NewTxt { r#type: "TXT", name, content: value, ttl: 60 })
            .send()
            .await
            .map_err(|e| DnsError::Api(e.to_string()))?;
        let body: CfEnvelope<CfRecord> =
            resp.json().await.map_err(|e| DnsError::Api(format!("decode create response: {e}")))?;
        if !body.success {
            return Err(DnsError::Api(format!("create TXT failed: {}", errors_to_string(&body.errors))));
        }
        let id = body.result.ok_or_else(|| DnsError::Api("create TXT: no record in response".into()))?.id;
        Ok(TxtHandle { name: name.to_string(), value: value.to_string(), provider_ref: id })
    }

    async fn remove_txt(&self, handle: &TxtHandle) -> Result<(), DnsError> {
        let url = format!("{}/zones/{}/dns_records/{}", self.api_base, self.zone_id, handle.provider_ref);
        let resp = self
            .http
            .delete(url)
            .bearer_auth(&self.api_token)
            .send()
            .await
            .map_err(|e| DnsError::Api(e.to_string()))?;
        // Already gone ⇒ nothing to do (cleanup must be idempotent).
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let body: CfEnvelope<CfRecord> =
            resp.json().await.map_err(|e| DnsError::Api(format!("decode delete response: {e}")))?;
        if !body.success {
            return Err(DnsError::Api(format!("delete TXT failed: {}", errors_to_string(&body.errors))));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_txt_serializes_with_cloudflare_field_names() {
        let body = serde_json::to_string(&NewTxt {
            r#type: "TXT",
            name: "_acme-challenge.example.com",
            content: "tokenvalue",
            ttl: 60,
        })
        .unwrap();
        assert!(body.contains("\"type\":\"TXT\""), "{body}");
        assert!(body.contains("\"name\":\"_acme-challenge.example.com\""), "{body}");
        assert!(body.contains("\"content\":\"tokenvalue\""), "{body}");
    }

    #[test]
    fn parses_success_envelope_and_extracts_record_id() {
        let json = r#"{"success":true,"errors":[],"result":{"id":"abc123"}}"#;
        let env: CfEnvelope<CfRecord> = serde_json::from_str(json).unwrap();
        assert!(env.success);
        assert_eq!(env.result.unwrap().id, "abc123");
    }

    #[test]
    fn parses_error_envelope() {
        let json = r#"{"success":false,"errors":[{"code":81044,"message":"Record does not exist"}],"result":null}"#;
        let env: CfEnvelope<CfRecord> = serde_json::from_str(json).unwrap();
        assert!(!env.success);
        assert_eq!(errors_to_string(&env.errors), "Record does not exist (81044)");
    }

    #[test]
    fn builds_with_ring_tls_client() {
        // Proves the ring-based rustls client config + reqwest client actually build.
        let p = CloudflareDns::new("dummy-token", "dummy-zone").expect("client builds");
        assert_eq!(p.zone_id, "dummy-zone");
    }
}
