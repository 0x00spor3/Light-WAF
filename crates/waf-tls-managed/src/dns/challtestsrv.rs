// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! [`ChallTestSrvDns`] — a [`DnsProvider`] backed by Let's Encrypt's `pebble-challtestsrv`
//! mock DNS, used ONLY for local/CI DNS-01 testing against Pebble. It POSTs to the
//! challtestsrv management API (default `:8055`): `/set-txt` to publish, `/clear-txt` to
//! remove.
//!
//! ## Single-value caveat (why this is test-only)
//! challtestsrv's `/set-txt` **replaces** the TXT set for a host (one value list per host).
//! So this provider can hold at most one value per name — enough for a single-domain or
//! wildcard-only probe. The additive multi-value contract (apex + wildcard on the same name)
//! is verified separately by a unit test against an in-memory provider; challtestsrv cannot
//! represent two concurrent values through its API. A real provider (Cloudflare) does.

use async_trait::async_trait;
use serde::Serialize;

use super::{DnsError, DnsProvider, TxtHandle};

/// A DNS-01 provider talking to a `pebble-challtestsrv` management endpoint.
pub struct ChallTestSrvDns {
    /// Base URL of the challtestsrv management API, e.g. `http://127.0.0.1:8055`.
    base_url: String,
    http: reqwest::Client,
}

impl ChallTestSrvDns {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self { base_url: base_url.into(), http: reqwest::Client::new() }
    }
}

#[derive(Serialize)]
struct SetTxt<'a> {
    host: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct ClearTxt<'a> {
    host: &'a str,
}

#[async_trait]
impl DnsProvider for ChallTestSrvDns {
    async fn add_txt(&self, name: &str, value: &str) -> Result<TxtHandle, DnsError> {
        let host = fqdn(name);
        self.http
            .post(format!("{}/set-txt", self.base_url))
            .json(&SetTxt { host: &host, value })
            .send()
            .await
            .map_err(|e| DnsError::Api(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Api(e.to_string()))?;
        Ok(TxtHandle {
            name: name.to_string(),
            value: value.to_string(),
            provider_ref: String::new(),
        })
    }

    async fn remove_txt(&self, handle: &TxtHandle) -> Result<(), DnsError> {
        let host = fqdn(&handle.name);
        self.http
            .post(format!("{}/clear-txt", self.base_url))
            .json(&ClearTxt { host: &host })
            .send()
            .await
            .map_err(|e| DnsError::Api(e.to_string()))?
            .error_for_status()
            .map_err(|e| DnsError::Api(e.to_string()))?;
        Ok(())
    }
}

/// challtestsrv keys its mock records by the fully-qualified name (trailing dot).
fn fqdn(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}
