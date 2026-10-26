// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! DNS provider abstraction for ACME **DNS-01** — publish/remove the `_acme-challenge.<base>`
//! TXT records the challenge needs. Concrete providers (Cloudflare, a test challtestsrv, …)
//! implement this trait; the DNS-01 driver ([`crate::acme_dns01`]) is provider-agnostic.
//!
//! ## The frozen contract: ADD/REMOVE of one value, never set/overwrite
//!
//! A single `_acme-challenge.<base>` name can legitimately carry **several** TXT values at
//! once. Validating `example.com` **and** `*.example.com` produces two distinct ACME
//! authorizations whose challenge tokens both publish under
//! `_acme-challenge.example.com` — two values on the *same* name, concurrently.
//!
//! Therefore the contract is deliberately **add one value / remove that exact value**, and a
//! [`TxtHandle`] identifies the **single record**, not the name. A provider that "sets" the
//! name (overwriting its value list) would make the second challenge clobber the first — so
//! that shape is forbidden by this trait. This is the one design choice that is expensive to
//! change later, so it is fixed here up front.

use std::fmt;

use async_trait::async_trait;

pub mod challtestsrv;
pub mod cloudflare;
pub mod route53;
pub use challtestsrv::ChallTestSrvDns;
pub use cloudflare::CloudflareDns;
pub use route53::Route53Dns;

/// A DNS provider that can publish and remove individual ACME DNS-01 TXT values.
///
/// Implementations MUST be additive: [`add_txt`](DnsProvider::add_txt) adds **one** value
/// without disturbing other values already present at the same name, and
/// [`remove_txt`](DnsProvider::remove_txt) deletes **exactly** the record named by the
/// handle. See the module docs for why (wildcard + apex share one name).
#[async_trait]
pub trait DnsProvider: Send + Sync {
    /// Publish one TXT `value` at the fully-qualified `name` (already
    /// `_acme-challenge.<base>`). Returns a [`TxtHandle`] identifying the single record just
    /// created, so it can later be removed precisely without touching sibling values.
    async fn add_txt(&self, name: &str, value: &str) -> Result<TxtHandle, DnsError>;

    /// Remove exactly the record identified by `handle`. Idempotent: removing a record that
    /// is already gone is `Ok` (cleanup must never fail a renewal).
    async fn remove_txt(&self, handle: &TxtHandle) -> Result<(), DnsError>;
}

/// Identifies **one** published TXT record (never just the name).
///
/// The provider that minted the handle in `add_txt` is the only one that consumes it in
/// `remove_txt`, so it decides which field is authoritative for deletion:
/// - id-based providers (e.g. Cloudflare) store the record id in [`provider_ref`](Self::provider_ref)
///   and delete by id;
/// - value-based providers (e.g. RFC2136 dynamic update, deSEC rrset edit) delete by the
///   `(name, value)` pair.
///
/// `name`/`value` are always populated (for value-based deletion and for diagnostics/logging
/// on cleanup); `provider_ref` is empty when the provider is value-based.
#[derive(Debug, Clone)]
pub struct TxtHandle {
    /// Fully-qualified record name (e.g. `_acme-challenge.example.com`).
    pub name: String,
    /// The exact TXT value of this single record.
    pub value: String,
    /// Provider-minted identity of the single record (e.g. a Cloudflare record id). Empty for
    /// value-based providers, which delete by `(name, value)`.
    pub provider_ref: String,
}

/// Why a DNS provider operation failed. Provider-specific detail is carried as a message so
/// the trait stays object-safe and provider-agnostic.
#[derive(Debug)]
pub enum DnsError {
    /// The provider's API rejected the request or was unreachable.
    Api(String),
    /// The provider is misconfigured (missing token, unknown zone, …) — fatal at boot.
    Config(String),
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(m) => write!(f, "DNS provider API error: {m}"),
            Self::Config(m) => write!(f, "DNS provider config error: {m}"),
        }
    }
}

impl std::error::Error for DnsError {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// In-memory provider that records every record by a unique id — the reference shape a
    /// correct provider must have (Cloudflare = create/delete by record id). It proves the
    /// frozen contract: two values on the SAME name coexist, and removal is per-record.
    #[derive(Default)]
    struct MemDns {
        // (id, name, value)
        records: Mutex<Vec<(String, String, String)>>,
        next_id: Mutex<u64>,
    }

    impl MemDns {
        fn values_at(&self, name: &str) -> Vec<String> {
            self.records
                .lock()
                .unwrap()
                .iter()
                .filter(|(_, n, _)| n == name)
                .map(|(_, _, v)| v.clone())
                .collect()
        }
    }

    #[async_trait]
    impl DnsProvider for MemDns {
        async fn add_txt(&self, name: &str, value: &str) -> Result<TxtHandle, DnsError> {
            let mut id = self.next_id.lock().unwrap();
            *id += 1;
            let rec_id = id.to_string();
            self.records.lock().unwrap().push((
                rec_id.clone(),
                name.to_string(),
                value.to_string(),
            ));
            Ok(TxtHandle {
                name: name.to_string(),
                value: value.to_string(),
                provider_ref: rec_id,
            })
        }

        async fn remove_txt(&self, handle: &TxtHandle) -> Result<(), DnsError> {
            self.records.lock().unwrap().retain(|(id, _, _)| id != &handle.provider_ref);
            Ok(())
        }
    }

    /// R1: the apex + wildcard case. Two challenges publish two DIFFERENT values under the
    /// SAME `_acme-challenge.example.com`. The additive contract must keep BOTH present, and
    /// removing one (by its handle) must leave the other untouched.
    #[tokio::test]
    async fn two_values_on_one_name_coexist_and_remove_is_per_record() {
        let dns = MemDns::default();
        let name = "_acme-challenge.example.com";

        let h_apex = dns.add_txt(name, "apex-token-value").await.unwrap();
        let h_wild = dns.add_txt(name, "wildcard-token-value").await.unwrap();

        // Both values live on the same name at once (this is what set/overwrite would break).
        let mut values = dns.values_at(name);
        values.sort();
        assert_eq!(values, vec!["apex-token-value", "wildcard-token-value"]);
        // The handles point at distinct records.
        assert_ne!(h_apex.provider_ref, h_wild.provider_ref);

        // Remove exactly one → the sibling survives.
        dns.remove_txt(&h_apex).await.unwrap();
        assert_eq!(dns.values_at(name), vec!["wildcard-token-value"]);

        // Idempotent cleanup of an already-gone record.
        dns.remove_txt(&h_apex).await.unwrap();
        dns.remove_txt(&h_wild).await.unwrap();
        assert!(dns.values_at(name).is_empty());
    }
}
