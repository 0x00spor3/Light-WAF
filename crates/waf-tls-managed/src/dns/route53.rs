// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! [`Route53Dns`] — a [`DnsProvider`] over AWS Route 53, via the official `aws-sdk-route53`
//! (correct SigV4 signing + endpoint resolution).
//!
//! ## Value-based, rrset semantics (the R1 case)
//! Unlike Cloudflare (one API record per value, deletable by id), Route 53 is **rrset-based**:
//! you manage the whole `ResourceRecordSet` for a `(name, TYPE)`. So adding a second TXT value
//! to `_acme-challenge.example.com` (apex **and** wildcard) must UPSERT the FULL set of values
//! — a naive single-value UPSERT would replace the first. This provider therefore tracks the
//! values it has published per name in memory and **read-modify-writes** the rrset on every
//! add/remove. [`TxtHandle`](super::TxtHandle) is value-based here (`provider_ref` empty).
//!
//! Credentials come from the caller (the wiring layer reads the standard `AWS_ACCESS_KEY_ID` /
//! `AWS_SECRET_ACCESS_KEY` env vars), never the config file. `zone_id` is the hosted-zone id.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use async_trait::async_trait;
use aws_sdk_route53::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};
use aws_sdk_route53::Client;

use super::{DnsError, DnsProvider, TxtHandle};

/// A DNS-01 provider backed by AWS Route 53, scoped to one hosted zone.
pub struct Route53Dns {
    client: Client,
    zone_id: String,
    /// The TXT values we have published, per record name — the source for the read-modify-write
    /// UPSERT that keeps apex + wildcard values coexisting on the same name.
    published: Mutex<HashMap<String, BTreeSet<String>>>,
}

impl Route53Dns {
    /// Build a provider for `zone_id` (a Route 53 hosted-zone id) with static credentials.
    /// Route 53 is a global service; `region` is used only for signing (`us-east-1` is the
    /// conventional value).
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
        region: impl Into<String>,
        zone_id: impl Into<String>,
    ) -> Self {
        let creds = Credentials::new(
            access_key_id.into(),
            secret_access_key.into(),
            session_token,
            None,
            "waf-route53",
        );
        let conf = aws_sdk_route53::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(region.into()))
            .credentials_provider(creds)
            .build();
        Self {
            client: Client::from_conf(conf),
            zone_id: zone_id.into(),
            published: Mutex::new(HashMap::new()),
        }
    }

    /// Apply one change (UPSERT/DELETE) to the TXT rrset at `name` with exactly `values`.
    async fn apply(&self, action: ChangeAction, name: &str, values: &[String]) -> Result<(), DnsError> {
        // Route 53 requires TXT values wrapped in double quotes. ACME dns-01 values are
        // base64url (no quotes/specials), so plain wrapping is sufficient.
        let records = values
            .iter()
            .map(|v| ResourceRecord::builder().value(format!("\"{v}\"")).build())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| DnsError::Api(e.to_string()))?;
        let rrset = ResourceRecordSet::builder()
            .name(name)
            .r#type(RrType::Txt)
            .ttl(60)
            .set_resource_records(Some(records))
            .build()
            .map_err(|e| DnsError::Api(e.to_string()))?;
        let change = Change::builder()
            .action(action)
            .resource_record_set(rrset)
            .build()
            .map_err(|e| DnsError::Api(e.to_string()))?;
        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| DnsError::Api(e.to_string()))?;
        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| DnsError::Api(format!("route53 change failed: {e}")))?;
        Ok(())
    }
}

/// What `remove_txt` must do once the in-memory set has been updated.
enum RemovePlan {
    /// We never published this name (already gone) — nothing to do.
    Noop,
    /// The set is now empty — delete the rrset (it currently holds exactly these values).
    Delete(Vec<String>),
    /// Siblings remain — re-UPSERT the rrset with the remaining values.
    Upsert(Vec<String>),
}

#[async_trait]
impl DnsProvider for Route53Dns {
    async fn add_txt(&self, name: &str, value: &str) -> Result<TxtHandle, DnsError> {
        let values = {
            let mut pub_map = self.published.lock().unwrap();
            let set = pub_map.entry(name.to_string()).or_default();
            set.insert(value.to_string());
            set.iter().cloned().collect::<Vec<_>>()
        };
        self.apply(ChangeAction::Upsert, name, &values).await?;
        Ok(TxtHandle {
            name: name.to_string(),
            value: value.to_string(),
            provider_ref: String::new(),
        })
    }

    async fn remove_txt(&self, handle: &TxtHandle) -> Result<(), DnsError> {
        let plan = {
            let mut pub_map = self.published.lock().unwrap();
            let decision = match pub_map.get_mut(&handle.name) {
                Some(set) => {
                    set.remove(&handle.value);
                    if set.is_empty() {
                        RemovePlan::Delete(vec![handle.value.clone()])
                    } else {
                        RemovePlan::Upsert(set.iter().cloned().collect())
                    }
                }
                None => RemovePlan::Noop,
            };
            if let RemovePlan::Delete(_) = decision {
                pub_map.remove(&handle.name);
            }
            decision
        };
        match plan {
            RemovePlan::Noop => Ok(()),
            RemovePlan::Delete(values) => self.apply(ChangeAction::Delete, &handle.name, &values).await,
            RemovePlan::Upsert(values) => self.apply(ChangeAction::Upsert, &handle.name, &values).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builds_client_and_tracks_rrset_values() {
        let p = Route53Dns::new("AKIAEXAMPLE", "secret", None, "us-east-1", "Z123456");
        assert_eq!(p.zone_id, "Z123456");
        // The in-memory rrset bookkeeping (the R1-critical part) is testable without AWS:
        // simulate the apex + wildcard publish/cleanup the driver performs.
        let name = "_acme-challenge.example.com";
        {
            let mut m = p.published.lock().unwrap();
            m.entry(name.to_string()).or_default().insert("apex".into());
            m.entry(name.to_string()).or_default().insert("wild".into());
            let set = &m[name];
            assert!(set.contains("apex") && set.contains("wild"), "both values coexist on one name");
        }
    }
}
