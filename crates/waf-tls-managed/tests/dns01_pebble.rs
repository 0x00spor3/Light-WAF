// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Live DNS-01 probe against Pebble + `pebble-challtestsrv` (the Step-0 / R4 vertical slice).
//!
//! **ENV-GATED**: runs only when `WAF_ACME_PEBBLE=1` (the two containers must be up), exactly
//! like the Redis live tests. Normal `cargo test` compiles it and self-skips.
//!
//! It exercises the whole suture: account trusting Pebble's CA → order → DNS-01 fulfilled via
//! challtestsrv → finalize with OUR key → issued chain → `CertifiedKey` built with the core's
//! rustls → installed into the resolver. Asserting a cert ends up installed proves the slice.
//!
//! ## Bring up the environment (Linux/Docker)
//! ```sh
//! docker network create acme 2>/dev/null || true
//! # mock DNS + management API on :8055, answering A/AAAA and the TXT records we set
//! docker run -d --name challtestsrv --network acme -p 8055:8055 \
//!   ghcr.io/letsencrypt/pebble-challtestsrv:latest -defaultIPv6 "" -defaultIPv4 127.0.0.1
//! # Pebble ACME directory on :14000, using challtestsrv as its DNS resolver
//! docker run -d --name pebble --network acme -p 14000:14000 \
//!   -e PEBBLE_VA_NOSLEEP=1 ghcr.io/letsencrypt/pebble:latest \
//!   pebble -config /test/config/pebble-config.json -dnsserver challtestsrv:8053
//! # Pebble's CA (to trust its directory TLS) — copy it out of the image once:
//! docker cp pebble:/test/certs/pebble.minica.pem ./pebble.minica.pem
//! ```
//! Then: `WAF_ACME_PEBBLE=1 PEBBLE_CA=./pebble.minica.pem cargo test -p waf-tls-managed --test dns01_pebble -- --nocapture`

use instant_acme::{Account, NewAccount};
use waf_tls_managed::acme_dns01::{issue_once, Dns01Config, Dns01Resolver};
use waf_tls_managed::dns::ChallTestSrvDns;

#[tokio::test]
async fn dns01_issues_and_installs_against_pebble() {
    if std::env::var("WAF_ACME_PEBBLE").ok().as_deref() != Some("1") {
        eprintln!("skipping: set WAF_ACME_PEBBLE=1 (with Pebble + challtestsrv up) to run");
        return;
    }

    // Knobs default to the standard Pebble docker setup.
    let directory =
        std::env::var("PEBBLE_DIRECTORY").unwrap_or_else(|_| "https://localhost:14000/dir".into());
    let pebble_ca = std::env::var("PEBBLE_CA").unwrap_or_else(|_| "pebble.minica.pem".into());
    let challtestsrv =
        std::env::var("CHALLTESTSRV").unwrap_or_else(|_| "http://localhost:8055".into());
    let domain = std::env::var("ACME_DOMAIN").unwrap_or_else(|_| "waf.test".into());

    // Account whose ACME-directory HTTPS trusts Pebble's self-signed CA (impossible with the
    // rustls-acme path — this is why DNS-01 testing is cleaner locally).
    let (account, _creds) = Account::builder_with_root(&pebble_ca)
        .expect("load Pebble CA root")
        .create(
            &NewAccount {
                contact: &[],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory,
            None,
        )
        .await
        .expect("create ACME account against Pebble");

    let provider = ChallTestSrvDns::new(challtestsrv);
    let resolver = Dns01Resolver::new();

    // Wildcard issuance: a single authorization → one TXT value, which challtestsrv can hold.
    // (The apex+wildcard two-value case is the in-memory unit test, not this live probe.)
    let domains = vec![format!("*.{domain}")];
    issue_once(&account, &domains, &provider, &resolver, &Dns01Config::default(), None, None)
        .await
        .expect("DNS-01 issuance + install");

    assert!(
        resolver.current().is_some(),
        "a certificate must be installed in the resolver after issuance"
    );
}
