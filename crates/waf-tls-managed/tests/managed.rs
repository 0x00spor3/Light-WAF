// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

//! Construction + error-path tests for the managed-TLS seams. No network (the live
//! ACME-against-Pebble flow is a separate, env-gated concern).

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use waf_tls_managed::acme::{self, AcmeError, AcmeParams, ChallengeStrategy};
use waf_tls_managed::{verifier_from_ca_file, MtlsError};

fn tmp(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    std::env::temp_dir().join(format!("waf-tls-{tag}-{nanos}-{}", N.fetch_add(1, Ordering::Relaxed)))
}

// ── mTLS verifier construction ────────────────────────────────────────────────

#[test]
fn verifier_built_from_a_valid_ca_pem() {
    let ca = rcgen::generate_simple_self_signed(vec!["client-ca".to_string()]).unwrap();
    let path = tmp("ca.pem");
    std::fs::write(&path, ca.cert.pem()).unwrap();

    let verifier = verifier_from_ca_file(&path).expect("verifier builds from a valid CA");
    // It actually wants client auth (the whole point of mTLS).
    assert!(verifier.client_auth_mandatory());
    std::fs::remove_file(&path).ok();
}

#[test]
fn missing_ca_file_is_io_error() {
    let err = verifier_from_ca_file(&tmp("does-not-exist.pem")).unwrap_err();
    assert!(matches!(err, MtlsError::Io { .. }));
}

#[test]
fn empty_ca_file_is_no_roots() {
    let path = tmp("empty.pem");
    std::fs::File::create(&path).unwrap().write_all(b"# no certs here\n").unwrap();
    let err = verifier_from_ca_file(&path).unwrap_err();
    assert!(matches!(err, MtlsError::NoRoots(_)));
    std::fs::remove_file(&path).ok();
}

// ── ACME error paths (return before spawning, so no runtime needed) ────────────

#[test]
fn acme_requires_at_least_one_domain() {
    let params = AcmeParams {
        domains: vec![],
        email: None,
        cache_dir: tmp("acme-cache"),
        staging: true,
        directory_url: None,
        strategy: ChallengeStrategy::TlsAlpn01,
    };
    assert!(matches!(acme::start_resolver(&params), Err(AcmeError::NoDomains)));
}

#[test]
fn dns01_is_not_implemented_yet() {
    let params = AcmeParams {
        domains: vec!["example.com".to_string()],
        email: None,
        cache_dir: tmp("acme-cache"),
        staging: true,
        directory_url: None,
        strategy: ChallengeStrategy::Dns01 { provider: Some("cloudflare".to_string()) },
    };
    assert!(matches!(acme::start_resolver(&params), Err(AcmeError::Dns01NotImplemented)));
}
