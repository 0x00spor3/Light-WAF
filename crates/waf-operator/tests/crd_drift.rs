// SPDX-License-Identifier: Apache-2.0
//! Guard against a stale committed CRD: the checked-in deploy/operator/crd.yaml must equal
//! what `waf-operator crd` generates from the current Rust types. Regenerate with:
//!   cargo run -p waf-operator -- crd > deploy/operator/crd.yaml

use kube::CustomResourceExt;
use waf_operator::WafProxy;

#[test]
fn committed_crd_matches_generated() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../deploy/operator/crd.yaml");
    // Normalize line endings: a Windows checkout (core.autocrlf) has CRLF, the generator emits LF.
    let committed = std::fs::read_to_string(path)
        .expect("read deploy/operator/crd.yaml")
        .replace("\r\n", "\n");
    let generated = serde_yaml::to_string(&WafProxy::crd()).expect("serialize CRD");
    assert_eq!(
        committed.trim_end(),
        generated.trim_end(),
        "deploy/operator/crd.yaml is stale — regenerate: cargo run -p waf-operator -- crd > deploy/operator/crd.yaml"
    );
}
