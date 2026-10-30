// SPDX-License-Identifier: Apache-2.0
//! The shipped example CR (deploy/operator/sample-wafproxy.yaml) must deserialize into the
//! generated `WafProxy` type — a guard that the docs/sample and the CRD schema stay in sync.

use waf_operator::WafProxy;

#[test]
fn sample_wafproxy_manifest_deserializes() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/operator/sample-wafproxy.yaml"
    );
    let yaml = std::fs::read_to_string(path).expect("read sample-wafproxy.yaml");
    let wp: WafProxy = serde_saphyr::from_str(&yaml).expect("sample CR must match the WafProxy type");

    assert_eq!(wp.metadata.name.as_deref(), Some("myapp-waf"));
    assert_eq!(wp.spec.backend.service.as_ref().unwrap().name, "myapp");
    assert_eq!(wp.spec.replicas, 2);
    assert!(wp.spec.crs_curated);
    assert_eq!(
        wp.spec.backend_url("prod").as_deref(),
        Some("http://myapp.prod.svc.cluster.local:8080")
    );
}
