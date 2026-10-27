// SPDX-License-Identifier: Apache-2.0
//! Unit tests for the pure render layer — no cluster required.

use std::collections::BTreeMap;
use waf_operator::crd::{Backend, Mode, ServiceRef, WafProxySpec};
use waf_operator::render;

fn spec() -> WafProxySpec {
    WafProxySpec {
        image: "registry.internal:5000/waf-enterprise:0.1.0".into(),
        backend: Backend {
            service: Some(ServiceRef {
                name: "myapp".into(),
                port: 8080,
                namespace: None,
            }),
            url: None,
        },
        mode: Mode::Blocking,
        paranoia_level: 3,
        block_threshold: 3,
        replicas: 2,
        modules: BTreeMap::new(),
        crs_curated: true,
        api_schema_spec_ref: None,
    }
}

#[test]
fn backend_url_from_service_ref_is_cluster_local() {
    let s = spec();
    assert_eq!(
        s.backend_url("prod").as_deref(),
        Some("http://myapp.prod.svc.cluster.local:8080")
    );
}

#[test]
fn backend_url_prefers_explicit_url_and_service_namespace() {
    let mut s = spec();
    s.backend.service.as_mut().unwrap().namespace = Some("other".into());
    assert_eq!(
        s.backend_url("prod").as_deref(),
        Some("http://myapp.other.svc.cluster.local:8080")
    );
    s.backend.url = Some("http://legacy:9000".into());
    assert_eq!(s.backend_url("prod").as_deref(), Some("http://legacy:9000"));
}

#[test]
fn config_toml_is_wellformed_and_carries_values() {
    let cfg = render::config_toml(&spec(), "prod");
    let v: toml::Value = toml::from_str(&cfg).expect("rendered config.toml must parse");

    assert_eq!(
        v["proxy"]["backend"].as_str(),
        Some("http://myapp.prod.svc.cluster.local:8080")
    );
    assert_eq!(v["proxy"]["listen"].as_str(), Some("0.0.0.0:8080"));
    assert_eq!(v["waf"]["mode"].as_str(), Some("blocking"));
    assert_eq!(v["waf"]["paranoia_level"].as_integer(), Some(3));
    assert_eq!(v["waf"]["block_threshold"].as_integer(), Some(3));
    // limits must be plain integers (regression guard for the Helm float64/scientific bug).
    assert_eq!(v["limits"]["max_body_size"].as_integer(), Some(1_048_576));
    // all default modules present + on
    assert_eq!(v["modules"]["sqli"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["modules"]["request_smuggling"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["enterprise"]["crs_curated"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["metrics"]["enabled"].as_bool(), Some(true));
    // no api_schema block when unset
    assert!(v.get("enterprise").and_then(|e| e.get("api_schema")).is_none());
}

#[test]
fn config_toml_module_override_and_detection_mode() {
    let mut s = spec();
    s.mode = Mode::Detection;
    s.modules.insert("sqli".into(), false);
    s.modules.insert("graphql".into(), true); // extra, non-default module
    let cfg = render::config_toml(&s, "prod");
    let v: toml::Value = toml::from_str(&cfg).unwrap();
    assert_eq!(v["waf"]["mode"].as_str(), Some("detection-only"));
    assert_eq!(v["modules"]["sqli"]["enabled"].as_bool(), Some(false));
    assert_eq!(v["modules"]["xss"]["enabled"].as_bool(), Some(true));
    assert_eq!(v["modules"]["graphql"]["enabled"].as_bool(), Some(true));
}

/// The rendered config must be accepted by the WAF's own config type, in both modes —
/// a value the WAF rejects (e.g. `mode = "detection"`) would crash-loop every pod.
#[test]
fn config_toml_parses_as_waf_config() {
    for mode in [Mode::Blocking, Mode::Detection] {
        let mut s = spec();
        s.mode = mode;
        let cfg = render::config_toml(&s, "prod");
        let parsed: Result<waf_core::Config, _> = toml::from_str(&cfg);
        assert!(parsed.is_ok(), "rendered config rejected by waf-core: {:?}\n{cfg}", parsed.err());
    }
}

#[test]
fn config_toml_api_schema_block_when_ref_set() {
    let mut s = spec();
    s.api_schema_spec_ref = Some("myapp-openapi".into());
    let cfg = render::config_toml(&s, "prod");
    let v: toml::Value = toml::from_str(&cfg).unwrap();
    assert_eq!(v["enterprise"]["api_schema"]["enabled"].as_bool(), Some(true));
    assert_eq!(
        v["enterprise"]["api_schema"]["spec_path"].as_str(),
        Some("/etc/waf/openapi.json")
    );
}

#[test]
fn configmap_has_owner_ref_and_config_key() {
    let cm = render::configmap("edge", "prod", "uid-123", &spec());
    assert_eq!(cm.metadata.name.as_deref(), Some("edge-config"));
    assert_eq!(cm.metadata.namespace.as_deref(), Some("prod"));
    let owners = cm.metadata.owner_references.unwrap();
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0].kind, "WafProxy");
    assert_eq!(owners[0].uid, "uid-123");
    assert_eq!(owners[0].controller, Some(true));
    assert!(cm.data.unwrap().contains_key("config.toml"));
}

#[test]
fn deployment_shape() {
    let dep = render::deployment("edge", "prod", "uid-123", &spec());
    let spec_ = dep.spec.unwrap();
    assert_eq!(spec_.replicas, Some(2));
    assert_eq!(
        spec_.selector.match_labels.as_ref().unwrap()["app.kubernetes.io/instance"],
        "edge"
    );
    let pod = spec_.template.spec.unwrap();
    // pod security context: non-root 10001
    let psc = pod.security_context.unwrap();
    assert_eq!(psc.run_as_user, Some(10001));
    assert_eq!(psc.run_as_non_root, Some(true));
    let c = &pod.containers[0];
    assert_eq!(c.image.as_deref(), Some("registry.internal:5000/waf-enterprise:0.1.0"));
    assert_eq!(c.args.as_ref().unwrap(), &vec!["--config".to_string(), "/etc/waf/config.toml".to_string()]);
    // container security: readonly rootfs, drop ALL
    let sc = c.security_context.as_ref().unwrap();
    assert_eq!(sc.read_only_root_filesystem, Some(true));
    assert_eq!(sc.capabilities.as_ref().unwrap().drop.as_ref().unwrap(), &vec!["ALL".to_string()]);
    // three ports: http + metrics + health (K0)
    let ports: Vec<_> = c.ports.as_ref().unwrap().iter().map(|p| p.name.clone().unwrap()).collect();
    assert!(ports.contains(&"http".to_string()) && ports.contains(&"metrics".to_string()));
    assert!(ports.contains(&"health".to_string()), "health port must be exposed");
    // health probes hit /healthz + /readyz (K0), and WAF_HEALTH_LISTEN is set
    assert_eq!(c.liveness_probe.as_ref().unwrap().http_get.as_ref().unwrap().path.as_deref(), Some("/healthz"));
    assert_eq!(c.readiness_probe.as_ref().unwrap().http_get.as_ref().unwrap().path.as_deref(), Some("/readyz"));
    assert!(c.env.as_ref().unwrap().iter().any(|e| e.name == "WAF_HEALTH_LISTEN"));
    // owner ref present
    assert_eq!(dep.metadata.owner_references.unwrap()[0].uid, "uid-123");
    // no api-schema volume when unset
    assert!(!pod.volumes.unwrap().iter().any(|v| v.name == "api-schema"));
}

#[test]
fn deployment_mounts_api_schema_when_ref_set() {
    let mut s = spec();
    s.api_schema_spec_ref = Some("myapp-openapi".into());
    let dep = render::deployment("edge", "prod", "uid-123", &s);
    let pod = dep.spec.unwrap().template.spec.unwrap();
    assert!(pod.volumes.unwrap().iter().any(|v| v.name == "api-schema"));
    assert!(pod.containers[0]
        .volume_mounts
        .as_ref()
        .unwrap()
        .iter()
        .any(|m| m.name == "api-schema"));
}

#[test]
fn service_selects_the_data_plane() {
    let svc = render::service("edge", "prod", "uid-123", &spec());
    let sp = svc.spec.unwrap();
    assert_eq!(sp.type_.as_deref(), Some("ClusterIP"));
    assert_eq!(sp.selector.unwrap()["app.kubernetes.io/instance"], "edge");
    let port = &sp.ports.unwrap()[0];
    assert_eq!(port.port, 8080);
}
