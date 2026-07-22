// SPDX-License-Identifier: BUSL-1.1
//! Pure functions: a `WafProxySpec` (+ owner identity) → the owned Kubernetes objects
//! (ConfigMap, Deployment, Service). No cluster access here, so this is unit-testable in
//! isolation — the reconcile loop just server-side-applies whatever these return.

use crate::crd::WafProxySpec;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Capabilities, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort, EmptyDirVolumeSource,
    EnvVar, ExecAction, HTTPGetAction, Lifecycle, LifecycleHandler, PodSecurityContext, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, SeccompProfile, SecurityContext, Service,
    ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{
    LabelSelector, ObjectMeta, OwnerReference,
};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

pub const HTTP_PORT: i32 = 8080;
pub const METRICS_PORT: i32 = 9090;
pub const HEALTH_PORT: i32 = 8081;
const CONFIG_PATH: &str = "/etc/waf/config.toml";
const NON_ROOT_UID: i64 = 10001;

/// The detection modules the rendered config always names (mirrors config.compose.toml).
/// `spec.modules` overrides individual entries.
const DEFAULT_MODULES: &[&str] = &[
    "sqli",
    "xss",
    "path_traversal",
    "rce",
    "lfi_rfi",
    "ssrf",
    "ldap",
    "nosql",
    "mail",
    "ssti",
    "scanner",
    "ssi",
    "xxe",
    "header_injection",
    "request_smuggling",
];

fn config_name(name: &str) -> String {
    format!("{name}-config")
}

/// Standard labels for every owned object.
pub fn labels(instance: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".into(), "waf".into()),
        ("app.kubernetes.io/instance".into(), instance.into()),
        ("app.kubernetes.io/managed-by".into(), "waf-operator".into()),
        ("app.kubernetes.io/component".into(), "data-plane".into()),
        ("waf.io/wafproxy".into(), instance.into()),
    ])
}

/// Selector labels — the stable subset used for matchLabels / Service selector.
pub fn selector_labels(instance: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("app.kubernetes.io/name".into(), "waf".into()),
        ("app.kubernetes.io/instance".into(), instance.into()),
    ])
}

fn owner_ref(name: &str, uid: &str) -> OwnerReference {
    OwnerReference {
        api_version: "waf.io/v1alpha1".into(),
        kind: "WafProxy".into(),
        name: name.into(),
        uid: uid.into(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

fn meta(name: String, namespace: &str, instance: &str, uid: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: Some(namespace.into()),
        labels: Some(labels(instance)),
        owner_references: Some(vec![owner_ref(instance, uid)]),
        ..Default::default()
    }
}

/// Render `config.toml` for the data-plane from the spec.
pub fn config_toml(spec: &WafProxySpec, owner_ns: &str) -> String {
    let backend = spec
        .backend_url(owner_ns)
        .unwrap_or_else(|| "http://127.0.0.1:0".into());
    let mut s = String::new();
    s.push_str("[proxy]\n");
    s.push_str("listen = \"0.0.0.0:8080\"\n");
    s.push_str(&format!("backend = {:?}\n\n", backend));

    s.push_str("[resilience]\n");
    s.push_str("on_upstream_error   = \"fail_closed\"\n");
    s.push_str("on_internal_error   = \"fail_open\"\n");
    s.push_str("on_config_error     = \"fail_open\"\n");
    s.push_str("on_parser_limit     = \"fail_closed\"\n");
    s.push_str("upstream_timeout_ms = 30000\n\n");

    s.push_str("[waf]\n");
    s.push_str(&format!("mode = {:?}\n", spec.mode.as_config()));
    s.push_str(&format!("block_threshold = {}\n", spec.block_threshold));
    s.push_str(&format!("paranoia_level = {}\n\n", spec.paranoia_level));

    s.push_str("[waf.severity_scores]\n");
    s.push_str("critical = 6\nerror    = 4\nwarning  = 3\nnotice   = 2\n\n");

    s.push_str("[limits]\n");
    s.push_str("max_body_size    = 1048576\n");
    s.push_str("max_header_size  = 8192\n");
    s.push_str("max_headers      = 100\n");
    s.push_str("max_params       = 100\n");
    s.push_str("max_cookies      = 50\n");
    s.push_str("max_json_depth   = 20\n");

    for m in DEFAULT_MODULES {
        let enabled = spec.modules.get(*m).copied().unwrap_or(true);
        s.push_str(&format!("\n[modules.{m}]\nenabled = {enabled}\n"));
    }
    // Any spec.modules key that is not a known default (forward-compat / extra modules).
    let mut extra: Vec<(&String, &bool)> = spec
        .modules
        .iter()
        .filter(|(k, _)| !DEFAULT_MODULES.contains(&k.as_str()))
        .collect();
    extra.sort_by_key(|(k, _)| (*k).clone());
    for (k, v) in extra {
        s.push_str(&format!("\n[modules.{k}]\nenabled = {v}\n"));
    }

    if spec.crs_curated {
        s.push_str("\n[enterprise.crs_curated]\nenabled = true\n");
    }

    s.push_str("\n[metrics]\nenabled = true\nlisten  = \"0.0.0.0:9090\"\n");

    if spec.api_schema_spec_ref.is_some() {
        s.push_str("\n[enterprise.api_schema]\nenabled   = true\n");
        s.push_str("spec_path = \"/etc/waf/openapi.json\"\n");
        s.push_str("violation_severity = \"critical\"\n");
    }
    s
}

fn config_hash(config: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    config.hash(&mut h);
    format!("{:016x}", h.finish())
}

pub fn configmap(name: &str, namespace: &str, uid: &str, spec: &WafProxySpec) -> ConfigMap {
    ConfigMap {
        metadata: meta(config_name(name), namespace, name, uid),
        data: Some(BTreeMap::from([(
            "config.toml".into(),
            config_toml(spec, namespace),
        )])),
        ..Default::default()
    }
}

pub fn service(name: &str, namespace: &str, uid: &str, _spec: &WafProxySpec) -> Service {
    Service {
        metadata: meta(name.to_string(), namespace, name, uid),
        spec: Some(ServiceSpec {
            type_: Some("ClusterIP".into()),
            selector: Some(selector_labels(name)),
            ports: Some(vec![ServicePort {
                name: Some("http".into()),
                port: HTTP_PORT,
                target_port: Some(IntOrString::String("http".into())),
                protocol: Some("TCP".into()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn quantity_map(pairs: &[(&str, &str)]) -> BTreeMap<String, Quantity> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), Quantity((*v).to_string())))
        .collect()
}

pub fn deployment(name: &str, namespace: &str, uid: &str, spec: &WafProxySpec) -> Deployment {
    let cfg = config_toml(spec, namespace);
    let mut pod_annotations = BTreeMap::new();
    pod_annotations.insert("waf.io/config-hash".to_string(), config_hash(&cfg));

    let mut volume_mounts = vec![
        VolumeMount {
            name: "config".into(),
            mount_path: CONFIG_PATH.into(),
            sub_path: Some("config.toml".into()),
            read_only: Some(true),
            ..Default::default()
        },
        VolumeMount {
            name: "tmp".into(),
            mount_path: "/tmp".into(),
            ..Default::default()
        },
    ];
    let mut volumes = vec![
        Volume {
            name: "config".into(),
            config_map: Some(ConfigMapVolumeSource {
                name: config_name(name),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "tmp".into(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Default::default()
        },
    ];
    if let Some(cm) = &spec.api_schema_spec_ref {
        volume_mounts.push(VolumeMount {
            name: "api-schema".into(),
            mount_path: "/etc/waf/openapi.json".into(),
            sub_path: Some("openapi.json".into()),
            read_only: Some(true),
            ..Default::default()
        });
        volumes.push(Volume {
            name: "api-schema".into(),
            config_map: Some(ConfigMapVolumeSource {
                name: cm.clone(),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    // Health probes hit the enterprise binary's health endpoint (K0): /healthz (liveness)
    // and /readyz (readiness, → 503 during the graceful drain).
    let http_probe = |path: &str| Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.into()),
            port: IntOrString::String("health".into()),
            ..Default::default()
        }),
        period_seconds: Some(10),
        timeout_seconds: Some(3),
        failure_threshold: Some(3),
        ..Default::default()
    };

    let container = Container {
        name: "waf".into(),
        image: Some(spec.image.clone()),
        args: Some(vec!["--config".into(), CONFIG_PATH.into()]),
        env: Some(vec![EnvVar {
            name: "WAF_HEALTH_LISTEN".into(),
            value: Some(format!("0.0.0.0:{HEALTH_PORT}")),
            ..Default::default()
        }]),
        ports: Some(vec![
            ContainerPort {
                name: Some("http".into()),
                container_port: HTTP_PORT,
                ..Default::default()
            },
            ContainerPort {
                name: Some("metrics".into()),
                container_port: METRICS_PORT,
                ..Default::default()
            },
            ContainerPort {
                name: Some("health".into()),
                container_port: HEALTH_PORT,
                ..Default::default()
            },
        ]),
        lifecycle: Some(Lifecycle {
            pre_stop: Some(LifecycleHandler {
                exec: Some(ExecAction {
                    command: Some(vec!["sleep".into(), "5".into()]),
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        liveness_probe: Some(http_probe("/healthz")),
        readiness_probe: Some(http_probe("/readyz")),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            read_only_root_filesystem: Some(true),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".into()]),
                add: None,
            }),
            ..Default::default()
        }),
        resources: Some(ResourceRequirements {
            requests: Some(quantity_map(&[("cpu", "100m"), ("memory", "128Mi")])),
            limits: Some(quantity_map(&[("cpu", "1"), ("memory", "512Mi")])),
            ..Default::default()
        }),
        volume_mounts: Some(volume_mounts),
        ..Default::default()
    };

    let pod_spec = PodSpec {
        security_context: Some(PodSecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(NON_ROOT_UID),
            run_as_group: Some(NON_ROOT_UID),
            fs_group: Some(NON_ROOT_UID),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                localhost_profile: None,
            }),
            ..Default::default()
        }),
        termination_grace_period_seconds: Some(30),
        containers: vec![container],
        volumes: Some(volumes),
        ..Default::default()
    };

    Deployment {
        metadata: meta(name.to_string(), namespace, name, uid),
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(selector_labels(name)),
                match_expressions: None,
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(selector_labels(name)),
                    annotations: Some(pod_annotations),
                    ..Default::default()
                }),
                spec: Some(pod_spec),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}
