// SPDX-License-Identifier: Apache-2.0
//! The `WafProxy` custom resource: a declarative request to protect a target Service
//! with a WAF data-plane Deployment. The operator reconciles it into a ConfigMap +
//! Deployment + Service (see `render`). No routing lives in the core — one CR ⇒ one WAF
//! in front of one upstream (the WAF-per-workload model).

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "waf.io",
    version = "v1alpha1",
    kind = "WafProxy",
    namespaced,
    status = "WafProxyStatus",
    shortname = "wafp",
    printcolumn = r#"{"name":"Mode","type":"string","jsonPath":".spec.mode"}"#,
    printcolumn = r#"{"name":"Replicas","type":"integer","jsonPath":".spec.replicas"}"#,
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct WafProxySpec {
    /// Container image for the WAF data-plane (e.g. ghcr.io/0x00spor3/waf-enterprise:1.0.2).
    pub image: String,

    /// The upstream this WAF protects — a Service reference or a raw URL.
    pub backend: Backend,

    /// Enforcement mode.
    #[serde(default)]
    pub mode: Mode,

    /// CRS paranoia level (1–4).
    #[serde(default = "default_paranoia")]
    pub paranoia_level: u8,

    /// Score at/above which a request is blocked.
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,

    /// Desired data-plane replicas.
    #[serde(default = "default_replicas")]
    pub replicas: i32,

    /// Detection modules to force on/off (name → enabled). Unlisted modules keep the
    /// image defaults.
    #[serde(default)]
    pub modules: BTreeMap<String, bool>,

    /// Enable the premium curated-CRS module.
    #[serde(default = "default_true")]
    pub crs_curated: bool,

    /// Name of a ConfigMap (same namespace) holding `openapi.json` for positive-security
    /// enforcement. When set, it is mounted and `[enterprise.api_schema]` is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_schema_spec_ref: Option<String>,
}

/// Upstream target: prefer a Service reference; a raw URL overrides it when both are set.
#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Backend {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceRef {
    pub name: String,
    #[serde(default = "default_backend_port")]
    pub port: u16,
    /// Defaults to the WafProxy's namespace.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Blocking,
    Detection,
}

impl Mode {
    /// The `[waf].mode` value the WAF accepts. The CR spells the observe-only mode
    /// `detection`; the WAF config calls it `detection-only`.
    pub fn as_config(&self) -> &'static str {
        match self {
            Mode::Blocking => "blocking",
            Mode::Detection => "detection-only",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct WafProxyStatus {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl WafProxySpec {
    /// Resolve the upstream URL the WAF config's `[proxy].backend` should carry.
    /// `owner_ns` is the WafProxy's namespace (used when a ServiceRef omits one).
    pub fn backend_url(&self, owner_ns: &str) -> Option<String> {
        if let Some(url) = &self.backend.url {
            return Some(url.clone());
        }
        self.backend.service.as_ref().map(|svc| {
            let ns = svc.namespace.as_deref().unwrap_or(owner_ns);
            format!("http://{}.{}.svc.cluster.local:{}", svc.name, ns, svc.port)
        })
    }
}

fn default_paranoia() -> u8 {
    3
}
fn default_block_threshold() -> u32 {
    3
}
fn default_replicas() -> i32 {
    2
}
fn default_true() -> bool {
    true
}
fn default_backend_port() -> u16 {
    80
}
