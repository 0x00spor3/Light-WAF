// SPDX-License-Identifier: Apache-2.0
//! Kubernetes operator for Light WAF (K4). Reconciles a `WafProxy` custom resource into a
//! WAF data-plane Deployment (+ ConfigMap + Service) in front of a target Service — the
//! declarative, native UX for the WAF-per-workload model. No routing in the core: one CR
//! ⇒ one WAF in front of one upstream. Control-plane only; zero datapath.

pub mod controller;
pub mod crd;
pub mod render;

pub use crd::{WafProxy, WafProxySpec, WafProxyStatus};
