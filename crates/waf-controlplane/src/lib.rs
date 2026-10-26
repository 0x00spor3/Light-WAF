// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Light WAF — **control plane** (§7, enterprise BSL 1.1).
//!
//! A SEPARATE service (never on the WAF data port) that consumes the OPEN telemetry — the
//! structured JSON decision-log and the Prometheus `/metrics` — and persists it to Postgres for
//! long-term retention, dashboards and **blocked-request drill-down**. It is **zero-core on the
//! datapath** and deliberately does not link `waf-core`: it depends on the telemetry *contract*
//! (the decision-log schema + metrics ABI), not the datapath crate.
//!
//! v1 is read-only observability. Rule management (write path → SIGHUP push) is deferred behind
//! §8 governance (RBAC/audit); alerting is a fast-follow. This crate (Phase 1) provides the config,
//! the data model and the Postgres store; ingestion (Phase 2) and the axum API (Phase 3) build on it.

pub mod compliance;
pub mod config;
pub mod error;
pub mod evaluator;
pub mod gov_api;
pub mod ingest;
pub mod inventory;
pub mod model;
pub mod oidc;
pub mod prometheus;
pub mod rule_api;
pub mod scraper;
pub mod server;
pub mod siem;
pub mod siem_forward;
pub mod store;
pub mod stream;

pub use config::ControlPlaneConfig;
pub use error::{Error, Result};
pub use evaluator::{evaluate_once, run_evaluator};
pub use stream::{EventBus, StreamKind};
pub use gov_api::Governance;
pub use ingest::Ingestor;
pub use siem_forward::{SiemForwarder, SiemStatusHandle};
pub use model::{Alert, Contribution, DecisionEvent, MetricRollup};
pub use server::{app, AppState};
pub use store::Store;
