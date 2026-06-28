// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! `waf-wasm` — a Proxy-Wasm plugin **runtime** that exposes a loaded `.wasm` filter as a
//! [`waf_core::WafModule`] (BOUNDARY §1.7, B3). The runtime is OPEN; marketplace/signing is
//! enterprise (§2.4).
//!
//! ## Design (see ARCHITECTURE §9 and the B3 plan)
//! - **Engine**: `wasmi` (pure-Rust interpreter; no JIT/C). Pinned to the version the B3-0
//!   probe validated for reentrant `malloc` + fuel + memory-cap traps.
//! - **Model**: the WAF is buffer-then-inspect on the request, so per request the host runs
//!   the Proxy-Wasm request-path callbacks in one shot (`end_of_stream = true`) and maps a
//!   captured `proxy_send_local_response` to a [`waf_core::Decision`]. The plugin never
//!   writes the response itself — the pipeline decides (detection-only safe).
//! - **DoS posture**: fuel reset per request (latency ceiling, not just kill-switch), a
//!   memory cap, no network/filesystem host calls. Any trap fails closed (`Reject{500}`).
//! - **Subset**: a declared set of host functions; everything else returns
//!   [`abi::Status::Unimplemented`] and is reported at boot (never a silent partial).
//!
//! This crate isolates the `wasmi` dependency from the rest of the workspace: it depends
//! only on `waf-core` (no cycle), and `waf-proxy` depends on it.

pub mod abi;
pub mod host;
pub mod marshal;
pub mod memory;
pub mod report;
pub mod runtime;

pub use report::ImportReport;
pub use runtime::{WasmError, WasmModule, WasmOptions};
