// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Boot-time classification of a guest's declared imports (policy D3=A: explicit coverage,
//! never a silent partial). A missing import would make instantiation fail, so the loader
//! STUBS every import it does not implement; this report says which were stubbed and — the
//! load-bearing distinction (paletto #4) — whether any stub *alters detection semantics*.
//!
//! - **implemented**: the host function does the real thing.
//! - **cosmetic stub**: absence does not change what the plugin detects (metrics, ticks…).
//! - **semantic stub**: the plugin's detection logic *may* depend on it (`http_call`,
//!   `shared_data`, header mutation…); stubbing it makes a plugin that CALLS it behave
//!   differently from how it was written.
//!
//! Crucial nuance learned from a real SDK filter (paletto #4): a Proxy-Wasm SDK *declares*
//! every host import regardless of use, so a *declared* semantic import is NOT evidence the
//! plugin depends on it. This boot report is therefore **informational** (what the plugin
//! links + which links are semantic-capable); the accurate "degraded" signal is emitted at
//! RUNTIME, the first time the plugin actually invokes a stubbed semantic host call
//! (`runtime::register_stubs` → `HostState::semantic_stub_hit`). We never reject at load.

use wasmi::Module;

/// Host functions the runtime implements for real.
pub const IMPLEMENTED: &[&str] = &[
    "proxy_log",
    "proxy_get_buffer_bytes",
    "proxy_get_header_map_pairs",
    "proxy_get_header_map_value",
    "proxy_get_property",
    "proxy_send_local_response",
    "proxy_get_current_time_nanoseconds",
    "proxy_set_tick_period_milliseconds",
];

/// Stubbing these changes detection semantics → a plugin that uses one is `degraded`.
pub const SEMANTIC: &[&str] = &[
    "proxy_http_call",
    "proxy_dispatch_http_call",
    "proxy_get_shared_data",
    "proxy_set_shared_data",
    "proxy_register_shared_queue",
    "proxy_resolve_shared_queue",
    "proxy_enqueue_shared_queue",
    "proxy_dequeue_shared_queue",
    "proxy_set_header_map_pairs",
    "proxy_replace_header_map_value",
    "proxy_add_header_map_value",
    "proxy_remove_header_map_value",
    "proxy_set_property",
    "proxy_set_buffer_bytes",
    "proxy_call_foreign_function",
    "proxy_grpc_call",
    "proxy_grpc_stream",
    "proxy_grpc_send",
    "proxy_grpc_cancel",
    "proxy_grpc_close",
];

/// How a single stubbed import was classified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubClass {
    Cosmetic,
    Semantic,
}

/// Outcome of classifying a module's imports.
#[derive(Debug, Clone, Default)]
pub struct ImportReport {
    /// `(name, class)` for every import the loader had to stub.
    pub stubbed: Vec<(String, StubClass)>,
    /// Implemented host functions the guest actually imports.
    pub implemented_used: Vec<String>,
}

impl ImportReport {
    /// Count of semantic-capable stubbed imports the plugin LINKS (not necessarily calls).
    pub fn semantic_linked(&self) -> usize {
        self.stubbed.iter().filter(|(_, c)| *c == StubClass::Semantic).count()
    }

    /// Names of the semantic-capable stubs the plugin links.
    pub fn semantic_stubs(&self) -> Vec<&str> {
        self.stubbed
            .iter()
            .filter(|(_, c)| *c == StubClass::Semantic)
            .map(|(n, _)| n.as_str())
            .collect()
    }

    /// One-line boot summary — informational. Whether the plugin is actually degraded is a
    /// runtime fact (see the module docs), not derivable from declared imports.
    pub fn summary(&self) -> String {
        let semantic = self.semantic_linked();
        let cosmetic = self.stubbed.len() - semantic;
        format!(
            "WASM import: {} implemented, {} stubbed ({} semantic-capable, {} cosmetic); \
             semantic host calls return Unimplemented IF the plugin invokes them at runtime",
            self.implemented_used.len(),
            self.stubbed.len(),
            semantic,
            cosmetic,
        )
    }
}

/// Classify the func imports a module declares (namespace `env`).
pub fn classify(module: &Module) -> ImportReport {
    let mut report = ImportReport::default();
    for import in module.imports() {
        // Only function imports matter here; memory/global/table imports are handled by
        // instantiation directly.
        if import.ty().func().is_none() {
            continue;
        }
        let name = import.name();
        if IMPLEMENTED.contains(&name) {
            report.implemented_used.push(name.to_string());
        } else if SEMANTIC.contains(&name) {
            report.stubbed.push((name.to_string(), StubClass::Semantic));
        } else {
            report.stubbed.push((name.to_string(), StubClass::Cosmetic));
        }
    }
    report
}
