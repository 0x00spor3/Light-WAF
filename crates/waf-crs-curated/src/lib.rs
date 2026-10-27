// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Curated **premium** CRS/ModSecurity ruleset content (ARCHITECTURE_ENTERPRISE §6).
//!
//! The `seclang` parser/engine is OPEN (`waf_detection::crs`, B2); this crate ships only the
//! *content* (`BOUNDARY §2.4`). The rules are **premium-additive** — high-cura CVE / app-specific /
//! evasion signatures that ADD to the OPEN native detection modules and contribute to the SAME
//! cumulative anomaly score. They never re-implement the baseline (SQLi/XSS/PT/RCE/LFI-RFI stay
//! OPEN); removing the native modules and relying on this would be a "gutted core".
//!
//! ## Shape
//! - Content-only: the `.conf` files are embedded at compile time via `include_str!` — no runtime
//!   deps. The enterprise binary builds a `CrsModule` from [`curated_source`] and injects it via
//!   `Proxy::builder().add_module(..)`, gated by `[enterprise.crs_curated]`.
//! - Only v1-subset constructs (`@rx`/`@pm` on supported targets). The compat gate
//!   (`tests/gate.rs`) loads the content through the OPEN engine and asserts [`EXPECTED_LOADED`]
//!   rules load with **zero** skipped — so an edit that reaches outside the subset (which the
//!   engine would *skip*, not load) fails the build instead of silently shrinking coverage.
//! - Rule IDs live in the reserved **9000000+** range.

/// The curated `.conf` files, embedded at compile time in include order.
const FILES: &[&str] = &[
    include_str!("../rules/913-recon.conf"),
    include_str!("../rules/920-protocol.conf"),
    include_str!("../rules/930-lfi.conf"),
    include_str!("../rules/932-rce.conf"),
    include_str!("../rules/934-generic.conf"),
    include_str!("../rules/944-java.conf"),
    include_str!("../rules/cve.conf"),
];

/// How many rules the curated content is expected to load under the OPEN CRS engine's supported
/// subset. The compat gate asserts the engine's `loaded_count()` equals this **exactly**: any edit
/// that introduces an unsupported construct (which is *skipped*, not loaded) then fails the test
/// rather than silently reducing coverage — the lesson of the B2 setvar-scoring bug.
pub const EXPECTED_LOADED: usize = 28;

/// The full curated ruleset as one `seclang` source: the embedded `.conf` files concatenated in
/// include order, ready for `waf_detection::crs::CrsModule::from_source`.
pub fn curated_source() -> String {
    FILES.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_every_rule_file() {
        // Dep-free sanity that `include_str!` picked up all files (the gate proves they LOAD).
        // One representative id per file (913 / 920 / 930 / 932 / 934 / 944 / cve).
        let s = curated_source();
        for id in [
            "id:9000001", "id:9000020", "id:9000031", "id:9000040", "id:9000050", "id:9000003",
            "id:9100001",
        ] {
            assert!(s.contains(id), "curated_source missing {id}");
        }
    }
}
