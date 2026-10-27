// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Curated OWASP CRS / ModSecurity rule content for [Light WAF](https://github.com/0x00spor3/Light-WAF).
//!
//! The core ships the `SecRule` parser and engine (`waf_detection::crs`); this crate ships only
//! **content**: high-confidence CVE, application and evasion signatures that **add** to the core's
//! native detection modules and contribute to the same cumulative anomaly score. It never
//! re-implements the baseline (SQLi/XSS/traversal/RCE/LFI-RFI stay in the core).
//!
//! - The `.conf` files are embedded at compile time. Build a module from [`curated_source`] with
//!   `waf_detection::crs::CrsModule::from_source` and inject it with
//!   `Proxy::builder(&cfg).add_module(..)` (or a `module_factory`).
//! - Only constructs supported by the core engine are used. A test loads the content through that
//!   engine and asserts that exactly [`EXPECTED_LOADED`] rules load with **zero** skipped, so a rule the
//!   engine could not run fails the build instead of silently shrinking coverage.
//! - Rule ids live in the reserved `9000000+` range.

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
