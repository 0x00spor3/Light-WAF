// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Threat intelligence for [Light WAF](https://github.com/0x00spor3/Light-WAF): cluster-wide IP
//! reputation, in two halves.
//!
//! - **Read**: [`ReputationModule`] is a detection module that runs at the connection phase, looks up
//!   the client IP in a `waf_state_redis::ReputationStore` and adds a severity to the request's
//!   cumulative anomaly score (`Malicious` / `Suspicious`; `Unknown` adds nothing). A store outage
//!   reads as `Unknown`: it neither blocks nor unblocks traffic.
//! - **Write**: [`start_reputation_feed`] polls [`ReputationFeed`] sources ([`FileFeed`],
//!   [`HttpListFeed`]) and populates the store, with a per-cycle single-writer lock and per-entry TTL
//!   so de-listed IPs age out.
//!
//! Reputation stays out of the core's API: the core datapath never reads or writes it.

use std::sync::Arc;

use waf_core::{Config, Decision, Phase, RequestContext, ScoreItem, Severity, WafModule};
use waf_state_redis::{Reputation, ReputationStore};

mod driver;
mod feed;
pub use driver::{start_reputation_feed, FeedConfig};
pub use feed::{FeedError, FileFeed, HttpListFeed, ReputationFeed};

/// How an IP-reputation verdict maps to an anomaly-score severity. No hardcoded points: the
/// module declares a [`Severity`] and the pipeline resolves `severity -> points` via
/// `[waf.severity_scores]` (so the operator tunes whether reputation alone blocks).
#[derive(Debug, Clone, Copy)]
pub struct ReputationConfig {
    pub enabled: bool,
    pub malicious: Severity,
    pub suspicious: Severity,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self { enabled: false, malicious: Severity::Critical, suspicious: Severity::Warning }
    }
}

/// A premium `WafModule` that scores a request by the reputation of its client IP.
pub struct ReputationModule {
    store: Arc<dyn ReputationStore>,
    cfg: ReputationConfig,
}

impl ReputationModule {
    /// Fully configured at construction: the core `Config` carries no reputation fields, so the
    /// enterprise wiring builds this from `[enterprise.reputation]` and `init()` is a no-op.
    pub fn new(store: Arc<dyn ReputationStore>, cfg: ReputationConfig) -> Self {
        Self { store, cfg }
    }
}

impl WafModule for ReputationModule {
    fn id(&self) -> &str {
        "reputation"
    }

    fn phase(&self) -> Phase {
        Phase::Connection
    }

    fn init(&mut self, _cfg: &Config) {}

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        if !self.cfg.enabled {
            return Decision::Allow;
        }
        // `Unknown` (no opinion — also the store's fail-safe when the feed is down) MUST NOT
        // contribute: the request keeps flowing through normal inspection.
        let (rule_id, severity) = match self.store.reputation(ctx.client_ip) {
            Reputation::Malicious => ("reputation-malicious", self.cfg.malicious),
            Reputation::Suspicious => ("reputation-suspicious", self.cfg.suspicious),
            Reputation::Unknown => return Decision::Allow,
        };
        // Distinct `rule_id` namespace so a future signature feed (§6) can dedup the same IP
        // and not double-count it into the cumulative score.
        Decision::Scores(vec![ScoreItem { rule_id: rule_id.to_string(), severity }])
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use waf_core::testkit::Request;
    use waf_core::{Config, RequestContext, WafMode};
    use waf_pipeline::{Pipeline, PipelineVerdict};

    use super::*;

    /// A stub store with a fixed verdict — lets the bite-test exercise the module on the real
    /// pipeline without Redis. (The real Redis fail-to-Unknown is proven in waf-state-redis.)
    struct FixedRep(Reputation);
    impl ReputationStore for FixedRep {
        fn reputation(&self, _ip: IpAddr) -> Reputation {
            self.0
        }
    }

    fn ctx_with_ip(ip: &str) -> RequestContext {
        let mut c = Request::new().build();
        c.client_ip = ip.parse().unwrap();
        c
    }

    fn enabled() -> ReputationConfig {
        ReputationConfig { enabled: true, malicious: Severity::Critical, suspicious: Severity::Warning }
    }

    fn blocking_config() -> Config {
        let mut c = Config::default();
        c.waf.mode = WafMode::Blocking;
        c.waf.block_threshold = 5; // default severity critical=6 ≥ 5 ⇒ a malicious IP blocks
        c
    }

    #[test]
    fn malicious_scores_with_configured_severity_clean_allows() {
        let m = ReputationModule::new(Arc::new(FixedRep(Reputation::Malicious)), enabled());
        let d = m.inspect(&ctx_with_ip("1.2.3.4"));
        assert!(
            matches!(d, Decision::Scores(ref v) if v.len() == 1 && v[0].severity == Severity::Critical),
            "malicious IP must score Critical, got {d:?}"
        );

        let unknown = ReputationModule::new(Arc::new(FixedRep(Reputation::Unknown)), enabled());
        assert_eq!(unknown.inspect(&ctx_with_ip("1.2.3.4")), Decision::Allow);
    }

    #[test]
    fn disabled_module_never_scores() {
        let cfg = ReputationConfig { enabled: false, ..enabled() };
        let m = ReputationModule::new(Arc::new(FixedRep(Reputation::Malicious)), cfg);
        assert_eq!(m.inspect(&ctx_with_ip("1.2.3.4")), Decision::Allow);
    }

    /// THE bite-test: a malicious IP raises the cumulative score → the pipeline blocks; the
    /// SAME request with NO reputation module passes → proves the module is on the datapath and
    /// causes the block (not green for some other reason).
    #[test]
    fn malicious_blocks_on_datapath_but_control_without_module_passes() {
        let config = blocking_config();

        let mut ctx = ctx_with_ip("9.9.9.9");
        let pipe = Pipeline::new(
            &config,
            vec![Box::new(ReputationModule::new(Arc::new(FixedRep(Reputation::Malicious)), enabled()))],
        );
        assert!(
            !matches!(pipe.run(&mut ctx), PipelineVerdict::Allow),
            "malicious IP must push score ≥ threshold → not Allow"
        );

        let mut ctx_ctrl = ctx_with_ip("9.9.9.9");
        let bare = Pipeline::new(&config, vec![]);
        assert!(
            matches!(bare.run(&mut ctx_ctrl), PipelineVerdict::Allow),
            "without the module the same IP must pass (control)"
        );
    }

    /// fail-to-Unknown / no-opinion: an Unknown verdict (what the Redis store returns when the
    /// feed is down) must NOT block — the request still flows through inspection.
    #[test]
    fn unknown_does_not_block_request_keeps_flowing() {
        let config = blocking_config();
        let mut ctx = ctx_with_ip("9.9.9.9");
        let pipe = Pipeline::new(
            &config,
            vec![Box::new(ReputationModule::new(Arc::new(FixedRep(Reputation::Unknown)), enabled()))],
        );
        assert!(matches!(pipe.run(&mut ctx), PipelineVerdict::Allow));
    }
}
