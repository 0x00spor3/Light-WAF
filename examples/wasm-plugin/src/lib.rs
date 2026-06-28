// SPDX-License-Identifier: Apache-2.0
//! Example WASM plugin for the WAF's Proxy-Wasm runtime (B3).
//!
//! A small but realistic **custom denylist filter**: it blocks (HTTP 403) any request whose
//! path, `User-Agent`, or body contains one of a configurable list of substrings, plus an
//! explicit `X-Block` kill-switch header. This is exactly the kind of app-specific rule you
//! would add as a plugin to extend the WAF *without forking the core*.
//!
//! It demonstrates every host capability the v1 runtime implements:
//!   - reading the plugin configuration (`proxy_on_configure`),
//!   - reading request headers (incl. the injected `:path` pseudo-header),
//!   - reading the request body buffer,
//!   - sending a local response (the WAF captures it → `Block`/`Reject`, never the wire),
//!   - logging.
//!
//! Build it to `wasm32-unknown-unknown` and point a `[[modules.wasm.plugins]]` entry at the
//! resulting `.wasm` — see README.md.

use std::sync::Arc;

use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Info);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> {
        Box::new(DenylistRoot { denylist: Arc::new(Vec::new()) })
    });
}}

/// Root context: parses the plugin configuration once, then hands the compiled denylist to
/// each per-request HTTP context.
struct DenylistRoot {
    denylist: Arc<Vec<String>>,
}

impl Context for DenylistRoot {}

impl RootContext for DenylistRoot {
    /// `config = "..."` from the TOML arrives here. We treat it as a comma-separated list of
    /// case-insensitive substrings to block (e.g. `config = "/admin,. ./,sqlmap,union select"`).
    fn on_configure(&mut self, _config_size: usize) -> bool {
        if let Some(bytes) = self.get_plugin_configuration() {
            let raw = String::from_utf8_lossy(&bytes);
            let list: Vec<String> = raw
                .split(',')
                .map(|t| t.trim().to_lowercase())
                .filter(|t| !t.is_empty())
                .collect();
            proxy_wasm::hostcalls::log(
                LogLevel::Info,
                &format!("waf-wasm-example: loaded {} denylist term(s)", list.len()),
            )
            .ok();
            self.denylist = Arc::new(list);
        }
        true
    }

    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }

    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(DenylistHttp { denylist: Arc::clone(&self.denylist) }))
    }
}

/// Per-request context.
struct DenylistHttp {
    denylist: Arc<Vec<String>>,
}

impl DenylistHttp {
    /// Return the first denylist term contained (case-insensitively) in `haystack`.
    fn first_hit(&self, haystack: &str) -> Option<String> {
        let hay = haystack.to_lowercase();
        self.denylist.iter().find(|term| hay.contains(term.as_str())).cloned()
    }

    /// Emit the block: log it and send a 403. The WAF *captures* this local response and
    /// turns it into a `Block` decision — the plugin never writes the wire itself.
    fn block(&self, surface: &str, term: &str) -> Action {
        proxy_wasm::hostcalls::log(
            LogLevel::Warn,
            &format!("waf-wasm-example: BLOCK ({surface} matched denylist term '{term}')"),
        )
        .ok();
        self.send_http_response(
            403,
            vec![("x-blocked-by", "waf-wasm-example")],
            Some(b"blocked by the WASM denylist plugin\n"),
        );
        Action::Pause
    }
}

impl Context for DenylistHttp {}

impl HttpContext for DenylistHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        // Explicit kill switch.
        if self.get_http_request_header("x-block").is_some() {
            return self.block("header", "x-block");
        }
        // The runtime injects the `:path` pseudo-header (path + query). You could also read
        // it as `self.get_property(vec!["request", "path"])`.
        if let Some(path) = self.get_http_request_header(":path") {
            if let Some(term) = self.first_hit(&path) {
                return self.block("path", &term);
            }
        }
        if let Some(ua) = self.get_http_request_header("user-agent") {
            if let Some(term) = self.first_hit(&ua) {
                return self.block("user-agent", &term);
            }
        }
        Action::Continue
    }

    fn on_http_request_body(&mut self, body_size: usize, end_of_stream: bool) -> Action {
        // The WAF buffers the whole body, so this fires once with end_of_stream = true.
        if !end_of_stream || body_size == 0 {
            return Action::Continue;
        }
        if let Some(bytes) = self.get_http_request_body(0, body_size) {
            let body = String::from_utf8_lossy(&bytes);
            if let Some(term) = self.first_hit(&body) {
                return self.block("body", &term);
            }
        }
        Action::Continue
    }
}
