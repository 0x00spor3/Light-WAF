// SPDX-License-Identifier: Apache-2.0
//! A minimal REAL Proxy-Wasm filter (built with the `proxy-wasm` Rust SDK) used as the
//! ABI-fidelity oracle for the env-gated smoke. It blocks (403) any request carrying an
//! `x-block` header and otherwise continues. Single-purpose on purpose — it is an oracle,
//! not an example of a useful filter.

use proxy_wasm::traits::*;
use proxy_wasm::types::*;

proxy_wasm::main! {{
    proxy_wasm::set_log_level(LogLevel::Warn);
    proxy_wasm::set_root_context(|_| -> Box<dyn RootContext> { Box::new(BlockRoot) });
}}

struct BlockRoot;

impl Context for BlockRoot {}

impl RootContext for BlockRoot {
    fn get_type(&self) -> Option<ContextType> {
        Some(ContextType::HttpContext)
    }
    fn create_http_context(&self, _context_id: u32) -> Option<Box<dyn HttpContext>> {
        Some(Box::new(BlockHttp))
    }
}

struct BlockHttp;

impl Context for BlockHttp {}

impl HttpContext for BlockHttp {
    fn on_http_request_headers(&mut self, _num_headers: usize, _end_of_stream: bool) -> Action {
        if self.get_http_request_header("x-block").is_some() {
            self.send_http_response(403, vec![], Some(b"blocked by wasm"));
            return Action::Pause;
        }
        Action::Continue
    }
}
