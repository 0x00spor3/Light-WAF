// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! The runtime: compile a Proxy-Wasm guest, drive its request-path lifecycle per request,
//! and expose it as a [`WafModule`]. See ARCHITECTURE §9 and the B3 plan.
//!
//! - **Linker**: the implemented subset ([`crate::host::add_to_linker`]) plus a dynamic
//!   stub for every other import the guest declares, so instantiation never fails on a
//!   missing import while the coverage gap stays explicit ([`crate::report`]).
//! - **Pool**: pre-instantiated `(Store, Instance)` pairs behind a `Mutex` + `Condvar`.
//!   Checkout blocks up to `checkout_timeout`; exhaustion fails closed (the
//!   `on_internal_error` binary). A `Store` is never shared across threads.
//! - **DoS**: fuel reset per request, a memory cap; any trap fails closed (`Reject{500}`).

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use tracing::warn;
use waf_core::{Decision, Phase, RequestContext, WafModule};
use wasmi::{
    Config, Engine, Instance, Linker, Module, Store, StoreLimitsBuilder, Val, ValType,
};

use crate::abi::Status;
use crate::host::{add_to_linker, HostState, LocalResponse};
use crate::marshal::{header_value, RequestView};
use crate::report::{self, ImportReport};

const ROOT_CTX: i32 = 1;
const HTTP_CTX: i32 = 2;

/// Tunables for a plugin instance set.
#[derive(Debug, Clone)]
pub struct WasmOptions {
    pub pool_size: usize,
    pub fuel_per_request: u64,
    pub max_memory_bytes: usize,
    pub checkout_timeout: Duration,
}

impl Default for WasmOptions {
    fn default() -> Self {
        WasmOptions {
            pool_size: 4,
            fuel_per_request: 10_000_000,
            max_memory_bytes: 16 * 1024 * 1024,
            checkout_timeout: Duration::from_millis(100),
        }
    }
}

/// Errors building a plugin (load-time, before serving).
#[derive(Debug)]
pub enum WasmError {
    Compile(String),
    Instantiate(String),
    MissingMemory,
    MissingAllocator,
    VmStart(String),
}

impl std::fmt::Display for WasmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WasmError::Compile(e) => write!(f, "wasm compile failed: {e}"),
            WasmError::Instantiate(e) => write!(f, "wasm instantiate failed: {e}"),
            WasmError::MissingMemory => write!(f, "guest exports no linear memory"),
            WasmError::MissingAllocator => {
                write!(f, "guest exports no allocator (proxy_on_memory_allocate/malloc)")
            }
            WasmError::VmStart(e) => write!(f, "guest vm/configure start failed: {e}"),
        }
    }
}

impl std::error::Error for WasmError {}

struct Pooled {
    store: Store<HostState>,
    instance: Instance,
}

struct Runtime {
    name: String,
    fuel: u64,
    checkout_timeout: Duration,
    pool: Mutex<Vec<Pooled>>,
    available: Condvar,
}

/// A Proxy-Wasm plugin exposed as a [`WafModule`]. Build with [`WasmModule::from_bytes`].
pub struct WasmModule {
    id: String,
    runtime: Arc<Runtime>,
}

impl WasmModule {
    /// Compile `wasm`, build a pool of `opts.pool_size` instances, run each guest's VM
    /// start/configure with `config`, and return the module plus its import report.
    pub fn from_bytes(
        name: &str,
        wasm: &[u8],
        config: &[u8],
        opts: &WasmOptions,
    ) -> Result<(WasmModule, ImportReport), WasmError> {
        let mut engine_cfg = Config::default();
        engine_cfg.consume_fuel(true);
        let engine = Engine::new(&engine_cfg);
        let module =
            Module::new(&engine, wasm).map_err(|e| WasmError::Compile(e.to_string()))?;

        let report = report::classify(&module);

        // One linker (store-independent) reused for every pool instance.
        let mut linker: Linker<HostState> = Linker::new(&engine);
        add_to_linker(&mut linker).map_err(|e| WasmError::Instantiate(e.to_string()))?;
        register_stubs(&mut linker, &module)
            .map_err(|e| WasmError::Instantiate(e.to_string()))?;

        let mut pool = Vec::with_capacity(opts.pool_size.max(1));
        for _ in 0..opts.pool_size.max(1) {
            pool.push(build_instance(&engine, &linker, &module, config, opts)?);
        }

        let runtime = Arc::new(Runtime {
            name: name.to_string(),
            fuel: opts.fuel_per_request,
            checkout_timeout: opts.checkout_timeout,
            pool: Mutex::new(pool),
            available: Condvar::new(),
        });
        Ok((WasmModule { id: format!("wasm:{name}"), runtime }, report))
    }

    fn checkout(&self) -> Option<Pooled> {
        let rt = &self.runtime;
        let mut guard = rt.pool.lock().unwrap();
        let deadline = Instant::now() + rt.checkout_timeout;
        loop {
            if let Some(p) = guard.pop() {
                return Some(p);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (g, _to) = rt.available.wait_timeout(guard, deadline - now).unwrap();
            guard = g;
        }
    }

    fn checkin(&self, p: Pooled) {
        self.runtime.pool.lock().unwrap().push(p);
        self.runtime.available.notify_one();
    }
}

impl WafModule for WasmModule {
    fn id(&self) -> &str {
        &self.id
    }

    fn phase(&self) -> Phase {
        Phase::Body
    }

    fn init(&mut self, _cfg: &waf_core::Config) {
        // Compilation + VM start happen in `from_bytes`, before serving.
    }

    fn inspect(&self, ctx: &RequestContext) -> Decision {
        let view = view_from(ctx);
        let mut pooled = match self.checkout() {
            Some(p) => p,
            // Pool exhausted within the timeout: fail closed (on_internal_error binary).
            None => {
                warn!(plugin = %self.runtime.name, "wasm pool exhausted -> fail closed");
                return reject_500(&self.runtime.name);
            }
        };
        let decision =
            run_request(&mut pooled.store, &pooled.instance, view, &ctx.request_id, self.runtime.fuel, &self.runtime.name);
        self.checkin(pooled);
        decision
    }

    /// CRS-like: the host cannot prove a WASM plugin inert, so it runs on every request.
    fn structural(&self) -> bool {
        true
    }
}

/// Instantiate one pool member and run its VM start/configure.
fn build_instance(
    engine: &Engine,
    linker: &Linker<HostState>,
    module: &Module,
    config: &[u8],
    opts: &WasmOptions,
) -> Result<Pooled, WasmError> {
    let limiter = StoreLimitsBuilder::new().memory_size(opts.max_memory_bytes).build();
    let mut store = Store::new(engine, HostState::new(limiter));
    store.limiter(|s| &mut s.limiter);
    store.data_mut().config = config.to_vec();
    // VM start can run guest code -> bound it with one request's fuel budget.
    store.set_fuel(opts.fuel_per_request).ok();

    let instance = linker
        .instantiate_and_start(&mut store, module)
        .map_err(|e| WasmError::Instantiate(e.to_string()))?;

    // Cache memory + allocator for the host functions.
    let mem = instance.get_memory(&store, "memory").ok_or(WasmError::MissingMemory)?;
    let alloc = crate::abi::ALLOC_EXPORTS
        .iter()
        .find_map(|n| instance.get_typed_func::<i32, i32>(&store, n).ok())
        .ok_or(WasmError::MissingAllocator)?;
    store.data_mut().mem = Some(mem);
    store.data_mut().alloc = Some(alloc);

    // Proxy-Wasm SDKs register their root-context factory in a WASI-reactor initializer
    // (`_initialize`, or `_start` from the older `main!` macro). wasmi does NOT call it
    // automatically (it only runs a wasm `start` section, which these modules lack), so the
    // SDK's context map would be empty and `proxy_on_context_create` would panic. Call it
    // once here, before the lifecycle.
    for init in ["_initialize", "_start"] {
        if instance.get_func(&store, init).is_some() {
            call_opt(&mut store, &instance, init, &[])
                .map_err(|e| WasmError::VmStart(format!("{init}: {e}")))?;
            break;
        }
    }

    // Root context + vm start + configure.
    call_opt(&mut store, &instance, "proxy_on_context_create", &[ROOT_CTX, 0])
        .map_err(|e| WasmError::VmStart(e.to_string()))?;
    if let Some(r) = call_opt(&mut store, &instance, "proxy_on_vm_start", &[ROOT_CTX, 0])
        .map_err(|e| WasmError::VmStart(e.to_string()))?
    {
        if r == 0 {
            return Err(WasmError::VmStart("proxy_on_vm_start returned failure".into()));
        }
    }
    if let Some(r) =
        call_opt(&mut store, &instance, "proxy_on_configure", &[ROOT_CTX, config.len() as i32])
            .map_err(|e| WasmError::VmStart(e.to_string()))?
    {
        if r == 0 {
            return Err(WasmError::VmStart("proxy_on_configure returned failure".into()));
        }
    }

    Ok(Pooled { store, instance })
}

/// Register a dynamic stub for every func import the runtime does not implement. The stub
/// returns `Status::Unimplemented` for single-`i32` results (the honest answer the SDK maps
/// to an error) and zeros otherwise.
fn register_stubs(linker: &mut Linker<HostState>, module: &Module) -> Result<(), wasmi::Error> {
    for import in module.imports() {
        let Some(func_ty) = import.ty().func().cloned() else { continue };
        let name = import.name();
        if report::IMPLEMENTED.contains(&name) {
            continue;
        }
        let name = name.to_string();
        let res_types: Vec<ValType> = func_ty.results().to_vec();
        let unimpl = res_types.len() == 1 && res_types[0] == ValType::I32;
        // Whether *invoking* this stub changes detection semantics (paletto #4). A real
        // SDK *declares* every host import, so the accurate "degraded" signal is a runtime
        // call, not a declared import — warn once, when actually hit.
        let semantic = report::SEMANTIC.contains(&name.as_str());
        let call_name = name.clone();
        linker.func_new(
            "env",
            &name,
            func_ty,
            move |mut caller, _params: &[Val], results: &mut [Val]| {
                if semantic && caller.data().semantic_stub_hit.is_none() {
                    caller.data_mut().semantic_stub_hit = Some(call_name.clone());
                    warn!(
                        host_call = %call_name,
                        "wasm plugin invoked a stubbed semantic host call -> Unimplemented (DEGRADED at runtime)"
                    );
                }
                for (slot, ty) in results.iter_mut().zip(res_types.iter()) {
                    *slot = zero_val(*ty);
                }
                if unimpl {
                    if let Some(s) = results.get_mut(0) {
                        *s = Val::I32(Status::Unimplemented.code());
                    }
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

fn zero_val(t: ValType) -> Val {
    match t {
        ValType::I32 => Val::I32(0),
        ValType::I64 => Val::I64(0),
        ValType::F32 => Val::F32(0.0f32.into()),
        ValType::F64 => Val::F64(0.0f64.into()),
        _ => Val::I32(0),
    }
}

/// Build the request view the host exposes to the guest (header names lowercased so
/// property/value lookups are case-insensitive). The HTTP/2-style **pseudo-headers**
/// (`:method`/`:path`/`:authority`/`:scheme`) are injected into the header map because
/// real Proxy-Wasm filters routinely read them there (Envoy convention) — in addition to
/// the `get_property` path.
fn view_from(ctx: &RequestContext) -> RequestView {
    let real: Vec<(String, String)> = ctx
        .headers
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
        .collect();
    let host = header_value(&real, "host").cloned().unwrap_or_default();
    let path = match &ctx.query {
        Some(q) => format!("{}?{}", ctx.path, q),
        None => ctx.path.clone(),
    };
    let mut headers = vec![
        (":method".to_string(), ctx.method.clone()),
        (":path".to_string(), path.clone()),
        (":authority".to_string(), host.clone()),
        (":scheme".to_string(), "http".to_string()),
    ];
    headers.extend(real);
    RequestView {
        method: ctx.method.clone(),
        path,
        url_path: ctx.path.clone(),
        protocol: ctx.http_version.clone(),
        scheme: "http".to_string(),
        host,
        source_addr: ctx.client_ip.to_string(),
        headers,
        body: ctx.body.clone(),
    }
}

/// Drive one request's callback sequence and map the captured disposition to a `Decision`.
/// Any trap/error fails closed.
fn run_request(
    store: &mut Store<HostState>,
    inst: &Instance,
    view: RequestView,
    request_id: &str,
    fuel: u64,
    name: &str,
) -> Decision {
    store.data_mut().reset_for(view, request_id.to_string());
    if store.set_fuel(fuel).is_err() {
        return reject_500(name);
    }
    match run_callbacks(store, inst) {
        Ok(()) => map_decision(store.data().captured.clone(), name),
        Err(e) => {
            warn!(plugin = %name, error = %e, "wasm request failed (fail-closed)");
            reject_500(name)
        }
    }
}

fn run_callbacks(store: &mut Store<HostState>, inst: &Instance) -> Result<(), wasmi::Error> {
    let num_headers = store.data().req.headers.len() as i32;
    let body_len = store.data().req.body.len() as i32;
    call_opt(store, inst, "proxy_on_context_create", &[HTTP_CTX, ROOT_CTX])?;
    let action = call_opt(store, inst, "proxy_on_request_headers", &[HTTP_CTX, num_headers, 1])?
        .unwrap_or(0);
    if action == 0 {
        // Continue
        call_opt(store, inst, "proxy_on_request_body", &[HTTP_CTX, body_len, 1])?;
    }
    call_opt(store, inst, "proxy_on_done", &[HTTP_CTX])?;
    call_opt(store, inst, "proxy_on_delete", &[HTTP_CTX])?;
    Ok(())
}

fn map_decision(captured: Option<LocalResponse>, name: &str) -> Decision {
    match captured {
        None => Decision::Allow,
        Some(lr) => {
            let rule_id = format!("wasm-{name}");
            let reason = if lr.detail.is_empty() {
                "wasm plugin local response".to_string()
            } else {
                lr.detail
            };
            if lr.status == 403 {
                Decision::Block { rule_id, reason }
            } else {
                Decision::Reject { rule_id, reason, status: lr.status, retry_after: None }
            }
        }
    }
}

fn reject_500(name: &str) -> Decision {
    Decision::Reject {
        rule_id: format!("wasm-{name}"),
        reason: "wasm runtime error (fail-closed)".to_string(),
        status: 500,
        retry_after: None,
    }
}

/// Call an exported function by name if it exists, tolerating ABI arity differences
/// (0.2.0 vs 0.2.1) by padding/truncating `args` to the export's actual param count.
/// Returns the first result as `i32` (or `Some(0)` for a void export, `None` if absent).
fn call_opt(
    store: &mut Store<HostState>,
    inst: &Instance,
    name: &str,
    args: &[i32],
) -> Result<Option<i32>, wasmi::Error> {
    let Some(func) = inst.get_func(&*store, name) else { return Ok(None) };
    let ty = func.ty(&*store);
    let nparams = ty.params().len();
    let params: Vec<Val> = (0..nparams).map(|i| Val::I32(args.get(i).copied().unwrap_or(0))).collect();
    let mut results: Vec<Val> = ty.results().iter().map(|t| zero_val(*t)).collect();
    func.call(&mut *store, &params, &mut results)?;
    Ok(Some(results.first().and_then(|v| v.i32()).unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A guest that imports a SEMANTIC host call (`proxy_http_call`, 10 params) and invokes
    // it — exercising the runtime degradation signal (paletto #4).
    const HTTP_CALL_WAT: &str = r#"
    (module
      (import "env" "proxy_http_call"
        (func $http (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 1)
      (func (export "proxy_on_memory_allocate") (param i32) (result i32) (i32.const 16))
      (func (export "run") (result i32)
        (call $http (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)
                    (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0))))
    "#;

    #[test]
    fn semantic_stub_invocation_returns_unimplemented_and_is_flagged() {
        let mut cfg = Config::default();
        cfg.consume_fuel(true);
        let engine = Engine::new(&cfg);
        let module = Module::new(&engine, wat::parse_str(HTTP_CALL_WAT).unwrap().as_slice()).unwrap();

        // The stub must be classified semantic (so a runtime call flags it).
        let report = report::classify(&module);
        assert_eq!(report.semantic_stubs(), vec!["proxy_http_call"]);

        let mut linker = Linker::new(&engine);
        add_to_linker(&mut linker).unwrap();
        register_stubs(&mut linker, &module).unwrap();

        let limiter = StoreLimitsBuilder::new().memory_size(64 * 1024).build();
        let mut store = Store::new(&engine, HostState::new(limiter));
        store.limiter(|s| &mut s.limiter);
        store.set_fuel(1_000_000).unwrap();
        let inst = linker.instantiate_and_start(&mut store, &module).unwrap();

        let run = inst.get_typed_func::<(), i32>(&store, "run").unwrap();
        let ret = run.call(&mut store, ()).unwrap();
        assert_eq!(ret, Status::Unimplemented.code(), "semantic stub must answer Unimplemented");
        assert_eq!(
            store.data().semantic_stub_hit.as_deref(),
            Some("proxy_http_call"),
            "invoking a semantic stub must flag the instance as degraded at runtime"
        );
    }
}
