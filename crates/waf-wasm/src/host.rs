// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! `HostState` (the `Store` data) and the implemented subset of Proxy-Wasm host functions.
//!
//! Every closure copies the `Memory`/allocator handles (both `Copy`) and clones any owned
//! request data it needs **before** taking a mutable borrow of the `Caller`, so the
//! reentrant `alloc_and_write` (which mutably borrows the store) never aliases. A failure
//! anywhere returns `Err` → the call traps → the driver fails closed (`Reject{500}`).
//!
//! Host functions OUTSIDE this subset are not defined here; the loader stubs them per the
//! guest's declared imports and reports them (see `report.rs`), so loading a real filter
//! never fails on a missing import while the coverage gap stays explicit (policy D3=A).

use std::time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};
use wasmi::{Caller, Linker, Memory, StoreLimits, TypedFunc};

use crate::abi::{BufferType, LogLevel, MapType, Status};
use crate::marshal::{encode_header_map_pairs, header_value, resolve_property, RequestView};
use crate::memory;

/// A `proxy_send_local_response` captured by the host — the plugin's disposition. The
/// driver maps it to a `waf_core::Decision` (never written to the wire by the plugin).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalResponse {
    pub status: u16,
    pub detail: String,
    pub body: Vec<u8>,
}

/// The `Store` data for one pooled instance. Per-request fields (`req`, `captured`) are
/// reset on checkout by the driver — the host owns that reset (paletto #1).
pub struct HostState {
    /// Enforces the memory cap (`max_memory_bytes`).
    pub limiter: StoreLimits,
    /// Guest linear memory, cached after instantiation.
    pub mem: Option<Memory>,
    /// Guest allocator (`proxy_on_memory_allocate`/`malloc`), cached after instantiation.
    pub alloc: Option<TypedFunc<i32, i32>>,
    /// Opaque plugin configuration (read by the guest during `proxy_on_configure`).
    /// Persistent per instance — NOT reset per request.
    pub config: Vec<u8>,
    /// Read-only view of the current request.
    pub req: RequestView,
    /// Disposition captured via `proxy_send_local_response`, if any.
    pub captured: Option<LocalResponse>,
    /// First semantically-meaningful stubbed host call the plugin actually INVOKED, if any.
    /// Set by the stub (see `runtime::register_stubs`) the first time it is hit — this is
    /// the accurate "degraded at runtime" signal (paletto #4), unlike a merely *declared*
    /// import. Persists per instance.
    pub semantic_stub_hit: Option<String>,
    /// For log correlation.
    pub request_id: String,
}

impl HostState {
    pub fn new(limiter: StoreLimits) -> Self {
        HostState {
            limiter,
            mem: None,
            alloc: None,
            config: Vec::new(),
            req: RequestView::default(),
            captured: None,
            semantic_stub_hit: None,
            request_id: String::new(),
        }
    }

    /// Reset per-request state at checkout (the host-owned half of the isolation boundary).
    pub fn reset_for(&mut self, req: RequestView, request_id: String) {
        self.req = req;
        self.captured = None;
        self.request_id = request_id;
    }
}

fn mem_of(caller: &Caller<'_, HostState>) -> Result<Memory, wasmi::Error> {
    caller.data().mem.ok_or_else(|| wasmi::Error::new("guest memory not initialised"))
}

fn alloc_of(caller: &Caller<'_, HostState>) -> Result<TypedFunc<i32, i32>, wasmi::Error> {
    caller.data().alloc.ok_or_else(|| wasmi::Error::new("guest allocator not initialised"))
}

/// Allocate + write `data` into guest memory, then write the (ptr,size) into the guest's
/// return-pointer slots. The Proxy-Wasm "host hands back a buffer" pattern.
fn return_buffer(
    caller: &mut Caller<'_, HostState>,
    data: &[u8],
    ret_ptr: i32,
    ret_size: i32,
) -> Result<i32, wasmi::Error> {
    let mem = mem_of(caller)?;
    let alloc = alloc_of(caller)?;
    let ptr = memory::alloc_and_write(&alloc, &mem, &mut *caller, data)?;
    memory::write_u32(&mem, &mut *caller, ret_ptr as u32, ptr)?;
    memory::write_u32(&mem, &mut *caller, ret_size as u32, data.len() as u32)?;
    Ok(Status::Ok.code())
}

/// Register the implemented subset on the linker (namespace `env`).
pub fn add_to_linker(linker: &mut Linker<HostState>) -> Result<(), wasmi::Error> {
    // proxy_log(level, message_data, message_size) -> status
    linker.func_wrap(
        "env",
        "proxy_log",
        |caller: Caller<'_, HostState>, level: i32, ptr: i32, size: i32| -> Result<i32, wasmi::Error> {
            let mem = mem_of(&caller)?;
            let bytes = memory::read(&mem, &caller, ptr as u32, size as u32)?;
            let msg = String::from_utf8_lossy(&bytes);
            let rid = &caller.data().request_id;
            match LogLevel::from_i32(level) {
                LogLevel::Error | LogLevel::Critical => warn!(request_id = %rid, "wasm plugin: {msg}"),
                _ => debug!(request_id = %rid, "wasm plugin: {msg}"),
            }
            Ok(Status::Ok.code())
        },
    )?;

    // proxy_get_buffer_bytes(buffer_type, start, max_size, ret_ptr, ret_size) -> status
    linker.func_wrap(
        "env",
        "proxy_get_buffer_bytes",
        |mut caller: Caller<'_, HostState>,
         buffer_type: i32,
         start: i32,
         max_size: i32,
         ret_ptr: i32,
         ret_size: i32|
         -> Result<i32, wasmi::Error> {
            let data: Vec<u8> = match BufferType::from_i32(buffer_type) {
                Some(BufferType::HttpRequestBody) => slice(&caller.data().req.body, start, max_size),
                Some(BufferType::PluginConfiguration) => {
                    slice(&caller.data().config, start, max_size)
                }
                Some(BufferType::VmConfiguration) => Vec::new(),
                _ => return Ok(Status::Unimplemented.code()),
            };
            return_buffer(&mut caller, &data, ret_ptr, ret_size)
        },
    )?;

    // proxy_get_header_map_pairs(map_type, ret_ptr, ret_size) -> status
    linker.func_wrap(
        "env",
        "proxy_get_header_map_pairs",
        |mut caller: Caller<'_, HostState>, map_type: i32, ret_ptr: i32, ret_size: i32|
         -> Result<i32, wasmi::Error> {
            match MapType::from_i32(map_type) {
                Some(MapType::HttpRequestHeaders) => {
                    let enc = encode_header_map_pairs(&caller.data().req.headers);
                    return_buffer(&mut caller, &enc, ret_ptr, ret_size)
                }
                _ => Ok(Status::Unimplemented.code()),
            }
        },
    )?;

    // proxy_get_header_map_value(map_type, key_ptr, key_size, ret_ptr, ret_size) -> status
    linker.func_wrap(
        "env",
        "proxy_get_header_map_value",
        |mut caller: Caller<'_, HostState>,
         map_type: i32,
         key_ptr: i32,
         key_size: i32,
         ret_ptr: i32,
         ret_size: i32|
         -> Result<i32, wasmi::Error> {
            if MapType::from_i32(map_type) != Some(MapType::HttpRequestHeaders) {
                return Ok(Status::Unimplemented.code());
            }
            let mem = mem_of(&caller)?;
            let key = memory::read(&mem, &caller, key_ptr as u32, key_size as u32)?;
            let key = String::from_utf8_lossy(&key).to_string();
            match header_value(&caller.data().req.headers, &key).cloned() {
                Some(v) => return_buffer(&mut caller, v.as_bytes(), ret_ptr, ret_size),
                // Absent header: `NotFound` (NOT an empty buffer — the SDK reads a returned
                // empty-but-non-null buffer as `Some("")`, a false positive).
                None => Ok(Status::NotFound.code()),
            }
        },
    )?;

    // proxy_get_property(path_ptr, path_size, ret_ptr, ret_size) -> status
    linker.func_wrap(
        "env",
        "proxy_get_property",
        |mut caller: Caller<'_, HostState>, path_ptr: i32, path_size: i32, ret_ptr: i32, ret_size: i32|
         -> Result<i32, wasmi::Error> {
            let mem = mem_of(&caller)?;
            let path = memory::read(&mem, &caller, path_ptr as u32, path_size as u32)?;
            match resolve_property(&path, &caller.data().req) {
                Some(v) => return_buffer(&mut caller, &v, ret_ptr, ret_size),
                None => Ok(Status::NotFound.code()),
            }
        },
    )?;

    // proxy_send_local_response(status, detail_ptr, detail_size, body_ptr, body_size,
    //                           headers_ptr, headers_size, grpc_status) -> status
    linker.func_wrap(
        "env",
        "proxy_send_local_response",
        |mut caller: Caller<'_, HostState>,
         status: i32,
         detail_ptr: i32,
         detail_size: i32,
         body_ptr: i32,
         body_size: i32,
         _headers_ptr: i32,
         _headers_size: i32,
         _grpc_status: i32|
         -> Result<i32, wasmi::Error> {
            let mem = mem_of(&caller)?;
            let detail = if detail_size > 0 {
                String::from_utf8_lossy(&memory::read(&mem, &caller, detail_ptr as u32, detail_size as u32)?)
                    .to_string()
            } else {
                String::new()
            };
            let body = if body_size > 0 {
                memory::read(&mem, &caller, body_ptr as u32, body_size as u32)?
            } else {
                Vec::new()
            };
            caller.data_mut().captured = Some(LocalResponse {
                status: status.clamp(0, u16::MAX as i32) as u16,
                detail,
                body,
            });
            Ok(Status::Ok.code())
        },
    )?;

    // proxy_get_current_time_nanoseconds(ret_ptr) -> status
    linker.func_wrap(
        "env",
        "proxy_get_current_time_nanoseconds",
        |mut caller: Caller<'_, HostState>, ret_ptr: i32| -> Result<i32, wasmi::Error> {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0);
            let mem = mem_of(&caller)?;
            memory::write(&mem, &mut caller, ret_ptr as u32, &nanos.to_le_bytes())?;
            Ok(Status::Ok.code())
        },
    )?;

    // proxy_set_tick_period_milliseconds(period) -> status. Cosmetic stub: we never tick,
    // but answering Ok keeps a plugin that merely sets a period working unchanged.
    linker.func_wrap(
        "env",
        "proxy_set_tick_period_milliseconds",
        |_caller: Caller<'_, HostState>, _period: i32| -> i32 { Status::Ok.code() },
    )?;

    Ok(())
}

/// Clamp `[start, start+max]` to a buffer and copy out the slice. Proxy-Wasm passes sizes
/// as UNSIGNED values in i32 slots, so `max_size` is reinterpreted as `u32` — the SDK reads
/// "the whole buffer" by passing `usize::MAX` (which arrives as `-1`).
fn slice(buf: &[u8], start: i32, max_size: i32) -> Vec<u8> {
    let start = start as u32 as usize;
    if start >= buf.len() {
        return Vec::new();
    }
    let max = max_size as u32 as usize;
    let end = start.saturating_add(max).min(buf.len());
    buf[start..end].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmi::{Engine, Module, Store, StoreLimitsBuilder};

    // A guest that, on `run`, reads the request headers map and sends a 403 local response
    // if the encoded header buffer contains the bytes "x-block". Exercises the real host
    // plumbing: get_header_map_pairs -> reentrant alloc into guest mem -> read back ->
    // send_local_response capture.
    const WAT: &str = r#"
    (module
      (import "env" "proxy_get_header_map_pairs"
        (func $get_headers (param i32 i32 i32) (result i32)))
      (import "env" "proxy_send_local_response"
        (func $send (param i32 i32 i32 i32 i32 i32 i32 i32) (result i32)))
      (memory (export "memory") 2)
      (global $bump (mut i32) (i32.const 1024))
      (func (export "proxy_on_memory_allocate") (param $n i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $bump))
        (global.set $bump (i32.add (global.get $bump) (local.get $n)))
        (local.get $p))
      ;; scratch: [0]=ptr slot, [4]=size slot
      (func (export "run") (result i32)
        (local $ptr i32) (local $size i32) (local $i i32) (local $base i32)
        (drop (call $get_headers (i32.const 0) (i32.const 0) (i32.const 4)))
        (local.set $ptr (i32.load (i32.const 0)))
        (local.set $size (i32.load (i32.const 4)))
        ;; naive scan for 'x' 'b' 'l' 'o' 'c' 'k'
        (local.set $i (i32.const 0))
        (block $found
          (block $notfound
            (loop $scan
              (br_if $notfound (i32.gt_s (local.get $i) (i32.sub (local.get $size) (i32.const 6))))
              (local.set $base (i32.add (local.get $ptr) (local.get $i)))
              (if (i32.and
                    (i32.and
                      (i32.eq (i32.load8_u (local.get $base)) (i32.const 120))           ;; x
                      (i32.eq (i32.load8_u (i32.add (local.get $base) (i32.const 1))) (i32.const 45))) ;; -
                    (i32.eq (i32.load8_u (i32.add (local.get $base) (i32.const 2))) (i32.const 98)))   ;; b
                (then (br $found)))
              (local.set $i (i32.add (local.get $i) (i32.const 1)))
              (br $scan)))
          (return (i32.const 0)))  ;; not found -> 0
        (drop (call $send (i32.const 403) (i32.const 0) (i32.const 0)
                          (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0) (i32.const 0)))
        (i32.const 1))
    )
    "#;

    fn run_with_headers(headers: Vec<(String, String)>) -> Option<LocalResponse> {
        let engine = Engine::default();
        let module = Module::new(&engine, wat::parse_str(WAT).unwrap().as_slice()).unwrap();
        let limiter = StoreLimitsBuilder::new().memory_size(4 * 64 * 1024).build();
        let mut store = Store::new(&engine, HostState::new(limiter));
        store.limiter(|s| &mut s.limiter);
        let mut linker = Linker::new(&engine);
        add_to_linker(&mut linker).unwrap();
        let inst = linker.instantiate_and_start(&mut store, &module).unwrap();

        // Cache memory + allocator (what the driver will do post-instantiate).
        let mem = inst.get_memory(&store, "memory").unwrap();
        let alloc = inst.get_typed_func::<i32, i32>(&store, "proxy_on_memory_allocate").unwrap();
        store.data_mut().mem = Some(mem);
        store.data_mut().alloc = Some(alloc);

        let req = RequestView { headers, ..RequestView::default() };
        store.data_mut().reset_for(req, "t".into());

        let run = inst.get_typed_func::<(), i32>(&store, "run").unwrap();
        run.call(&mut store, ()).unwrap();
        store.data().captured.clone()
    }

    #[test]
    fn guest_blocks_on_header_via_real_host_plumbing() {
        let cap = run_with_headers(vec![("x-block".into(), "1".into())]);
        assert_eq!(cap, Some(LocalResponse { status: 403, detail: String::new(), body: Vec::new() }));
    }

    #[test]
    fn guest_allows_benign_request() {
        let cap = run_with_headers(vec![("accept".into(), "text/html".into())]);
        assert_eq!(cap, None);
    }

    #[test]
    fn slice_treats_max_size_as_unsigned() {
        // The proxy-wasm SDK reads a whole buffer with `usize::MAX`, which arrives as i32 -1.
        // It must mean "everything", not "nothing" (regression: empty plugin config / body).
        let buf = b"hello world";
        assert_eq!(slice(buf, 0, -1), buf, "max_size -1 must mean the whole buffer");
        assert_eq!(slice(buf, 6, -1), b"world");
        assert_eq!(slice(buf, 0, 5), b"hello");
        assert_eq!(slice(buf, 100, -1), b"", "start past the end is empty");
    }
}
