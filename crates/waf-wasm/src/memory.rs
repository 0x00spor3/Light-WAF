// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

//! Guest linear-memory access + the reentrant guest-allocator primitive.
//!
//! Proxy-Wasm splits ownership: the **host** owns the bytes it wants to hand the guest,
//! but the **guest** owns its linear memory. So to return a buffer (request body, header
//! map, property value) the host must (1) call the guest's exported allocator to reserve
//! space, then (2) write the bytes there. That reentrant `malloc` call — invoked from
//! *inside* a host function — is where a fuel-exhaustion or memory-cap trap can land
//! mid-write; the B3-0 probe proved it unwinds cleanly to an `Err` (→ `Reject{500}`),
//! and every helper here returns `Result<_, wasmi::Error>` so that unwind stays clean.

use wasmi::{AsContext, AsContextMut, Memory, TypedFunc};

/// Read `len` bytes from guest linear memory at `ptr`. OOB → `Err` (never a host panic).
pub fn read(mem: &Memory, ctx: impl AsContext, ptr: u32, len: u32) -> Result<Vec<u8>, wasmi::Error> {
    let mut buf = vec![0u8; len as usize];
    mem.read(ctx, ptr as usize, &mut buf)?;
    Ok(buf)
}

/// Write `data` into guest linear memory at `ptr`. OOB → `Err`.
pub fn write(mem: &Memory, ctx: impl AsContextMut, ptr: u32, data: &[u8]) -> Result<(), wasmi::Error> {
    mem.write(ctx, ptr as usize, data)?;
    Ok(())
}

/// Write a little-endian `u32` at `ptr` — used for the return-pointer / return-size slots
/// the guest passes by reference to host calls like `get_buffer_bytes`.
pub fn write_u32(mem: &Memory, ctx: impl AsContextMut, ptr: u32, val: u32) -> Result<(), wasmi::Error> {
    write(mem, ctx, ptr, &val.to_le_bytes())
}

/// Call the guest allocator to reserve `len` bytes; returns the guest pointer. The call
/// may trap (fuel/memory ceiling) — that surfaces as `Err`, not a panic. A negative
/// return is treated as allocation failure (e.g. growth denied by the memory cap).
pub fn guest_malloc(
    alloc: &TypedFunc<i32, i32>,
    mut ctx: impl AsContextMut,
    len: u32,
) -> Result<u32, wasmi::Error> {
    let ptr = alloc.call(&mut ctx, len as i32)?;
    if ptr < 0 {
        return Err(wasmi::Error::new("guest allocator returned a negative pointer"));
    }
    Ok(ptr as u32)
}

/// Allocate `data.len()` bytes in the guest and write `data` there; returns the pointer.
/// The "host returns a buffer to the guest" primitive (request body, header map, …).
pub fn alloc_and_write(
    alloc: &TypedFunc<i32, i32>,
    mem: &Memory,
    mut ctx: impl AsContextMut,
    data: &[u8],
) -> Result<u32, wasmi::Error> {
    let ptr = guest_malloc(alloc, &mut ctx, data.len() as u32)?;
    write(mem, &mut ctx, ptr, data)?;
    Ok(ptr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasmi::{Engine, Instance, Linker, Module, Store};

    // A minimal guest: a page of memory + a bump allocator under the Proxy-Wasm name.
    const WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (global $bump (mut i32) (i32.const 16))
      (func (export "proxy_on_memory_allocate") (param $n i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $bump))
        (global.set $bump (i32.add (global.get $bump) (local.get $n)))
        (local.get $p)))
    "#;

    fn setup() -> (Store<()>, Instance) {
        let engine = Engine::default();
        let module = Module::new(&engine, wat::parse_str(WAT).unwrap().as_slice()).unwrap();
        let mut store = Store::new(&engine, ());
        let instance = Linker::<()>::new(&engine)
            .instantiate_and_start(&mut store, &module)
            .unwrap();
        (store, instance)
    }

    fn handles(store: &Store<()>, inst: &Instance) -> (Memory, TypedFunc<i32, i32>) {
        let mem = inst.get_memory(store, "memory").unwrap();
        let alloc = inst
            .get_typed_func::<i32, i32>(store, "proxy_on_memory_allocate")
            .unwrap();
        (mem, alloc)
    }

    #[test]
    fn alloc_write_read_round_trip() {
        let (mut store, inst) = setup();
        let (mem, alloc) = handles(&store, &inst);
        let payload = b"x-block: 1\r\nbody=EVIL";
        let ptr = alloc_and_write(&alloc, &mem, &mut store, payload).unwrap();
        let got = read(&mem, &store, ptr, payload.len() as u32).unwrap();
        assert_eq!(got, payload);
    }

    #[test]
    fn write_u32_is_little_endian() {
        let (mut store, inst) = setup();
        let (mem, alloc) = handles(&store, &inst);
        let ptr = guest_malloc(&alloc, &mut store, 4).unwrap();
        write_u32(&mem, &mut store, ptr, 0x0A0B0C0D).unwrap();
        assert_eq!(read(&mem, &store, ptr, 4).unwrap(), vec![0x0D, 0x0C, 0x0B, 0x0A]);
    }

    #[test]
    fn out_of_bounds_read_is_err_not_panic() {
        let (store, inst) = setup();
        let (mem, _alloc) = handles(&store, &inst);
        // One page = 64 KiB; read far past the end.
        assert!(read(&mem, &store, 60_000, 100_000).is_err());
    }

    #[test]
    fn two_allocations_do_not_overlap() {
        let (mut store, inst) = setup();
        let (mem, alloc) = handles(&store, &inst);
        let a = alloc_and_write(&alloc, &mem, &mut store, b"AAAA").unwrap();
        let b = alloc_and_write(&alloc, &mem, &mut store, b"BBBB").unwrap();
        assert_ne!(a, b);
        assert_eq!(read(&mem, &store, a, 4).unwrap(), b"AAAA");
        assert_eq!(read(&mem, &store, b, 4).unwrap(), b"BBBB");
    }
}
