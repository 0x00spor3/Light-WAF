# waf-wasm test fixtures

## In-CI oracle (deterministic, no toolchain)

The functional bite-tests in `tests/runtime.rs` use **inline WAT guests** compiled at test
time by the `wat` crate. They are the source of truth in CI: human-readable, reproducible,
and free of any opaque committed binary (this is deliberately stronger than checking in a
`.wasm` — see the B3 plan, paletto #5). They cover: block-on-marker, benign-allow,
per-request isolation (sequential + concurrent), and the DoS ceilings (fuel/memory).

## ABI-fidelity smoke (env-gated, real SDK filter)

`block_filter/` is a **real** Proxy-Wasm filter built with the `proxy-wasm` Rust SDK. It
proves the host runs an SDK-produced guest unchanged (the true ABI-fidelity check, like the
real-CRS smoke in B2). It is NOT built by the normal workspace build.

### Build command (pinned)

```sh
rustup target add wasm32-unknown-unknown
cd crates/waf-wasm/tests/fixtures/block_filter
cargo build --release --target wasm32-unknown-unknown
# output: target/wasm32-unknown-unknown/release/block_filter.wasm
```

### Run the smoke

Point the env var at the built artifact and run the gated test:

```sh
WAF_WASM_FIXTURE=crates/waf-wasm/tests/fixtures/block_filter/target/wasm32-unknown-unknown/release/block_filter.wasm \
  cargo test -p waf-wasm --test smoke -- --nocapture
```

When `WAF_WASM_FIXTURE` is unset the smoke is skipped (prints a notice), exactly like the
other env-gated oracles in this repo (gotestwaf, real CRS).
