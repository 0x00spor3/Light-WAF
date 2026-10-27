# waf-wasm-signing

Signed WASM plugins for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**.

The core's Proxy-Wasm runtime (`waf-wasm`) loads unsigned `.wasm` filters. This crate adds a trust
gate in front of it: it verifies a detached **minisign** (Ed25519) signature over the exact plugin
bytes against your trusted public keys, and only then hands those same bytes to the runtime.

```rust
use waf_wasm_signing::{load_verified_plugin, WasmOptions};

let wasm = std::fs::read("plugins/filter.wasm")?;
let sig = std::fs::read_to_string("plugins/filter.wasm.minisig")?;
let module = load_verified_plugin("filter", &wasm, &sig, &trusted_keys, b"", &WasmOptions::default())?;
```

`verify_signature` is available on its own if you only need the check.

## Fail-closed on purpose

The core loader *skips* a broken unsigned plugin: a missing plugin only reduces coverage. A signed
plugin whose signature does not verify — missing, malformed, or made with an untrusted key — is
**indistinguishable from tampering**, so it is a boot error, never a silent skip.

With the `waf-enterprise` binary: `[enterprise.wasm]` (`trusted_keys`,
`plugins = [{ wasm_path, sig_path, config }]`, runtime limits). Set `exclusive = true` to also
refuse at boot any unsigned plugin configured in the core's `[modules.wasm]`; without it, an
unsigned plugin there would bypass the gate.

## License

Apache-2.0. Part of [Light WAF](https://github.com/0x00spor3/Light-WAF); see
[`ARCHITECTURE_ENTERPRISE.md`](https://github.com/0x00spor3/Light-WAF/blob/main/ARCHITECTURE_ENTERPRISE.md) §4.
