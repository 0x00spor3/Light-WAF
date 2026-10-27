# waf-crs-curated

Curated OWASP CRS / ModSecurity rule content for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**.

The Light WAF core already ships a `SecRule` parser and engine (`waf-detection`'s CRS module). This
crate ships only **content**: 28 tuned rules, embedded at compile time, that add high-confidence
signatures on top of the core's native detection modules:

- generic categories — cloud-metadata SSRF, PHP-wrapper LFI, webshells, `.git`/`.env` exposure,
  dangerous HTTP methods, deserialization markers, reconnaissance user agents;
- a named-CVE pack taken from the CISA KEV catalog — e.g. Log4Shell (including lookup
  obfuscation such as `${${lower:j}ndi:…}`), Spring4Shell, MOVEit, GoAnywhere, PaperCut, PAN-OS,
  FortiWeb, TeamCity, SharePoint ToolShell, PHP-CGI argument injection, Next.js middleware bypass.

It does not re-implement baseline SQLi/XSS/traversal/RCE detection: that stays in the core.
Matches contribute to the same cumulative anomaly score as the native modules. Rule ids use the
reserved `9000000+` range.

## Usage

```rust
use waf_detection::crs::CrsModule;

let module = CrsModule::from_source(&waf_crs_curated::curated_source());
let proxy = waf_proxy::Proxy::builder(&config)
    .add_module(Box::new(module))
    .build()
    .await?;
```

With the `waf-enterprise` binary: `[enterprise.crs_curated] enabled = true`. Your own rule files
keep using the core's `[modules.crs].files`.

## Compatibility guarantee

The content uses only constructs supported by the core engine. A test loads it through that
engine and asserts that exactly `EXPECTED_LOADED` rules load with **none** skipped, so a rule that
the engine could not run fails the build instead of silently shrinking coverage.

## License

Apache-2.0. Part of [Light WAF](https://github.com/0x00spor3/Light-WAF); see
[`ARCHITECTURE_ENTERPRISE.md`](https://github.com/0x00spor3/Light-WAF/blob/main/ARCHITECTURE_ENTERPRISE.md) §6.
