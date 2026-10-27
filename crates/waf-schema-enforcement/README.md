# waf-schema-enforcement

Positive-security detection modules for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**:
they validate requests against **your application's real contract** and score what falls outside
it.

| Module | Validates against | Config table (`waf-enterprise`) |
|---|---|---|
| `GraphqlSchemaModule` | the app's GraphQL SDL (`.graphql`), via `apollo-compiler` | `[enterprise.schema_enforcement]` |
| `GrpcSchemaModule` | the app's compiled `FileDescriptorSet`, via `prost-reflect` (unary calls) | `[enterprise.grpc_schema_enforcement]` |
| `ApiSchemaModule` | the app's OpenAPI 3.0 / 3.1 spec (JSON), via `oas3` + `jsonschema` | `[enterprise.api_schema]` |
| `BotDetectionModule` | client integrity: a modern-browser user agent with no `sec-fetch-*` headers | `[enterprise.bot_detection]` |

A query for a field that is not in your schema, a gRPC method that does not exist, or a REST route
that is not in your spec is something your own clients never send — a strong probing signal.

## Design

- **Additive scoring**: every module returns scores into the same cumulative anomaly score as the
  core modules, under reserved rule-id namespaces (`schema-graphql-*`, `schema-grpc-*`,
  `schema-api-*`, `bot-*`), with configurable severities. Nothing blocks on its own below the
  threshold, which lets you start in monitor mode.
- **Defense in depth, not duplication**: the core's structural caps (depth, size, batch) run first,
  so validators only see bounded input; value-level injection (SQLi/XSS inside a parameter) stays
  in the core's content channel.
- **Fail-closed on configuration, never on traffic**: a missing or invalid schema/descriptor/spec
  is a boot error.
- **No remote fetching**: `jsonschema` is built without an HTTP retriever.

## Usage

```rust
use waf_schema_enforcement::GraphqlSchemaModule;

// graphql_cfg: waf_schema_enforcement::SchemaEnforcementConfig (schema_path, paths, severities)
let module = GraphqlSchemaModule::from_config(&graphql_cfg)?;   // loads and validates the SDL
let proxy = waf_proxy::Proxy::builder(&config)
    .add_module(Box::new(module))
    .build()
    .await?;
```

To pick up a changed schema on reload, build the modules inside `.module_factory(..)` instead of
`.add_module(..)`, as `waf-enterprise` does.

## License

Apache-2.0. Part of [Light WAF](https://github.com/0x00spor3/Light-WAF); see
[`ARCHITECTURE_ENTERPRISE.md`](https://github.com/0x00spor3/Light-WAF/blob/main/ARCHITECTURE_ENTERPRISE.md) §4.
