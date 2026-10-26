<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — GraphQL schema-enforcement (§4-B)

Verifies the enterprise GraphQL schema-enforcement module (`waf-modules-premium`): each GraphQL
operation is validated against the app's **real SDL schema** via `apollo-compiler` and injected as a
`structural()` `WafModule`. A query referencing anything not in the schema (unknown
field/type/argument, missing subselection, undefined/unused variable) scores
`schema-graphql-unknown-field` (Critical); a non-GraphQL body scores the lower
`schema-graphql-parse-error` (Warning). It is **governance of the schema**, not baseline detection —
value-injection stays in the OPEN §6 channel and the structural DoS caps stay in the OPEN Phase-11
module.

Two layers:
- **A. Offline suite** (`cargo test`, no environment needed) — unit + datapath bite-tests: schema
  load (boot-fatal on invalid SDL), the parse-error/unknown-field split, multi-transport extraction,
  the FP-guard (legit constructs incl. introspection stay clean), and a REAL-pipeline block/control.
  This is the CI-level proof and runs anywhere.
- **B. Live wire check** (`check_schema_enforcement.sh`) — a running enterprise WAF with the module
  enabled and a sample schema, hit with a battery of schema-invalid operations (must BLOCK) and
  legitimate ones (must PASS), across all three transports plus the path-gating guard.

---

## A. Offline suite

```sh
cd enterprise
cargo test -p waf-modules-premium
# lib (20): schema parse/load-from-file/boot-fatal, parse-error vs schema-invalid split, extraction
#           (application/graphql | JSON leaf + batch | GET ?query= | path-gating | envelope-unwrap),
#           FP-guard (aliases/fragments/__typename/introspection/variables → Valid), batch dedup,
#           registry rule_id uniqueness.
# datapath (5): on the REAL pipeline — schema-invalid query blocks (attributed to the rule) vs
#           control without the module passes; a valid query passes even with the module on;
#           default-off is inert; the module is structural().
cargo test -p waf-enterprise          # incl. 3 schema_enforcement config tests: section parse, defaults-off, bad severity rejected
```

What it proves (the enterprise value — validation that can't drift):
- `spec_violations_are_flagged` + `legit_constructs_validate_clean` — the exact set of what is and
  isn't a violation is pinned, so an `apollo-compiler` bump can't silently change the verdict.
- `datapath.rs` — the module, on the REAL pipeline, blocks a schema-invalid query; the same request
  with no module passes (control) — proving the module is what blocks.

## B. Live wire check

### B.1 Prereqs

- Build once: `cargo build -p waf-enterprise` (from `enterprise/`).
- `bash` + `curl`. A dummy backend (so legit requests get a 200, not a 502):

```sh
python3 -m http.server 3000
```

### B.2 Node config (`schema-node.toml`)

```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode            = "blocking"   # detection-only would LOG, not actually block
block_threshold = 5            # a single Critical unknown-field hit (severity 6) crosses this

[enterprise.schema_enforcement]
enabled     = true
schema_path = "scripts/schema-enforcement/app.graphql"
paths       = ["/graphql"]
# parse_error_severity   = "warning"    # non-GraphQL body — additive, does NOT block alone at 5
# unknown_field_severity = "critical"   # schema-invalid query — blocks
```

### B.3 Run

```sh
WAF_CONFIG=schema-node.toml cargo run -p waf-enterprise
# boot log: "wiring GraphQL schema-enforcement module (§4-B)  schema=... paths=[/graphql]"
# a missing/invalid schema_path is a FATAL boot error (fail-closed on config) — by design.
```

In another terminal (from `enterprise/`):

```sh
PORT=8080 scripts/schema-enforcement/check_schema_enforcement.sh
```

### B.4 What to observe

- Every **schema-invalid** row → `[BLOCK ok ] … -> 403` (blocked before the backend), across the
  `application/graphql`, JSON and GET transports.
- Every **legitimate** row → `[PASS ok  ] … -> 200`, **including introspection** (`__schema`) — this
  module does not police introspection (that is the OPEN `[modules.graphql]` module's job).
- The **path-gating** row → `[PASS ok  ]`: a `{"query": …}` JSON body on `/api/search` is left alone
  (a non-GraphQL API with a `query` field is not GraphQL).
- Summary `failed: 0` and `GraphQL schema-enforcement verified on the wire.`

### B.5 Optional — see the parse-error leaf block

The non-GraphQL-body case scores `schema-graphql-parse-error` = **Warning**, which is additive and
does not block on its own at `block_threshold = 5`. To watch it block, set
`parse_error_severity = "critical"` in the config and send a non-GraphQL body:

```sh
curl -s -o /dev/null -w '%{http_code}\n' \
  -H 'content-type: application/graphql' --data 'this is not graphql {{{' \
  http://127.0.0.1:8080/graphql        # -> 403 with parse_error_severity = critical
```

---

## Troubleshooting

- **All schema-invalid rows MISS (not blocked)** — the module isn't active or isn't scoring: check
  the boot log for `wiring GraphQL schema-enforcement module`; confirm
  `[enterprise.schema_enforcement].enabled = true`, `mode = "blocking"`, and `block_threshold <= 6`.
- **Boot fails with `GraphQL schema-enforcement: cannot read schema file …`** — `schema_path` is
  wrong or the file is missing. This is a **deliberate fail-closed boot error**, not a bug: fix the
  path (relative paths are resolved from the working directory the binary runs in).
- **Boot fails with a schema parse/validate error** — the SDL itself is invalid (e.g. a field of an
  undefined type). Fix `app.graphql`; the module refuses to start on an unvalidatable schema.
- **A legitimate query is blocked (`FALSE +`)** — almost always **schema drift**: the app's deployed
  schema is newer than `app.graphql`. Update the SDL copy (that is the governance contract), or lower
  `unknown_field_severity`. The one true FP source is drift — the module never flags a spec-valid
  query that matches the loaded schema.
- **The GET row MISSes but body rows BLOCK** — the operation is carried in `?query=` only on a
  configured GraphQL path; confirm `paths` includes the path you are hitting (`GQL_PATH`).
- **`BLOCK ok` never seen, a different code repeats** — your build's block status differs from `403`;
  re-run with `BLOCK_CODE=<code> scripts/schema-enforcement/check_schema_enforcement.sh`.
