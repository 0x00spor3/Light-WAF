<!-- SPDX-License-Identifier: Apache-2.0 -->
# Runbook — OpenAPI positive-security (§4-B part 3)

Verifies the enterprise API-security module (`waf-modules-premium`): each REST/JSON request under a
guarded path prefix is validated against the app's **real OpenAPI spec** (a JSON file — v1 is
JSON-only) and injected as a `structural()` `WafModule`. A request to an endpoint/method the spec does
not declare scores `schema-api-unknown-route` / `schema-api-method-not-allowed` (Critical); a request
to a known operation that violates its contract (undeclared/missing/mistyped parameter, unknown or
missing body property, wrong Content-Type, unparseable JSON) scores the lower `violation_severity`.
Governance of the **contract**, not baseline detection — value-level injection (SQLi/XSS in a
parameter *value*) stays in the OPEN §6 channel, and the structural DoS/body caps stay in the OPEN
pipeline (which runs first). Additive `Decision::Scores`, zero core.

Two layers:
- **A. Offline suite** (`cargo test`, no environment) — unit + datapath bite-tests: spec load
  (boot-fatal on invalid/uncompilable), 3.0→JSON-Schema normalization (nullable), the path router
  (most-specific-first), parameter/body validation per class, the FP-guard, and a REAL-pipeline
  block/control. This is the authoritative gate.
- **B. Live wire check** (`check_api_schema_enforcement.sh`) — a running enterprise WAF with the
  module enabled, hit with ordinary `curl`.

---

## A. Offline suite

```sh
cd enterprise
cargo test -p waf-modules-premium          # 32 api_schema unit (load/normalize/router/param+body)
                                           # + 6 api_schema_datapath (REAL pipeline: block/control/FP/boundary)
cargo test -p waf-enterprise               # incl. 3 api_schema config tests
```

## B. Live wire check

### B.1 Prereqs

- Build once: `cargo build -p waf-enterprise` (from `enterprise/`).
- `bash` + `curl`.
- The demo spec `scripts/api-schema-enforcement/openapi.json` (shipped) — or point `spec_path` at your
  own OpenAPI **JSON** (convert YAML → JSON first; v1 is JSON-only by design, see the plan/A0).

### B.2 Node config (`api-node.toml`)

```toml
[proxy]
listen  = "127.0.0.1:8080"
backend = "http://127.0.0.1:3000"

[waf]
mode            = "blocking"
block_threshold = 5            # a single Critical unknown-route hit (severity 6) crosses this

[enterprise.api_schema]
enabled   = true
spec_path = "scripts/api-schema-enforcement/openapi.json"
paths     = ["/api"]           # only requests under these prefixes are measured against the spec
# unknown_route_severity = "critical"
# violation_severity     = "warning"   # param/body shape violations (additive; see B.5)
# strict_params          = true        # flag undeclared query params
# strict_body            = true        # enforce additionalProperties:false on the body
```

### B.3 Run

```sh
WAF_CONFIG=api-node.toml cargo run -p waf-enterprise
# boot log: "wiring OpenAPI positive-security module (§4-B part 3)  spec=…/openapi.json paths=["/api"]"
# a missing/invalid/uncompilable spec_path is a FATAL boot error (fail-closed on config).
```

In another terminal (from `enterprise/`):

```sh
PORT=8080 scripts/api-schema-enforcement/check_api_schema_enforcement.sh
```

### B.4 What to observe

- The **unknown route** and **method not allowed** rows → `[BLOCK ok ] … -> 403` (blocked before the
  backend).
- The **contract-honouring** rows → `[PASS ok  ]`: a valid GET by id, a valid `?verbose=true`, a valid
  POST body, a body with the `nullable` field set to `null` (proves the 3.0 normalization on the wire),
  and a **non-API** path (`/health`, outside the `/api` prefix) left untouched.
- Summary `failed: 0` and `OpenAPI positive-security verified on the wire.`

### B.5 Optional — see the contract-violation leaves block

Param/body violations are `violation_severity` (Warning), so they do not block under the default
config. To watch them block, raise the severity and send the matching request:

```toml
[enterprise.api_schema]
enabled   = true
spec_path = "scripts/api-schema-enforcement/openapi.json"
violation_severity = "critical"
```

```sh
# unknown body property (additionalProperties:false) → 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' \
  --data '{"name":"ada","isAdmin":true}' http://127.0.0.1:8080/api/users
# missing required body field → 403
curl -s -o /dev/null -w '%{http_code}\n' -X POST -H 'content-type: application/json' \
  --data '{"age":1}' http://127.0.0.1:8080/api/users
# mistyped path param (id must be integer) → 403
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/api/users/abc
# undeclared query param (strict_params) → 403
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8080/api/users/5?foo=bar'
```

The boundary holds even here: a **contract-valid** body carrying an injection value is NOT flagged by
this module — that string is a valid `name`; catching it is the OPEN §6 channel's job. On the
**assembled** enterprise pipeline both channels coexist (verified live): `{"name":"x' UNION SELECT
password FROM users--"}` on `POST /api/users` is contract-valid (this module → allow) yet **blocked by
the OPEN §6 SQLi detector** (403), while `GET /api/nope` is blocked by this module's unknown-route.

---

## C. Discovery — API attack-surface inventory (control plane)

The enforcement decisions this module emits become an **API inventory** in the control plane (§4-B pt3
discovery, off-datapath). Point `[controlplane.api_inventory].spec_path` at the SAME OpenAPI JSON, and
the control plane classifies the endpoints seen in `decision_events` (denied traffic only) against it.

```toml
# controlplane.toml
[controlplane.api_inventory]
spec_path = "scripts/api-schema-enforcement/openapi.json"
```

```sh
# Endpoints observed in enforcement decisions, templated (/users/{}) + classified:
curl -s -H "authorization: Bearer $WAF_CP_API_TOKEN" http://127.0.0.1:8090/api/inventory
#   → [{"method":"GET","path":"/api/users/{}","classification":"documented","hits":2,…},
#      {"method":"GET","path":"/api/secrets","classification":"shadow","hits":1,…}]
# Drift only (the undeclared "shadow" surface being hit):
curl -s -H "authorization: Bearer $WAF_CP_API_TOKEN" http://127.0.0.1:8090/api/inventory/drift
```

In the dashboard this is the **"API Inventory"** view (Monitor group): per-id paths fold into one
endpoint, `shadow` (undeclared) vs `documented` (declared, drawing blocks), with a shadow-only filter.
Caveat: `decision_events` holds **denied requests only**, so this is the observed attack surface, not
an all-traffic inventory — zombie (declared-but-unused) detection is a follow-on.

---

## Troubleshooting

- **Unknown-route rows MISS** — the module isn't active: check the boot log for `wiring OpenAPI
  positive-security module`; confirm `enabled = true`, `mode = "blocking"`, `block_threshold <= 6`, and
  that the request path falls under a `paths` prefix.
- **Boot fails with `API schema-enforcement: cannot read OpenAPI spec …`** — `spec_path` is
  wrong/missing (relative paths resolve from the run dir). Deliberate fail-closed boot error.
- **Boot fails with `… spec is not valid JSON`** — you passed a YAML spec. v1 is JSON-only; convert it
  (`yq -o=json`, or any OpenAPI tool) and point `spec_path` at the JSON.
- **Boot fails with `… schema does not compile`** — a parameter/body schema is not valid JSON Schema
  (e.g. an invalid `pattern` regex). Fix the spec; the compile is boot-fatal on purpose.
- **A legit request is blocked (`FALSE +`)** — usually **schema drift** (the app deployed a newer spec
  than the WAF's copy). Update `spec_path`. If it is a query-param the client legitimately sends but the
  spec omits, either add it to the spec or set `strict_params = false`.
- **Everything MISSes** — confirm the WAF booted (`listening (enterprise)`) and the port matches `PORT`.
