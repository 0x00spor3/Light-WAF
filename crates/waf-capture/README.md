# waf-capture

Request capture for **[Light WAF](https://github.com/0x00spor3/Light-WAF)**: keep the **full**
HTTP request (method, path, query, headers, cookies, body) of every request the WAF blocks or
rejects, and ship it to the control plane so an operator can inspect it in the event drill-down.

The ordinary decision log carries only metadata; captured bodies travel on a separate channel and
never go through the logs.

## How it works

Three pieces, with no change to the core:

1. `CaptureModule` — a detection module that never scores: it clones each request into a bounded
   `CaptureRing` (by count, bytes and TTL), keyed by request id. Allowed requests simply age out.
2. `CaptureLayer` — a `tracing` layer that watches the WAF's `request blocked` / `request rejected`
   decision-log events and pulls the matching capture out of the ring.
3. `CaptureShipper` — a bounded queue with best-effort retry that POSTs captures to the control
   plane's `/ingest/captures`. On overflow it drops (with a metric and a log line); it never puts
   backpressure on the datapath.

With the `waf-enterprise` binary: `[enterprise.capture]` (`enabled`, `controlplane_url`,
`token_env`, `max_body_bytes`, ring and queue sizes). Default **off**.

## Privacy

Capture is raw by default, so it ships with defenses that are meant to be used together:

- **Node-side redaction** — `[enterprise.capture.redaction]` lists header names and body field
  names (JSON, recursively, and form-encoded) replaced by `***REDACTED***` before anything leaves
  the node;
- a **body size cap** (`max_body_bytes`);
- on the control plane: short, separate retention, and a dedicated permission (operator and admin
  roles) whose every use is recorded in the signed audit log.

Connection-phase rejects (rate limiting) and parser-limit 400s happen before inspection and are not
captured.

## License

Apache-2.0. Part of [Light WAF](https://github.com/0x00spor3/Light-WAF); see
[`ARCHITECTURE_ENTERPRISE.md`](https://github.com/0x00spor3/Light-WAF/blob/main/ARCHITECTURE_ENTERPRISE.md) §13.
