# waf-node-agent (enterprise, BSL 1.1)

Per-node **rule-management agent** for Light WAF (`ARCHITECTURE_ENTERPRISE.md` §7, write-path v3). It is
the pull side of the write path: it polls the control plane for the current managed ruleset, and when a
new version appears it **pre-validates** the content with the OPEN seclang parser, writes it **atomically**
to the managed `.conf` the WAF loads (`[modules.crs].files`), and runs a configurable `reload_command`
(a SIGHUP) so the WAF hot-reloads it (**validate-then-swap**). Then it reports the outcome so the control
plane's per-node convergence view is truthful.

- **Zero-core.** The agent writes a file the core already reads and triggers the core's existing SIGHUP
  reload — nothing in the datapath changes. It links `waf-detection` (OPEN) **only** to pre-validate; it
  never sits on the request path.
- **Two fail-safe levels.** (1) The agent refuses to touch the WAF if the ruleset does not parse into the
  supported subset. (2) The WAF's own reload does validate-then-swap (a bad file keeps the last-good rules).

## Configure + run

```toml
# node-agent.toml
[agent]
control_plane_url = "http://127.0.0.1:9600"
node_name = "edge-1"
managed_file = "/etc/waf/managed.conf"            # SAME path as the WAF's [modules.crs].files
reload_command = "kill -HUP $(cat /run/waf.pid)"  # or "systemctl reload waf"
poll_interval_seconds = 15
```

```sh
export WAF_AGENT_TOKEN='svc-token'    # a §8 control-plane service token (any role; rules are not secret)
cargo run -p waf-node-agent -- node-agent.toml
```

Each poll: `GET /api/rules/current` → if the version is new, pre-validate → **valid**: write + reload +
`POST /api/rules/status {applied}`; **invalid**: `POST {rejected, detail}` and leave the WAF untouched.

## Tests

```sh
cargo test -p waf-node-agent                    # unit: validate (valid/invalid/empty), atomic write
WAF_CP_DATABASE_URL=postgres://postgres:pw@localhost:5432/postgres \
  cargo test -p waf-node-agent --test e2e       # env-gated: publish → agent → in-process reload → block
```

See `scripts/controlplane/RUNBOOK.md` §I for the full operator flow (managed file, publish/rollback,
convergence, UI).
