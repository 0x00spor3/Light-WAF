<!-- SPDX-FileCopyrightText: 2026 0x00spor3
     SPDX-License-Identifier: BUSL-1.1 -->

# 5. Rule management

Governed rule management lets you change the WAF's rules from the dashboard — with versioning,
rollback, an audit trail, and per-node convergence — **without touching the WAF's code path**. The
control plane versions one managed SecRule `.conf`; a small agent on each node pulls it and triggers a
reload. Nothing about this is on the request path.

## The model

- The control plane owns **one managed ruleset file** per deployment.
- Every publish creates a new **immutable version** (id, author, note, timestamp). Versions are never
  edited or deleted.
- A single **current pointer** marks the live version. **Rollback** re-points it to an existing
  version — it does not create a new one.
- Each node reports its **applied version** and last outcome, so you can watch the cluster converge.

Publishing and rolling back require the `ManageRules` permission (operator or admin) and are recorded
in the [audit log](06-governance.md#the-audit-log). The agent-facing endpoints require only read
access.

## Two safety nets

A bad rule can never take the WAF down, because a new version is validated **twice**:

1. **The agent pre-validates** the ruleset with the same parser the WAF uses, *before* writing the
   file. An invalid version is rejected and the node reports `rejected` — the live file is untouched.
2. **The WAF validates-then-swaps** on reload: it parses the new file and only swaps it in if it's
   valid, keeping the last-good ruleset otherwise.

So an invalid publish converges to `rejected` on the nodes and the WAF keeps protecting with what it
had.

## Set up the agent

One `waf-node-agent` runs on each WAF node. The critical detail: its `managed_file` **must be the same
path** the WAF loads via `[modules.crs].files`. The agent overwrites that file atomically and runs
`reload_command` to signal the WAF (SIGHUP).

```toml
# node-agent.toml
[agent]
control_plane_url = "http://127.0.0.1:9600"
node_name         = "edge-1"                  # this node's identity in the convergence view
managed_file      = "/etc/waf/managed.conf"   # == the WAF's [modules.crs].files entry
reload_command    = "kill -HUP $(cat /run/waf.pid)"   # e.g. "systemctl reload waf"
poll_interval_seconds = 15
```

```sh
WAF_AGENT_TOKEN=<control-plane service token> waf-node-agent node-agent.toml
```

The token is any control-plane service token (rules are not secret — the agent needs read access to
pull the current version and to report status). Create one under [Tokens](06-governance.md#service-tokens).

## Publish a version

From the dashboard **Rules** view (operator or admin):

1. Paste the SecRule content into the editor and add a change note.
2. **Publish & make current** — the new version becomes the current pointer.
3. Watch **Node convergence**: each node picks up the change on its next poll, validates it, writes the
   file, reloads, and reports `applied` (or `rejected` with a reason if the ruleset was invalid).

Equivalently via the API:

```sh
# publish
curl -X POST "$CP/api/rules/versions" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"content":"SecRule ARGS \"@rx (?i)attack\" \"id:9001,phase:2,block\"","note":"block probe"}'

# see per-node convergence
curl "$CP/api/rules/nodes" -H "Authorization: Bearer $TOKEN"
```

## Roll back

In **Rules**, find an earlier version and choose **Roll back to this**. The current pointer moves to
that version; nodes converge to it on their next poll. Rollback is audited like a publish.

```sh
curl -X POST "$CP/api/rules/rollback" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d '{"version": 13}'
```

## Convergence outcomes

| Status | Meaning |
|---|---|
| `applied` | the node validated and reloaded the current version |
| `rejected` | the node found the version invalid; it kept the previous file (WAF unaffected) |
| `error` | the node hit an operational error (e.g. couldn't write the file or run the reload command) |

A healthy cluster shows every node `applied` at the current version. A `rejected` on one node with the
others `applied` usually means a node-local parser difference — check the detail message.

Next: [Governance & access control](06-governance.md).
