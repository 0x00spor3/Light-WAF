// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";
import { fmtTime, statusColor } from "../theme";

const PLACEHOLDER =
  'SecRule ARGS "@rx (?i)attackpattern" "id:9001,phase:2,severity:CRITICAL,block,msg:\'blocked\'"';

/// §7 write-path: version the ONE managed SecRule `.conf`, publish new versions, roll back to an old
/// one, and watch per-node convergence. Publish/rollback require ManageRules (operator+); the backend
/// enforces it — this view is only shown to callers who have it.
export function Rules() {
  const versions = useApi(() => api.ruleVersions());
  const nodes = useApi(() => api.ruleNodes());

  const [content, setContent] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function publish(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await api.publishRule(content, note.trim());
      setNote("");
      versions.reload();
      nodes.reload();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function loadIntoEditor(id: number) {
    try {
      const v = await api.ruleVersion(id);
      setContent(v.content);
      setNote(v.note);
    } catch (err) {
      alert(String(err));
    }
  }

  async function rollback(id: number) {
    if (!confirm(`Roll back the live ruleset to version ${id}?`)) return;
    try {
      await api.rollbackRule(id);
      versions.reload();
      nodes.reload();
    } catch (err) {
      alert(String(err));
    }
  }

  const editor = (
    <Panel
      title="Publish a ruleset version"
      subtitle="The managed SecRule .conf pushed to every node (validated, then hot-reloaded)"
    >
      <form className="rule-editor" onSubmit={publish}>
        <textarea
          className="mono"
          rows={12}
          placeholder={PLACEHOLDER}
          value={content}
          onChange={(e) => setContent(e.target.value)}
        />
        <div className="filters">
          <input
            placeholder="change note (optional)"
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <button type="submit" disabled={busy || !content.trim()}>
            Publish &amp; make current
          </button>
          {formError && <span className="error">{formError}</span>}
        </div>
      </form>
    </Panel>
  );

  const versionsPanel = (
    <Panel title="Versions" subtitle="Immutable history; the current one is live on the cluster">
      {versions.loading ? (
        <Loading />
      ) : versions.error ? (
        <ErrorState error={versions.error} onRetry={versions.reload} />
      ) : !versions.data || versions.data.length === 0 ? (
        <Empty label="No versions published yet." />
      ) : (
        <table className="rows-hover">
          <thead>
            <tr>
              <th>Version</th>
              <th>Author</th>
              <th>Note</th>
              <th>Published</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {versions.data.map((v) => (
              <tr key={v.id}>
                <td className="mono">
                  #{v.id}{" "}
                  {v.current && (
                    <span className="badge" style={{ ["--c" as string]: statusColor("current") }}>
                      current
                    </span>
                  )}
                </td>
                <td className="mono">{v.author}</td>
                <td className="muted">{v.note || "—"}</td>
                <td className="muted nowrap">{fmtTime(v.created_at)}</td>
                <td className="actions">
                  <button className="ghost" onClick={() => loadIntoEditor(v.id)}>
                    Load into editor
                  </button>
                  {!v.current && (
                    <button className="ghost" onClick={() => rollback(v.id)}>
                      Roll back to this
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );

  const convergence = (
    <Panel title="Node convergence" subtitle="The version each node has applied, and its last outcome">
      {nodes.loading ? (
        <Loading />
      ) : nodes.error ? (
        <ErrorState error={nodes.error} onRetry={nodes.reload} />
      ) : !nodes.data || nodes.data.length === 0 ? (
        <Empty label="No nodes have reported yet." />
      ) : (
        <table className="rows-hover">
          <thead>
            <tr>
              <th>Node</th>
              <th>Applied version</th>
              <th>Status</th>
              <th>Detail</th>
              <th>Reported</th>
            </tr>
          </thead>
          <tbody>
            {nodes.data.map((n) => (
              <tr key={n.node}>
                <td className="mono">{n.node}</td>
                <td className="mono">{n.applied_version !== null ? `#${n.applied_version}` : "—"}</td>
                <td>
                  <span className="badge" style={{ ["--c" as string]: statusColor(n.status) }}>
                    {n.status}
                  </span>
                </td>
                <td className="muted">{n.detail || "—"}</td>
                <td className="muted nowrap">{fmtTime(n.reported_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );

  return (
    <div className="stack">
      {editor}
      {versionsPanel}
      {convergence}
    </div>
  );
}
