// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api, type CreatedToken, type Role } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";
import { fmtTime, statusColor } from "../theme";

const ROLES: Role[] = ["viewer", "operator", "admin"];

export function Tokens() {
  const { data, loading, error, reload } = useApi(() => api.tokens());
  const [name, setName] = useState("");
  const [role, setRole] = useState<Role>("operator");
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<CreatedToken | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const t = await api.createToken(name.trim(), role);
      setCreated(t); // show the plaintext once
      setName("");
      reload();
    } catch (err) {
      alert(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function revoke(id: number) {
    if (!confirm("Revoke this token?")) return;
    try {
      await api.revokeToken(id);
      reload();
    } catch (err) {
      alert(String(err));
    }
  }

  const form = (
    <form className="filters" onSubmit={create}>
      <input placeholder="token name" value={name} onChange={(e) => setName(e.target.value)} />
      <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
        {ROLES.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      <button type="submit" disabled={busy || !name.trim()}>
        Create token
      </button>
    </form>
  );

  return (
    <Panel title="Service tokens" subtitle="Named, revocable, role-bound API tokens" actions={form}>
      {created && (
        <div className="token-reveal">
          <div>
            <strong>{created.name}</strong> ({created.role}) — copy this token now; it is shown only once:
          </div>
          <code className="mono">{created.token}</code>
          <button className="ghost" onClick={() => setCreated(null)}>
            Dismiss
          </button>
        </div>
      )}
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No service tokens." />
      ) : (
        <table className="rows-hover">
          <thead>
            <tr>
              <th>Name</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.map((t) => (
              <tr key={t.id}>
                <td className="mono">{t.name}</td>
                <td>{t.role}</td>
                <td>
                  {t.revoked ? (
                    <span className="badge" style={{ ["--c" as string]: statusColor("revoked") }}>revoked</span>
                  ) : (
                    <span className="badge" style={{ ["--c" as string]: statusColor("active") }}>active</span>
                  )}
                </td>
                <td className="muted nowrap">{fmtTime(t.created_at)}</td>
                <td className="actions">
                  {!t.revoked && (
                    <button className="ghost danger" onClick={() => revoke(t.id)}>
                      Revoke
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
}
