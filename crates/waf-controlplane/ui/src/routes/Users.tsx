// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api, type Role } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";
import { fmtTime } from "../theme";

const ROLES: Role[] = ["viewer", "operator", "admin"];

export function Users() {
  const { data, loading, error, reload } = useApi(() => api.users());
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [busy, setBusy] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setFormError(null);
    try {
      await api.createUser(username.trim(), password, role);
      setUsername("");
      setPassword("");
      setRole("viewer");
      reload();
    } catch (err) {
      setFormError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function act(fn: () => Promise<unknown>) {
    try {
      await fn();
      reload();
    } catch (err) {
      alert(String(err));
    }
  }

  const form = (
    <form className="filters" onSubmit={create}>
      <input placeholder="username" value={username} onChange={(e) => setUsername(e.target.value)} />
      <input
        type="password"
        placeholder="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <select value={role} onChange={(e) => setRole(e.target.value as Role)}>
        {ROLES.map((r) => (
          <option key={r} value={r}>
            {r}
          </option>
        ))}
      </select>
      <button type="submit" disabled={busy || !username.trim() || !password}>
        Add user
      </button>
      {formError && <span className="error">{formError}</span>}
    </form>
  );

  return (
    <Panel title="Users" subtitle="Operator accounts + RBAC roles" actions={form}>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No users." />
      ) : (
        <table className="rows-hover">
          <thead>
            <tr>
              <th>Username</th>
              <th>Role</th>
              <th>Source</th>
              <th>Status</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.map((u) => (
              <tr key={u.id}>
                <td className="mono">{u.username}</td>
                <td>
                  <select
                    value={u.role}
                    onChange={(e) => act(() => api.updateUser(u.id, { role: e.target.value as Role }))}
                  >
                    {ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="muted">{u.auth_source}</td>
                <td>
                  {u.disabled ? <span className="badge" style={{ ["--c" as string]: "#ff5c5c" }}>disabled</span> : <span className="badge" style={{ ["--c" as string]: "#34d399" }}>active</span>}
                </td>
                <td className="muted nowrap">{fmtTime(u.created_at)}</td>
                <td className="actions">
                  <button className="ghost" onClick={() => act(() => api.updateUser(u.id, { disabled: !u.disabled }))}>
                    {u.disabled ? "Enable" : "Disable"}
                  </button>
                  {u.auth_source === "local" && (
                    <button
                      className="ghost"
                      onClick={() => {
                        const pw = prompt(`New password for ${u.username}:`);
                        if (pw) act(() => api.resetPassword(u.id, pw));
                      }}
                    >
                      Reset pw
                    </button>
                  )}
                  <button
                    className="ghost danger"
                    onClick={() => {
                      if (confirm(`Delete user ${u.username}?`)) act(() => api.deleteUser(u.id));
                    }}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}
