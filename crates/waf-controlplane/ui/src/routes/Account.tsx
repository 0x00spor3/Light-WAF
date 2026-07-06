// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";
import { fmtTime } from "../theme";

export function Account() {
  return (
    <div className="stack">
      <ChangePassword />
      <MySessions />
    </div>
  );
}

function ChangePassword() {
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setMsg(null);
    try {
      await api.changePassword(oldPw, newPw);
      setMsg({ ok: true, text: "Password changed — your other sessions were signed out." });
      setOldPw("");
      setNewPw("");
    } catch (err) {
      setMsg({ ok: false, text: String(err) });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Change password" subtitle="Local accounts only (SSO users manage their password at the IdP)">
      <form className="filters" onSubmit={submit}>
        <input
          type="password"
          placeholder="current password"
          value={oldPw}
          onChange={(e) => setOldPw(e.target.value)}
          autoComplete="current-password"
        />
        <input
          type="password"
          placeholder="new password"
          value={newPw}
          onChange={(e) => setNewPw(e.target.value)}
          autoComplete="new-password"
        />
        <button type="submit" disabled={busy || !oldPw || !newPw}>
          Update password
        </button>
        {msg && <span className={msg.ok ? "muted" : "error"}>{msg.text}</span>}
      </form>
    </Panel>
  );
}

function MySessions() {
  const { data, loading, error, reload } = useApi(() => api.sessions());

  async function revoke(id: string) {
    try {
      await api.revokeSession(id);
      reload();
    } catch (err) {
      alert(String(err));
    }
  }

  return (
    <Panel title="My sessions" subtitle="Active sessions for your account">
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No active sessions." />
      ) : (
        <table className="rows-hover">
          <thead>
            <tr>
              <th>Session</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.map((s) => (
              <tr key={s.id}>
                <td className="mono">
                  {s.id.slice(0, 12)}…{s.current && <span className="badge" style={{ ["--c" as string]: "#4f8cff", marginLeft: "0.4rem" }}>current</span>}
                </td>
                <td className="muted nowrap">{fmtTime(s.created_at)}</td>
                <td className="muted nowrap">{fmtTime(s.expires_at)}</td>
                <td className="actions">
                  {!s.current && (
                    <button className="ghost danger" onClick={() => revoke(s.id)}>
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
