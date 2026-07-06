// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useState } from "react";
import { api, type VerifyResult } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, Loading, Panel } from "../components/ui";
import { fmtTime } from "../theme";

export function Audit() {
  const { data, loading, error, reload } = useApi(() => api.audit(200));
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifying, setVerifying] = useState(false);

  async function runVerify() {
    setVerifying(true);
    try {
      setVerify(await api.verifyAudit());
    } catch (err) {
      alert(String(err));
    } finally {
      setVerifying(false);
    }
  }

  const actions = (
    <button onClick={runVerify} disabled={verifying}>
      {verifying ? "Verifying…" : "Verify chain"}
    </button>
  );

  return (
    <Panel title="Audit log" subtitle="Signed, hash-chained operator actions" actions={actions}>
      {verify && (
        <div className={verify.ok ? "verify-banner ok" : "verify-banner bad"}>
          {verify.ok ? (
            <>
              ✓ Chain verified — {verify.count} records signed by{" "}
              <code className="mono">{verify.public_key.slice(0, 16)}…</code>
            </>
          ) : (
            <>
              ⚠ Verification FAILED at seq {verify.broken_seq}: {verify.reason}
            </>
          )}
        </div>
      )}
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No audit records." />
      ) : (
        <div className="table-wrap">
          <table className="rows-hover">
            <thead>
              <tr>
                <th className="num">Seq</th>
                <th>Time</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Target</th>
              </tr>
            </thead>
            <tbody>
              {data.map((r) => (
                <tr key={r.seq}>
                  <td className="num">{r.seq}</td>
                  <td className="muted nowrap">{fmtTime(r.ts)}</td>
                  <td className="mono">{r.actor}</td>
                  <td className="mono">{r.action}</td>
                  <td className="mono muted">{r.target ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}
