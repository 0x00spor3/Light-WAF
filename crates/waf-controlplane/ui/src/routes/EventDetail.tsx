// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useApi } from "../hooks/useApi";
import { ErrorState, Loading, Panel, SeverityBadge, VerdictMeter } from "../components/ui";
import { fmtTime } from "../theme";

export function EventDetail() {
  const { id = "" } = useParams();
  const { data, loading, error, reload } = useApi(() => api.event(id), [id]);

  return (
    <div className="stack">
      <div className="crumbs">
        <Link to="/events">← Events</Link>
      </div>

      {loading ? (
        <Panel>
          <Loading />
        </Panel>
      ) : error ? (
        <Panel>
          <ErrorState error={error} onRetry={reload} />
        </Panel>
      ) : !data ? null : (
        <>
          <Panel title="Verdict" subtitle={data.request_id}>
            <VerdictMeter score={data.score} decision={data.decision} contributions={data.contributions} />
            <dl className="kv" style={{ marginTop: "1.25rem" }}>
              <div>
                <dt>Node</dt>
                <dd className="mono">{data.node}</dd>
              </div>
              <div>
                <dt>Time</dt>
                <dd className="mono">{fmtTime(data.ts)}</dd>
              </div>
              <div>
                <dt>Method</dt>
                <dd className="mono">{data.method ?? "—"}</dd>
              </div>
              <div>
                <dt>Path</dt>
                <dd className="mono wrap">{data.path ?? "—"}</dd>
              </div>
              <div>
                <dt>Client IP</dt>
                <dd className="mono">{data.client_ip ?? "—"}</dd>
              </div>
              <div>
                <dt>Rule</dt>
                <dd className="mono">{data.rule_id ?? "—"}</dd>
              </div>
              <div>
                <dt>Reason</dt>
                <dd>{data.reason ?? "—"}</dd>
              </div>
            </dl>
          </Panel>

          <Panel title="Score breakdown" subtitle="Per-rule contributions that produced the verdict">
            {data.contributions.length === 0 ? (
              <p className="muted">No per-rule contributions were recorded for this event.</p>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th>Module</th>
                    <th>Rule</th>
                    <th>Severity</th>
                    <th className="num">Points</th>
                  </tr>
                </thead>
                <tbody>
                  {data.contributions.map((c, i) => (
                    <tr key={`${c.module}-${c.rule_id}-${i}`}>
                      <td>{c.module}</td>
                      <td className="mono">{c.rule_id}</td>
                      <td>
                        <SeverityBadge severity={c.severity} />
                      </td>
                      <td className="num">{c.points}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Panel>
        </>
      )}
    </div>
  );
}
