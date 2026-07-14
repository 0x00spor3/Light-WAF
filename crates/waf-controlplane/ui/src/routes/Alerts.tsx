// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { api } from "../api";
import { useApi } from "../hooks/useApi";
import { useLiveStream } from "../hooks/useLiveStream";
import { Empty, ErrorState, LiveIndicator, Loading, Panel, SeverityBadge } from "../components/ui";
import { fmtTime } from "../theme";

export function Alerts() {
  return (
    <div className="stack">
      <FiredAlerts />
      <ConfiguredRules />
    </div>
  );
}

function FiredAlerts() {
  // SSE pushes the moment the evaluator fires an alert; the slow poll is a fallback if the stream
  // is blocked. Alerts are still evaluator-cadence bound, so "instant" here means "as soon as fired".
  const { data, loading, error, reload, refresh, lastUpdated } = useApi(() => api.alerts(100), [], {
    pollMs: 30_000,
  });

  useLiveStream("alerts", refresh);

  return (
    <Panel title="Fired alerts" subtitle="Recent, newest first" actions={<LiveIndicator at={lastUpdated} />}>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No alerts have fired." />
      ) : (
        <table className="rows-hover">
          <thead>
            <tr>
              <th>Fired at</th>
              <th>Rule</th>
              <th>Group</th>
              <th>Severity</th>
              <th className="num">Value / Threshold</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {data.map((a, i) => (
              <tr key={`${a.rule_name}-${a.group_key}-${i}`}>
                <td className="muted nowrap">{fmtTime(a.fired_at)}</td>
                <td className="mono">{a.rule_name}</td>
                <td className="mono">{a.group_key || "—"}</td>
                <td>
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="num">
                  <span className="over">{a.value}</span> / {a.threshold}
                </td>
                <td className="muted">{a.summary}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function ConfiguredRules() {
  const { data, loading, error, reload } = useApi(() => api.alertRules());

  return (
    <Panel title="Configured rules" subtitle="Active alert definitions">
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No alert rules configured." />
      ) : (
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Match</th>
              <th>Group by</th>
              <th className="num">Threshold</th>
              <th className="num">Window</th>
              <th>Severity</th>
              <th className="num">Cooldown</th>
            </tr>
          </thead>
          <tbody>
            {data.map((r) => (
              <tr key={r.name}>
                <td className="mono">{r.name}</td>
                <td className="muted">{matchSummary(r.decision, r.rule_id, r.client_ip)}</td>
                <td>{r.group_by}</td>
                <td className="num">{r.threshold}</td>
                <td className="num">{r.window_seconds}s</td>
                <td>
                  <SeverityBadge severity={r.severity} />
                </td>
                <td className="num">{r.cooldown_seconds}s</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

function matchSummary(
  decision: string | null,
  ruleId: string | null,
  clientIp: string | null,
): string {
  const parts: string[] = [];
  if (decision) parts.push(`decision=${decision}`);
  if (ruleId) parts.push(`rule=${ruleId}`);
  if (clientIp) parts.push(`ip=${clientIp}`);
  return parts.length ? parts.join(" · ") : "any denied event";
}
