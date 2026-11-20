// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { api, type AlertDetail as AlertDetailDto } from "../api";
import { useApi } from "../hooks/useApi";
import { DecisionBadge, Empty, ErrorState, Loading, Panel, SeverityBadge } from "../components/ui";
import { fmtTime } from "../theme";
import { matchSummary } from "./Alerts";

const PAGE = 50;

export function AlertDetail() {
  const { id = "" } = useParams();
  const alertId = Number(id);
  const { data, loading, error, reload } = useApi(() => api.alert(alertId), [alertId]);

  return (
    <div className="stack">
      <div className="crumbs">
        <Link to="/alerts">← Alerts</Link>
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
          <AlertSummary alert={data} />
          {data.match_source !== "unavailable" && <AlertEventsPanel alert={data} />}
        </>
      )}
    </div>
  );
}

function AlertSummary({ alert }: { alert: AlertDetailDto }) {
  const m = alert.match;
  return (
    <Panel title="Alert" subtitle={`#${alert.id} · ${alert.rule_name}`}>
      <dl className="kv">
        <div>
          <dt>Rule</dt>
          <dd className="mono">{alert.rule_name}</dd>
        </div>
        <div>
          <dt>Group</dt>
          <dd className="mono">{m && m.group_by !== "none" ? `${m.group_by}=${alert.group_key || "—"}` : "—"}</dd>
        </div>
        <div>
          <dt>Severity</dt>
          <dd>
            <SeverityBadge severity={alert.severity} />
          </dd>
        </div>
        <div>
          <dt>Fired at</dt>
          <dd className="mono">{fmtTime(alert.fired_at)}</dd>
        </div>
        <div>
          <dt>Value / Threshold</dt>
          <dd className="mono">
            <span className="over">{alert.value}</span> / {alert.threshold}
          </dd>
        </div>
        <div>
          <dt>Window</dt>
          <dd className="mono">
            {m && alert.window_start
              ? `${fmtTime(alert.window_start)} → ${fmtTime(alert.fired_at)} (${m.window_seconds}s)`
              : "—"}
          </dd>
        </div>
        <div>
          <dt>Match</dt>
          <dd className="muted">{m ? matchSummary(m.decision, m.rule_id, m.client_ip) : "—"}</dd>
        </div>
        <div>
          <dt>Now</dt>
          <dd>
            {m && alert.current ? (
              <>
                <span className={alert.current.above_threshold ? "over" : undefined}>{alert.current.count}</span>{" "}
                matching events in the last {m.window_seconds}s —{" "}
                {alert.current.above_threshold ? "still above threshold" : "below threshold"}
              </>
            ) : (
              "—"
            )}
          </dd>
        </div>
      </dl>
      {alert.match_source === "current_config" && (
        <p className="alert-notice">
          This alert fired before rule snapshots were stored, so its events are selected with the rule
          as it is configured now. If the rule changed since, the events below may not be the ones that
          fired it.
        </p>
      )}
      {alert.match_source === "unavailable" && (
        <p className="alert-notice">
          This alert fired before rule snapshots were stored and no rule named{" "}
          <code className="mono">{alert.rule_name}</code> is configured any more, so the events behind
          it cannot be resolved.
        </p>
      )}
    </Panel>
  );
}

function AlertEventsPanel({ alert }: { alert: AlertDetailDto }) {
  const [offset, setOffset] = useState(0);
  const navigate = useNavigate();
  const { data, loading, error, reload } = useApi(
    () => api.alertEvents(alert.id, PAGE, offset),
    [alert.id, offset],
  );

  const total = data?.total ?? 0;
  const pager =
    data && total > PAGE ? (
      <div className="pager">
        <button className="ghost" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>
          ← Newer
        </button>
        <span className="muted">
          {offset + 1}–{Math.min(offset + PAGE, total)} of {total}
        </span>
        <button className="ghost" disabled={offset + PAGE >= total} onClick={() => setOffset(offset + PAGE)}>
          Older →
        </button>
      </div>
    ) : undefined;

  return (
    <Panel
      title="Events"
      subtitle="Denied requests in the window that matched the rule and the fired group, newest first"
      actions={pager}
    >
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.events.length === 0 ? (
        <Empty label="No matching events are stored any more (pruned by retention)." />
      ) : (
        <>
          {total !== alert.value && (
            <p className="muted" style={{ marginTop: 0 }}>
              {total} events match now; the alert counted {alert.value} when it fired. The difference is
              events that arrived after the evaluation or were since removed by retention.
            </p>
          )}
          <div className="table-wrap">
            <table className="rows-hover">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Node</th>
                  <th>Method</th>
                  <th>Path</th>
                  <th>Client IP</th>
                  <th>Decision</th>
                  <th>Rule</th>
                  <th className="num">Score</th>
                </tr>
              </thead>
              <tbody>
                {data.events.map((ev) => (
                  <tr
                    key={ev.request_id}
                    className="clickable"
                    onClick={() => navigate(`/events/${encodeURIComponent(ev.request_id)}`)}
                  >
                    <td className="muted nowrap">{fmtTime(ev.ts)}</td>
                    <td>{ev.node}</td>
                    <td>{ev.method ?? "—"}</td>
                    <td className="path" title={ev.path ?? ""}>
                      {ev.path ?? "—"}
                    </td>
                    <td className="mono">{ev.client_ip ?? "—"}</td>
                    <td>
                      <DecisionBadge decision={ev.decision} />
                    </td>
                    <td className="mono">{ev.rule_id ?? "—"}</td>
                    <td className="num">{ev.score}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Panel>
  );
}
