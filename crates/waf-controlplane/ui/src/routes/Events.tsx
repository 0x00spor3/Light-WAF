// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { useNavigate } from "react-router";
import { api } from "../api";
import { useApi } from "../hooks/useApi";
import { useLiveStream } from "../hooks/useLiveStream";
import { DecisionBadge, Empty, ErrorState, LiveIndicator, Loading, Panel } from "../components/ui";
import { fmtTime } from "../theme";

interface Filters {
  rule_id: string;
  decision: string;
  client_ip: string;
  limit: number;
}

const EMPTY: Filters = { rule_id: "", decision: "", client_ip: "", limit: 100 };

export function Events() {
  // `applied` drives the query; the form edits a draft until submitted.
  const [applied, setApplied] = useState<Filters>(EMPTY);
  const [draft, setDraft] = useState<Filters>(EMPTY);
  const navigate = useNavigate();

  const { data, loading, error, reload, refresh, lastUpdated } = useApi(
    () =>
      api.events({
        rule_id: applied.rule_id || undefined,
        decision: applied.decision || undefined,
        client_ip: applied.client_ip || undefined,
        limit: applied.limit,
      }),
    [applied.rule_id, applied.decision, applied.client_ip, applied.limit],
    // SSE (below) refreshes the instant new events are ingested; this slow poll is just a fallback
    // in case the stream is blocked (e.g. a buffering proxy).
    { pollMs: 20_000 },
  );

  // Live: refresh the moment the control plane ingests new decision events.
  useLiveStream("events", refresh);

  function submit(e: React.FormEvent) {
    e.preventDefault();
    setApplied(draft);
  }
  function clear() {
    setDraft(EMPTY);
    setApplied(EMPTY);
  }

  const form = (
    <form className="filters" onSubmit={submit}>
      <input
        placeholder="rule_id"
        value={draft.rule_id}
        onChange={(e) => setDraft({ ...draft, rule_id: e.target.value })}
      />
      <select value={draft.decision} onChange={(e) => setDraft({ ...draft, decision: e.target.value })}>
        <option value="">any decision</option>
        <option value="blocked">blocked</option>
        <option value="rejected">rejected</option>
      </select>
      <input
        placeholder="client_ip"
        value={draft.client_ip}
        onChange={(e) => setDraft({ ...draft, client_ip: e.target.value })}
      />
      <input
        type="number"
        min={1}
        max={1000}
        value={draft.limit}
        onChange={(e) => setDraft({ ...draft, limit: Number(e.target.value) || 100 })}
        title="limit"
        style={{ width: 90 }}
      />
      <button type="submit">Search</button>
      <button type="button" className="ghost" onClick={clear}>
        Clear
      </button>
    </form>
  );

  const actions = (
    <div className="actions-group">
      <LiveIndicator at={lastUpdated} />
      {form}
    </div>
  );

  return (
    <Panel title="Denied requests" subtitle="Search blocked / rejected events, newest first" actions={actions}>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No matching events." />
      ) : (
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
              {data.map((ev) => (
                <tr key={ev.request_id} className="clickable" onClick={() => navigate(`/events/${ev.request_id}`)}>
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
      )}
    </Panel>
  );
}
