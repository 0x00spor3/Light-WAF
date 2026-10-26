// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: Apache-2.0

import { useMemo, useState } from "react";

import { api, ApiClassification } from "../api";
import { useApi } from "../hooks/useApi";
import { useLiveStream } from "../hooks/useLiveStream";
import { Empty, ErrorState, LiveIndicator, Loading, Panel, StatCard } from "../components/ui";
import { classificationColor, fmtNum, fmtTime } from "../theme";

type Filter = "all" | "shadow" | "documented";

/// API attack-surface inventory (§4-B pt3 discovery): the endpoints observed in enforcement
/// decisions (denied traffic only), templated and classified against the app's OpenAPI spec.
/// `shadow` = an undeclared endpoint being hit; `documented` = a declared endpoint drawing blocks.
export function Inventory() {
  const { data, loading, error, reload, refresh, lastUpdated } = useApi(() => api.inventory(), [], {
    pollMs: 30_000,
  });
  // The inventory is derived from denied events, so refresh the instant a new one is ingested.
  useLiveStream("events", refresh);

  const [filter, setFilter] = useState<Filter>("all");

  const rows = data ?? [];
  const shadow = rows.filter((e) => e.classification === "shadow").length;
  const documented = rows.filter((e) => e.classification === "documented").length;
  const shown = useMemo(
    () => (filter === "all" ? rows : rows.filter((e) => e.classification === filter)),
    [rows, filter],
  );

  return (
    <div className="stack">
      <div className="stat-row">
        <StatCard label="Endpoints seen" value={fmtNum(rows.length)} />
        <StatCard
          label="Shadow (undeclared)"
          value={fmtNum(shadow)}
          accent={classificationColor("shadow")}
        />
        <StatCard
          label="Documented"
          value={fmtNum(documented)}
          accent={classificationColor("documented")}
        />
      </div>

      <Panel
        title="API attack surface"
        subtitle="Endpoints seen in enforcement decisions — denied traffic only, per-id paths folded"
        actions={
          <div className="actions-group">
            <select value={filter} onChange={(e) => setFilter(e.target.value as Filter)}>
              <option value="all">All</option>
              <option value="shadow">Shadow only</option>
              <option value="documented">Documented only</option>
            </select>
            <LiveIndicator at={lastUpdated} />
          </div>
        }
      >
        {loading ? (
          <Loading />
        ) : error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : shown.length === 0 ? (
          <Empty label="No API endpoints observed in enforcement decisions yet." />
        ) : (
          <table className="rows-hover">
            <thead>
              <tr>
                <th>Method</th>
                <th>Path</th>
                <th>Classification</th>
                <th className="num">Hits</th>
                <th>First seen</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((e, i) => (
                <tr key={`${e.method}-${e.path}-${i}`}>
                  <td className="mono">{e.method}</td>
                  <td className="mono">{e.path}</td>
                  <td>
                    <ClassBadge c={e.classification} />
                  </td>
                  <td className="num">{fmtNum(e.hits)}</td>
                  <td className="muted nowrap">{fmtTime(e.first_seen)}</td>
                  <td className="muted nowrap">{fmtTime(e.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

/// A colored pill for an inventory classification.
function ClassBadge({ c }: { c: ApiClassification }) {
  return (
    <span className="badge" style={{ ["--c" as string]: classificationColor(c) }}>
      {c}
    </span>
  );
}
