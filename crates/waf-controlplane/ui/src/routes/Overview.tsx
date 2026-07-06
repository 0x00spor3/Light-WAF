// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, type SeriesPoint } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, Loading, Panel, StatCard } from "../components/ui";
import {
  CHART_AXIS,
  CHART_GRID,
  decisionColor,
  fmtClock,
  fmtNum,
  fmtTime,
  LATENCY_COLORS,
} from "../theme";

const TOOLTIP_STYLE = {
  background: "#12151b",
  border: "1px solid #2a2f3a",
  borderRadius: "8px",
  color: "#e6e9ef",
} as const;

interface RangePreset {
  label: string;
  window: number;
  bucket: number;
}
const RANGES: RangePreset[] = [
  { label: "1h", window: 3600, bucket: 60 },
  { label: "6h", window: 21600, bucket: 300 },
  { label: "24h", window: 86400, bucket: 3600 },
  { label: "7d", window: 604800, bucket: 3600 },
];

export function Overview() {
  return (
    <div className="stack">
      <VolumeSection />
      <div className="grid-2">
        <SeriesSection />
        <LatencySection />
      </div>
      <ClusterSection />
    </div>
  );
}

function VolumeSection() {
  const { data, loading, error, reload } = useApi(() => api.decisionsVolume());
  const total = useMemo(() => (data ?? []).reduce((s, d) => s + d.total, 0), [data]);

  return (
    <Panel title="Decision volumes" subtitle="Latest counter snapshot across the cluster">
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No metrics scraped yet." />
      ) : (
        <>
          <div className="stat-row">
            <StatCard label="Total requests" value={fmtNum(total)} accent="#4f8cff" />
            {data.map((d) => (
              <StatCard
                key={d.decision}
                label={d.decision}
                value={fmtNum(d.total)}
                accent={decisionColor(d.decision)}
              />
            ))}
          </div>
          <div className="chart" style={{ height: 240 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
                <CartesianGrid stroke={CHART_GRID} vertical={false} />
                <XAxis dataKey="decision" stroke={CHART_AXIS} tickLine={false} />
                <YAxis stroke={CHART_AXIS} tickLine={false} width={48} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "#ffffff08" }} />
                <Bar dataKey="total" radius={[6, 6, 0, 0]} isAnimationActive={false}>
                  {data.map((d) => (
                    <Cell key={d.decision} fill={decisionColor(d.decision)} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </>
      )}
    </Panel>
  );
}

function SeriesSection() {
  const [range, setRange] = useState<RangePreset>(RANGES[1]);
  const { data, loading, error, reload } = useApi(
    () => api.decisionsSeries(range.window, range.bucket),
    [range.window, range.bucket],
  );

  const { rows, decisions } = useMemo(() => pivotSeries(data ?? []), [data]);

  const selector = (
    <div className="segmented">
      {RANGES.map((r) => (
        <button
          key={r.label}
          className={r.label === range.label ? "seg active" : "seg"}
          onClick={() => setRange(r)}
        >
          {r.label}
        </button>
      ))}
    </div>
  );

  return (
    <Panel title="Denied events over time" subtitle="Bucketed decision counts" actions={selector}>
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : rows.length === 0 ? (
        <Empty label="No events in this window." />
      ) : (
        <div className="chart" style={{ height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
              <defs>
                {decisions.map((d) => (
                  <linearGradient key={d} id={`g-${d}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor={decisionColor(d)} stopOpacity={0.5} />
                    <stop offset="100%" stopColor={decisionColor(d)} stopOpacity={0.02} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid stroke={CHART_GRID} vertical={false} />
              <XAxis dataKey="t" tickFormatter={fmtClock} stroke={CHART_AXIS} tickLine={false} minTickGap={32} />
              <YAxis stroke={CHART_AXIS} tickLine={false} width={40} allowDecimals={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} labelFormatter={(v) => fmtTime(String(v))} />
              <Legend />
              {decisions.map((d) => (
                <Area
                  key={d}
                  type="monotone"
                  dataKey={d}
                  stackId="1"
                  stroke={decisionColor(d)}
                  fill={`url(#g-${d})`}
                  isAnimationActive={false}
                />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
  );
}

function LatencySection() {
  const { data, loading, error, reload } = useApi(() => api.latency());

  const rows = useMemo(
    () => (data ?? []).map((l) => ({ node: l.node, p50: l.p50_ms, p95: l.p95_ms, p99: l.p99_ms })),
    [data],
  );

  return (
    <Panel title="Latency by node" subtitle="p50 / p95 / p99 (ms), latest snapshot">
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : rows.length === 0 ? (
        <Empty label="No latency samples yet." />
      ) : (
        <div className="chart" style={{ height: 260 }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} margin={{ top: 8, right: 12, left: 0, bottom: 0 }}>
              <CartesianGrid stroke={CHART_GRID} vertical={false} />
              <XAxis dataKey="node" stroke={CHART_AXIS} tickLine={false} />
              <YAxis stroke={CHART_AXIS} tickLine={false} width={48} unit="ms" />
              <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: "#ffffff08" }} />
              <Legend />
              <Bar dataKey="p50" fill={LATENCY_COLORS[0]} radius={[4, 4, 0, 0]} isAnimationActive={false} />
              <Bar dataKey="p95" fill={LATENCY_COLORS[1]} radius={[4, 4, 0, 0]} isAnimationActive={false} />
              <Bar dataKey="p99" fill={LATENCY_COLORS[2]} radius={[4, 4, 0, 0]} isAnimationActive={false} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
  );
}

function ClusterSection() {
  const { data, loading, error, reload } = useApi(() => api.clusterStatus());

  return (
    <Panel title="Cluster status" subtitle="Scraped nodes and last-seen">
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No nodes reporting." />
      ) : (
        <table>
          <thead>
            <tr>
              <th>Node</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {data.map((n) => (
              <tr key={n.node}>
                <td>
                  <span className="dot online" /> {n.node}
                </td>
                <td className="muted">{fmtTime(n.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  );
}

/// Pivot flat `{t, decision, count}` rows into per-timestamp rows keyed by decision, for a stacked
/// area chart. Returns the sorted rows and the set of decisions seen.
function pivotSeries(points: SeriesPoint[]): {
  rows: Array<Record<string, number | string>>;
  decisions: string[];
} {
  const byT = new Map<string, Record<string, number | string>>();
  const decisions = new Set<string>();
  for (const p of points) {
    decisions.add(p.decision);
    const row = byT.get(p.t) ?? { t: p.t };
    row[p.decision] = (Number(row[p.decision] ?? 0) as number) + p.count;
    byT.set(p.t, row);
  }
  const rows = [...byT.values()].sort((a, b) => String(a.t).localeCompare(String(b.t)));
  return { rows, decisions: [...decisions] };
}
