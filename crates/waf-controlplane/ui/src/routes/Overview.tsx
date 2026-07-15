// SPDX-FileCopyrightText: 2026 0x00spor3
// SPDX-License-Identifier: BUSL-1.1

import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api, type SeriesPoint } from "../api";
import { useApi } from "../hooks/useApi";
import { Empty, ErrorState, LiveIndicator, Loading, Panel, StatCard } from "../components/ui";
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
  background: "#161a24",
  border: "1px solid #2e3648",
  borderRadius: "8px",
  color: "#e6eaf2",
  fontFamily: "var(--font-mono)",
  fontSize: "0.8rem",
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

// Volume/latency/cluster tiles come from the Prometheus scraper (default 15s), so polling faster
// than the scrape cadence would just re-fetch the same snapshot.
const OVERVIEW_POLL_MS = 15_000;

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

/// Format a fraction as a percentage; more precision for tiny block rates so "0.04%" stays legible.
function fmtPct(frac: number): string {
  if (frac <= 0) return "0%";
  const digits = frac < 0.01 ? 2 : frac < 0.1 ? 1 : 1;
  return `${(frac * 100).toFixed(digits)}%`;
}

function VolumeSection() {
  const { data, loading, error, reload, lastUpdated } = useApi(() => api.decisionsVolume(), [], {
    pollMs: OVERVIEW_POLL_MS,
  });
  const s = useMemo(() => {
    const rows = data ?? [];
    const of = (k: string) => rows.find((d) => d.decision.toLowerCase() === k)?.total ?? 0;
    const allowed = of("allowed") + of("passed");
    const blocked = of("blocked");
    // The Prometheus counters classify a rejection by its HTTP disposition (`rate_limited` = 429,
    // `bad_request` = 400), whereas the decision-log calls both "rejected". Fold those metric
    // categories together so this tile matches the Events view (and never shows a phantom 0).
    const rejected = of("rejected") + of("rate_limited") + of("bad_request");
    const denied = blocked + rejected;
    const total = rows.reduce((sum, d) => sum + d.total, 0);
    return { allowed, blocked, rejected, denied, total, rate: total ? denied / total : 0 };
  }, [data]);

  return (
    <Panel
      title="Decision volumes"
      subtitle="Cumulative across the cluster (reset-aware — survives WAF restarts)"
      actions={<LiveIndicator at={lastUpdated} />}
    >
      {loading ? (
        <Loading />
      ) : error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data || data.length === 0 ? (
        <Empty label="No metrics scraped yet." />
      ) : (
        <>
          <div className="stat-row">
            <StatCard label="Total requests" value={fmtNum(s.total)} accent="#2fe0c0" />
            <StatCard label="Allowed" value={fmtNum(s.allowed)} accent={decisionColor("allowed")} />
            <StatCard label="Blocked" value={fmtNum(s.blocked)} accent={decisionColor("blocked")} />
            <StatCard label="Rejected" value={fmtNum(s.rejected)} accent={decisionColor("rejected")} />
            <StatCard label="Block rate" value={fmtPct(s.rate)} accent="#fb5468" />
          </div>
          <DispositionBars summary={s} />
        </>
      )}
    </Panel>
  );
}

/// Two proportion tracks (reusing the Verdict Meter aesthetic). The first shows how all traffic was
/// disposed — allowed vastly outweighs denied, so denied slivers keep a visible minimum width. The
/// second normalizes the denied traffic on its own, so the blocked/rejected mix stays readable even
/// when it's a fraction of a percent of the whole.
function DispositionBars({
  summary,
}: {
  summary: { allowed: number; blocked: number; rejected: number; denied: number; total: number; rate: number };
}) {
  const { allowed, blocked, rejected, denied, total } = summary;
  const seg = (v: number, color: string, min = 0) =>
    v <= 0 ? null : { pct: total ? Math.max((v / total) * 100, min) : 0, color };

  const disposition = [
    seg(allowed, decisionColor("allowed")),
    seg(blocked, decisionColor("blocked"), 3),
    seg(rejected, decisionColor("rejected"), 3),
  ].filter((x): x is { pct: number; color: string } => x !== null);

  return (
    <div className="stack" style={{ gap: "1.1rem" }}>
      <div className="meter">
        <div className="meter-head">
          <span className="eyebrow">Traffic disposition</span>
          <span className="meter-flag" style={{ color: decisionColor("blocked") }}>
            {fmtPct(summary.rate)} denied
          </span>
        </div>
        <div className="meter-track" role="img" aria-label="traffic disposition">
          {disposition.map((d, i) => (
            <span key={i} className="meter-seg" style={{ width: `${d.pct}%`, background: d.color }} />
          ))}
        </div>
        <div className="meter-legend">
          <span>
            <i style={{ background: decisionColor("allowed") }} />
            allowed {fmtNum(allowed)}
          </span>
          <span>
            <i style={{ background: decisionColor("blocked") }} />
            blocked {fmtNum(blocked)}
          </span>
          <span>
            <i style={{ background: decisionColor("rejected") }} />
            rejected {fmtNum(rejected)}
          </span>
        </div>
      </div>

      {denied > 0 && (
        <div className="meter">
          <div className="meter-head">
            <span className="eyebrow">Denied mix</span>
            <span className="meter-flag muted">{fmtNum(denied)} denied requests</span>
          </div>
          <div className="meter-track" role="img" aria-label="denied mix">
            <span
              className="meter-seg"
              style={{ width: `${(blocked / denied) * 100}%`, background: decisionColor("blocked") }}
            />
            <span
              className="meter-seg"
              style={{ width: `${(rejected / denied) * 100}%`, background: decisionColor("rejected") }}
            />
          </div>
        </div>
      )}
    </div>
  );
}

function SeriesSection() {
  const [range, setRange] = useState<RangePreset>(RANGES[1]);
  const { data, loading, error, reload, lastUpdated } = useApi(
    () => api.decisionsSeries(range.window, range.bucket),
    [range.window, range.bucket],
    { pollMs: OVERVIEW_POLL_MS },
  );

  const { rows, decisions } = useMemo(() => pivotSeries(data ?? []), [data]);

  const selector = (
    <div className="actions-group">
      <LiveIndicator at={lastUpdated} />
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
  const { data, loading, error, reload, lastUpdated } = useApi(() => api.latency(), [], {
    pollMs: OVERVIEW_POLL_MS,
  });

  const rows = useMemo(
    () => (data ?? []).map((l) => ({ node: l.node, p50: l.p50_ms, p95: l.p95_ms, p99: l.p99_ms })),
    [data],
  );

  return (
    <Panel
      title="Latency by node"
      subtitle="p50 / p95 / p99 (ms), lifetime (reset-aware)"
      actions={<LiveIndicator at={lastUpdated} />}
    >
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
  const { data, loading, error, reload, lastUpdated } = useApi(() => api.clusterStatus(), [], {
    pollMs: OVERVIEW_POLL_MS,
  });

  return (
    <Panel
      title="Cluster status"
      subtitle="Scraped nodes and last-seen"
      actions={<LiveIndicator at={lastUpdated} />}
    >
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
