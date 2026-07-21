import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip } from "recharts";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { fetchIncidentStats } from "../lib/api";
import type { IncidentStats } from "../types";

const RANGES = [
  { label: "24 Hours", seconds: 86400 },
  { label: "7 Days", seconds: 604800 },
  { label: "30 Days", seconds: 2592000 },
];

export default function Analytics() {
  const [range, setRange] = useState(RANGES[0]);
  const [stats, setStats] = useState<IncidentStats | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchIncidentStats(range.seconds).then((s) => {
      if (!cancelled) setStats(s);
    });
    return () => {
      cancelled = true;
    };
  }, [range]);

  const categoryData = Object.entries(stats?.by_category ?? {}).map(([name, count]) => ({ name, count }));
  const severityData = Object.entries(stats?.by_severity ?? {}).map(([name, count]) => ({ name, count }));

  return (
    <AppShell title="Analytics">
      <div className="mb-4 flex gap-2">
        {RANGES.map((r) => (
          <button
            key={r.label}
            onClick={() => setRange(r)}
            className={`rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors ${
              range.label === r.label
                ? "border-signal-500/40 bg-signal-500/15 text-signal-400"
                : "border-base-600 bg-base-800 text-ink-500 hover:text-ink-100"
            }`}
          >
            {r.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Incidents by Category</CardTitle>
          </CardHeader>
          <CardBody className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData} layout="vertical" margin={{ left: 12 }}>
                <CartesianGrid stroke="var(--color-base-700)" strokeDasharray="3 3" horizontal={false} />
                <XAxis type="number" stroke="var(--color-ink-700)" fontSize={11} allowDecimals={false} />
                <YAxis type="category" dataKey="name" stroke="var(--color-ink-500)" fontSize={11} width={110} />
                <Tooltip contentStyle={{ background: "#0f141c", border: "1px solid #1b2431", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="var(--color-signal-500)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Incidents by Severity</CardTitle>
          </CardHeader>
          <CardBody className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid stroke="var(--color-base-700)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="name" stroke="var(--color-ink-500)" fontSize={11} />
                <YAxis stroke="var(--color-ink-700)" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0f141c", border: "1px solid #1b2431", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="count" fill="var(--color-sev-high)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Top Attackers</CardTitle>
          </CardHeader>
          <CardBody className="p-0">
            {(stats?.top_attackers.length ?? 0) === 0 ? (
              <p className="p-5 text-sm text-ink-500">No attacker data for this range.</p>
            ) : (
              <ul className="divide-y divide-base-700">
                {stats!.top_attackers.map((a, idx) => (
                  <li key={a.ip} className="flex items-center justify-between px-5 py-3">
                    <div className="flex items-center gap-3">
                      <span className="w-5 text-xs text-ink-700">{idx + 1}</span>
                      <span className="font-mono text-sm text-ink-100">{a.ip}</span>
                    </div>
                    <span className="font-mono text-sm text-ink-500">{a.count} incidents</span>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
    </AppShell>
  );
}
