import { useEffect, useState } from "react";
import { Activity, AlertTriangle, Gauge, Laptop2, ShieldAlert, Wifi } from "lucide-react";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts";
import { AppShell } from "../components/layout/AppShell";
import { StatCard } from "../components/ui/StatCard";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { SeverityBadge } from "../components/ui/Badge";
import { fetchDevices, fetchEngineStatus, fetchIncidentStats, fetchIncidents } from "../lib/api";
import type { Device, EngineStatus, Incident, IncidentStats } from "../types";

const CATEGORY_COLORS: Record<string, string> = {
  Reconnaissance: "#4c8bf5",
  "Credential Attacks": "#f5a623",
  "Network Attacks": "#ff7a45",
  "Malware Behaviors": "#ff4d4f",
  "Data Theft": "#b975ff",
  "Unknown Threats": "#57667c",
};

function timeAgo(ts: number): string {
  const seconds = Math.max(Math.floor(Date.now() / 1000 - ts), 0);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function overallThreatLevel(stats: IncidentStats | null): { label: string; tone: "ok" | "signal" | "critical" } {
  if (!stats || stats.total_incidents === 0) return { label: "Normal", tone: "ok" };
  const critical = stats.by_severity["CRITICAL"] ?? 0;
  const high = stats.by_severity["HIGH"] ?? 0;
  if (critical > 0) return { label: "Critical", tone: "critical" };
  if (high > 0) return { label: "Elevated", tone: "signal" };
  return { label: "Guarded", tone: "signal" };
}

export default function Dashboard() {
  const [stats, setStats] = useState<IncidentStats | null>(null);
  const [engine, setEngine] = useState<EngineStatus | null>(null);
  const [recent, setRecent] = useState<Incident[]>([]);
  const [devices, setDevices] = useState<Device[]>([]);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const [s, e, r, d] = await Promise.all([
          fetchIncidentStats(86400),
          fetchEngineStatus(),
          fetchIncidents({ limit: 8 }),
          fetchDevices(),
        ]);
        if (cancelled) return;
        setStats(s);
        setEngine(e);
        setRecent(r);
        setDevices(d);
      } catch {
        // handled inline by empty states below
      }
    }
    load();
    const id = setInterval(load, 5000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const threat = overallThreatLevel(stats);
  const onlineDevices = devices.filter((d) => d.status === "ONLINE").length;
  const categoryData = Object.entries(stats?.by_category ?? {}).map(([name, value]) => ({ name, value }));

  return (
    <AppShell title="Dashboard">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Threat Level"
          value={threat.label}
          icon={ShieldAlert}
          tone={threat.tone === "ok" ? "ok" : threat.tone === "critical" ? "critical" : "signal"}
          sublabel={`${stats?.total_incidents ?? 0} incidents / 24h`}
        />
        <StatCard
          label="Packets Captured"
          value={(engine?.packets_captured ?? 0).toLocaleString()}
          icon={Activity}
          tone="signal"
          sublabel={engine?.running ? `Live on ${engine.interface ?? "default"}` : "Capture stopped"}
        />
        <StatCard
          label="Connected Devices"
          value={onlineDevices}
          icon={Laptop2}
          sublabel={`${devices.length} discovered total`}
        />
        <StatCard
          label="Active Flows"
          value={engine?.active_flows ?? 0}
          icon={Wifi}
          sublabel={`${engine?.detections_total ?? 0} total detections`}
        />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Attack Distribution</CardTitle>
          </CardHeader>
          <CardBody className="h-64">
            {categoryData.length === 0 ? (
              <EmptyState icon={Gauge} text="No incidents in the last 24h" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={categoryData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={78} paddingAngle={2}>
                    {categoryData.map((entry) => (
                      <Cell key={entry.name} fill={CATEGORY_COLORS[entry.name] ?? "#3e7bfa"} stroke="none" />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "#0f141c", border: "1px solid #1b2431", borderRadius: 8, fontSize: 12 }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Recent Alerts</CardTitle>
          </CardHeader>
          <CardBody className="p-0">
            {recent.length === 0 ? (
              <div className="p-5">
                <EmptyState icon={AlertTriangle} text="No alerts yet — start capture from Live Monitor" />
              </div>
            ) : (
              <ul className="divide-y divide-base-700">
                {recent.map((incident) => (
                  <li key={incident.id} className="flex items-center justify-between gap-4 px-5 py-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium text-ink-100">{incident.attack_type}</p>
                      <p className="truncate font-mono text-xs text-ink-500">
                        {incident.source_ip}
                        {incident.destination_ip ? ` → ${incident.destination_ip}` : ""}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-3">
                      <span className="text-xs text-ink-700">{timeAgo(incident.timestamp)}</span>
                      <SeverityBadge severity={incident.severity} />
                    </div>
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

function EmptyState({ icon: Icon, text }: { icon: typeof Gauge; text: string }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 text-center text-ink-700">
      <Icon size={22} strokeWidth={1.5} />
      <p className="max-w-[220px] text-xs">{text}</p>
    </div>
  );
}
