import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ShieldAlert } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { Card } from "../components/ui/Card";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { fetchIncidents } from "../lib/api";
import type { Incident } from "../types";

const CATEGORIES = ["Reconnaissance", "Credential Attacks", "Network Attacks", "Malware Behaviors", "Data Theft", "Unknown Threats"];
const SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const STATUSES = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];

function timeAgo(ts: number): string {
  const seconds = Math.max(Math.floor(Date.now() / 1000 - ts), 0);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function Threats() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [category, setCategory] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const data = await fetchIncidents({
          category: category || undefined,
          severity: severity || undefined,
          status: status || undefined,
          limit: 200,
        });
        if (!cancelled) setIncidents(data);
      } finally {
        if (!cancelled) setLoaded(true);
      }
    }
    load();
    const id = setInterval(load, 6000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [category, severity, status]);

  return (
    <AppShell title="Threats">
      <div className="mb-4 flex flex-wrap gap-2">
        <Select value={category} onChange={setCategory} options={CATEGORIES} placeholder="All categories" />
        <Select value={severity} onChange={setSeverity} options={SEVERITIES} placeholder="All severities" />
        <Select value={status} onChange={setStatus} options={STATUSES} placeholder="All statuses" />
      </div>

      <Card>
        {loaded && incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center text-ink-700">
            <ShieldAlert size={24} strokeWidth={1.5} />
            <p className="text-sm">No threats match these filters</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-base-700 text-left text-xs uppercase tracking-wide text-ink-500">
                <th className="px-5 py-3 font-medium">Attack</th>
                <th className="px-5 py-3 font-medium">Source</th>
                <th className="px-5 py-3 font-medium">Destination</th>
                <th className="px-5 py-3 font-medium">Confidence</th>
                <th className="px-5 py-3 font-medium">Severity</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Detected</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {incidents.map((i) => (
                <tr key={i.id} className="transition-colors hover:bg-base-800/60">
                  <td className="px-5 py-3">
                    <Link to={`/threats/${i.id}`} className="font-medium text-ink-100 hover:text-signal-400">
                      {i.attack_type}
                    </Link>
                    <p className="text-xs text-ink-700">{i.category}</p>
                  </td>
                  <td className="px-5 py-3 font-mono text-ink-300">{i.source_ip}</td>
                  <td className="px-5 py-3 font-mono text-ink-500">{i.destination_ip ?? "—"}</td>
                  <td className="px-5 py-3 font-mono text-ink-300">{Math.round(i.confidence * 100)}%</td>
                  <td className="px-5 py-3">
                    <SeverityBadge severity={i.severity} />
                  </td>
                  <td className="px-5 py-3">
                    <StatusBadge status={i.status} />
                  </td>
                  <td className="px-5 py-3 text-xs text-ink-500">{timeAgo(i.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </AppShell>
  );
}

function Select({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string;
  onChange: (v: string) => void;
  options: string[];
  placeholder: string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-xs font-medium text-ink-300 outline-none focus:border-signal-500"
    >
      <option value="">{placeholder}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {o.replace("_", " ")}
        </option>
      ))}
    </select>
  );
}
