import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Laptop2 } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { Card } from "../components/ui/Card";
import { fetchDevices } from "../lib/api";
import type { Device } from "../types";

function timeAgo(ts: number): string {
  const seconds = Math.max(Math.floor(Date.now() / 1000 - ts), 0);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export default function Devices() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const d = await fetchDevices();
        if (!cancelled) setDevices(d);
      } finally {
        if (!cancelled) setLoaded(true);
      }
    }
    load();
    const id = setInterval(load, 8000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  return (
    <AppShell title="Devices">
      <Card>
        {loaded && devices.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-16 text-center text-ink-700">
            <Laptop2 size={24} strokeWidth={1.5} />
            <p className="text-sm">No devices discovered yet</p>
            <p className="max-w-xs text-xs">
              Devices are discovered from ARP traffic once live capture is running. Start it from Live Monitor.
            </p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-base-700 text-left text-xs uppercase tracking-wide text-ink-500">
                <th className="px-5 py-3 font-medium">Device</th>
                <th className="px-5 py-3 font-medium">IP Address</th>
                <th className="px-5 py-3 font-medium">MAC Address</th>
                <th className="px-5 py-3 font-medium">Status</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Last Seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-base-700">
              {devices.map((d) => (
                <tr key={d.mac_address} className="transition-colors hover:bg-base-800/60">
                  <td className="px-5 py-3">
                    <Link to={`/devices/${d.mac_address}`} className="font-medium text-ink-100 hover:text-signal-400">
                      {d.hostname ?? d.vendor ?? "Unknown device"}
                    </Link>
                  </td>
                  <td className="px-5 py-3 font-mono text-ink-300">{d.ip_address}</td>
                  <td className="px-5 py-3 font-mono text-xs text-ink-500">{d.mac_address}</td>
                  <td className="px-5 py-3">
                    <span
                      className={`inline-flex items-center gap-1.5 text-xs font-medium ${
                        d.status === "ONLINE" ? "text-ok-500" : "text-ink-700"
                      }`}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${d.status === "ONLINE" ? "bg-ok-500" : "bg-ink-700"}`} />
                      {d.status}
                    </span>
                  </td>
                  <td className="px-5 py-3 font-mono text-ink-300">{d.risk_score}</td>
                  <td className="px-5 py-3 text-xs text-ink-500">{timeAgo(d.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </AppShell>
  );
}
