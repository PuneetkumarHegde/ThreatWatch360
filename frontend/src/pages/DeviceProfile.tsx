import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Laptop2 } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { SeverityBadge } from "../components/ui/Badge";
import { fetchDevice, fetchIncidents } from "../lib/api";
import type { Device, Incident } from "../types";

export default function DeviceProfile() {
  const { mac } = useParams<{ mac: string }>();
  const [device, setDevice] = useState<Device | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    if (!mac) return;
    let cancelled = false;
    async function load() {
      try {
        const d = await fetchDevice(mac!);
        if (cancelled) return;
        setDevice(d);
        const [srcIncidents, dstIncidents] = await Promise.all([
          fetchIncidents({ source_ip: d.ip_address, limit: 50 }),
          fetchIncidents({ limit: 200 }),
        ]);
        if (cancelled) return;
        const related = [...srcIncidents, ...dstIncidents.filter((i) => i.destination_ip === d.ip_address)];
        const unique = Array.from(new Map(related.map((i) => [i.id, i])).values()).sort(
          (a, b) => b.timestamp - a.timestamp
        );
        setIncidents(unique);
      } catch {
        if (!cancelled) setNotFound(true);
      }
    }
    load();
    return () => {
      cancelled = true;
    };
  }, [mac]);

  return (
    <AppShell title="Device Profile">
      <Link to="/devices" className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-ink-500 hover:text-ink-100">
        <ArrowLeft size={14} /> Back to Devices
      </Link>

      {notFound && <Card className="p-8 text-center text-sm text-ink-500">Device not found.</Card>}

      {device && (
        <>
          <Card className="mb-4">
            <CardBody className="flex items-center gap-4">
              <div className="rounded-xl bg-base-700/60 p-3 text-signal-400">
                <Laptop2 size={22} strokeWidth={1.75} />
              </div>
              <div className="grid flex-1 grid-cols-2 gap-4 sm:grid-cols-4">
                <Field label="Hostname" value={device.hostname ?? "Unknown"} />
                <Field label="IP Address" value={device.ip_address} mono />
                <Field label="MAC Address" value={device.mac_address} mono />
                <Field label="Vendor" value={device.vendor ?? "Unknown"} />
                <Field label="OS" value={device.os_guess ?? "Unknown"} />
                <Field label="Status" value={device.status} />
                <Field label="Risk Score" value={String(device.risk_score)} mono />
                <Field label="First Seen" value={new Date(device.first_seen * 1000).toLocaleString()} />
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Detected Activity ({incidents.length})</CardTitle>
            </CardHeader>
            <CardBody className="p-0">
              {incidents.length === 0 ? (
                <p className="p-5 text-sm text-ink-500">No incidents involving this device.</p>
              ) : (
                <ul className="divide-y divide-base-700">
                  {incidents.map((i) => (
                    <li key={i.id}>
                      <Link
                        to={`/threats/${i.id}`}
                        className="flex items-center justify-between gap-4 px-5 py-3 hover:bg-base-800/60"
                      >
                        <div className="min-w-0">
                          <p className="truncate text-sm font-medium text-ink-100">{i.attack_type}</p>
                          <p className="truncate font-mono text-xs text-ink-500">
                            {i.source_ip} {i.destination_ip ? `→ ${i.destination_ip}` : ""}
                          </p>
                        </div>
                        <SeverityBadge severity={i.severity} />
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>
        </>
      )}
    </AppShell>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-ink-500">{label}</p>
      <p className={`mt-0.5 text-sm text-ink-100 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}
