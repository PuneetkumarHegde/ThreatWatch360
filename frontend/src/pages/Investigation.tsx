import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { ArrowLeft, Bot, ClipboardList, Crosshair, ShieldAlert, ShieldOff } from "lucide-react";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { SeverityBadge, StatusBadge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { useAuth } from "../context/AuthContext";
import { blockIncidentIp, fetchIncident, updateIncidentStatus } from "../lib/api";
import type { Incident, IncidentStatus } from "../types";

const STATUS_FLOW: IncidentStatus[] = ["OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"];

const RECOMMENDATIONS: Record<string, string> = {
  "Port Scan": "Block the source IP at the perimeter firewall and review which internal services are unnecessarily exposed.",
  "Host Discovery (Ping Sweep)": "Confirm this is not an authorized network scan; if unauthorized, isolate the source host for inspection.",
  "Service Enumeration": "Restrict access to the enumerated ports and check exposed service banners for information disclosure.",
  "SSH Brute Force": "Enforce key-based SSH auth, enable fail2ban-style throttling, and rotate credentials on the targeted host.",
  "Password Spraying": "Enforce account lockout/backoff policies and check for successful logins from the source IP across all targets.",
  "SYN Flood": "Enable SYN cookies on the target and consider upstream rate-limiting or a DDoS mitigation service.",
  "ARP Spoofing": "Enable dynamic ARP inspection / port security on the switch and verify the legitimate gateway MAC address.",
  "DNS Tunneling": "Block the destination and inspect the endpoint for tunneling malware; review DNS logs for the full session.",
  "Malware Beaconing": "Isolate the source host from the network immediately and run an endpoint malware scan.",
  "Botnet Communication": "Isolate the source host, block all listed C2 destinations at the firewall, and initiate incident response.",
  "Data Exfiltration": "Isolate the source host, preserve logs for forensics, and identify what data left the network.",
  "Unknown Attack": "Manually review the flow evidence below - this didn't match a known signature and needs analyst judgment.",
};

export default function Investigation() {
  const { id } = useParams<{ id: string }>();
  const { auth } = useAuth();
  const canTriage = auth?.role === "admin" || auth?.role === "analyst";

  const [incident, setIncident] = useState<Incident | null>(null);
  const [updating, setUpdating] = useState(false);
  const [blockResult, setBlockResult] = useState<string | null>(null);
  const [blocking, setBlocking] = useState(false);

  useEffect(() => {
    if (!id) return;
    fetchIncident(id).then(setIncident).catch(() => setIncident(null));
  }, [id]);

  async function handleStatusChange(status: IncidentStatus) {
    if (!incident) return;
    setUpdating(true);
    try {
      const updated = await updateIncidentStatus(incident.id, status);
      setIncident(updated);
    } finally {
      setUpdating(false);
    }
  }

  async function handleBlockIp() {
    if (!incident) return;
    setBlocking(true);
    setBlockResult(null);
    try {
      const result = await blockIncidentIp(incident.id);
      setBlockResult(result.message);
    } catch {
      setBlockResult("Failed to reach the block-IP endpoint.");
    } finally {
      setBlocking(false);
    }
  }

  if (!incident) {
    return (
      <AppShell title="Investigation">
        <p className="text-sm text-ink-500">Loading incident…</p>
      </AppShell>
    );
  }

  const evidenceEntries = Object.entries(incident.evidence).filter(
    ([k]) => !["shap_top_features", "top_deviations", "features"].includes(k)
  );
  const shapFeatures = (incident.evidence["shap_top_features"] as any[]) ?? [];
  const deviations = (incident.evidence["top_deviations"] as any[]) ?? [];

  return (
    <AppShell title="Investigation">
      <Link to="/threats" className="mb-4 inline-flex items-center gap-1.5 text-xs font-medium text-ink-500 hover:text-ink-100">
        <ArrowLeft size={14} /> Back to Threats
      </Link>

      <Card className="mb-4">
        <CardBody className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="rounded-xl bg-sev-critical/12 p-3 text-sev-critical">
              <ShieldAlert size={22} strokeWidth={1.75} />
            </div>
            <div>
              <h2 className="font-display text-lg font-semibold text-ink-100">{incident.attack_type}</h2>
              <p className="font-mono text-xs text-ink-500">
                {incident.source_ip} {incident.destination_ip ? `→ ${incident.destination_ip}` : ""}
                {incident.destination_port ? `:${incident.destination_port}` : ""}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <SeverityBadge severity={incident.severity} />
            <StatusBadge status={incident.status} />
            {incident.evidence["demo"] === true && (
              <span className="rounded-full border border-signal-500/40 bg-signal-500/15 px-2.5 py-0.5 text-xs font-medium text-signal-400">
                DEMO
              </span>
            )}
            <div className="text-right">
              <p className="font-display text-2xl font-semibold text-ink-100">{incident.risk_score}</p>
              <p className="text-[10px] uppercase tracking-wide text-ink-500">Risk Score</p>
            </div>
          </div>
        </CardBody>
      </Card>

      {canTriage && (
        <Card className="mb-4">
          <CardBody className="flex items-center gap-3">
            <span className="text-xs font-medium uppercase tracking-wide text-ink-500">Update status:</span>
            {STATUS_FLOW.map((s) => (
              <Button
                key={s}
                size="sm"
                variant={incident.status === s ? "primary" : "secondary"}
                disabled={updating}
                onClick={() => handleStatusChange(s)}
              >
                {s.replace("_", " ")}
              </Button>
            ))}
          </CardBody>
        </Card>
      )}

      {auth?.role === "admin" && (
        <Card className="mb-4">
          <CardBody>
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium text-ink-100">Automatic Response</p>
                <p className="text-xs text-ink-500">
                  Block {incident.source_ip} at the host firewall. Requires the backend process to be running with
                  root/Administrator privileges.
                </p>
              </div>
              <Button variant="danger" size="sm" onClick={handleBlockIp} disabled={blocking}>
                <ShieldOff size={14} /> {blocking ? "Blocking…" : `Block ${incident.source_ip}`}
              </Button>
            </div>
            {blockResult && <p className="mt-3 rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-xs text-ink-300">{blockResult}</p>}
          </CardBody>
        </Card>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bot size={15} /> AI Explanation
            </CardTitle>
          </CardHeader>
          <CardBody>
            <p className="text-sm leading-relaxed text-ink-300">{incident.explanation}</p>

            {shapFeatures.length > 0 && (
              <div className="mt-4 space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500">Top contributing features</p>
                {shapFeatures.map((f: any) => (
                  <FeatureBar key={f.raw_feature ?? f.feature} feature={f.feature} value={f.value} weight={Math.abs(f.shap_value ?? 0)} />
                ))}
              </div>
            )}

            {deviations.length > 0 && (
              <div className="mt-4 space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500">Most abnormal features (vs. benign baseline)</p>
                {deviations.map((d: any) => (
                  <FeatureBar key={d.feature} feature={d.feature} value={d.value} weight={Math.min(Math.abs(d.z_score) / 5, 1)} suffix={`z=${d.z_score}`} />
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Crosshair size={15} /> MITRE ATT&CK
            </CardTitle>
          </CardHeader>
          <CardBody>
            {incident.mitre_technique_id ? (
              <div className="rounded-lg border border-base-600 bg-base-800 p-4">
                <p className="font-mono text-sm text-signal-400">{incident.mitre_technique_id}</p>
                <p className="mt-1 text-sm text-ink-100">{incident.mitre_technique_name}</p>
              </div>
            ) : (
              <p className="text-sm text-ink-500">No technique mapping available.</p>
            )}

            <p className="mt-4 mb-2 text-xs font-medium uppercase tracking-wide text-ink-500">Recommendation</p>
            <p className="text-sm leading-relaxed text-ink-300">
              {RECOMMENDATIONS[incident.attack_type] ?? "Review the evidence and escalate per your incident response process."}
            </p>
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <ClipboardList size={15} /> Evidence
            </CardTitle>
          </CardHeader>
          <CardBody>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
              {evidenceEntries.map(([key, value]) => (
                <div key={key}>
                  <dt className="text-[11px] uppercase tracking-wide text-ink-500">{key.replace(/_/g, " ")}</dt>
                  <dd className="mt-0.5 font-mono text-sm text-ink-100">
                    {typeof value === "object" ? JSON.stringify(value) : String(value)}
                  </dd>
                </div>
              ))}
            </dl>
          </CardBody>
        </Card>
      </div>
    </AppShell>
  );
}

function FeatureBar({ feature, value, weight, suffix }: { feature: string; value: number; weight: number; suffix?: string }) {
  return (
    <div>
      <div className="flex items-center justify-between text-xs">
        <span className="text-ink-300">{feature}</span>
        <span className="font-mono text-ink-500">
          {value} {suffix}
        </span>
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-base-700">
        <div className="h-full rounded-full bg-signal-500" style={{ width: `${Math.min(weight * 100, 100)}%` }} />
      </div>
    </div>
  );
}
