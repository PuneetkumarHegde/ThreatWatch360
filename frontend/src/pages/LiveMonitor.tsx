import { useEffect, useState } from "react";
import { Play, Square, Activity, Radio, FlaskConical, CheckCircle2 } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, ResponsiveContainer, Tooltip } from "recharts";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { SeverityBadge } from "../components/ui/Badge";
import { useAuth } from "../context/AuthContext";
import { fetchDemoScenarios, fetchEngineStatus, runDemoScenario, startEngine, stopEngine } from "../lib/api";
import type { EngineStatus } from "../types";

interface TrafficPoint {
  time: string;
  packets: number;
}

export default function LiveMonitor() {
  const { auth } = useAuth();
  const canControl = auth?.role === "admin" || auth?.role === "analyst";

  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [iface, setIface] = useState("");
  const [traffic, setTraffic] = useState<TrafficPoint[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [scenarios, setScenarios] = useState<string[]>([]);
  const [runningScenario, setRunningScenario] = useState<string | null>(null);
  const [lastResult, setLastResult] = useState<{ scenario: string; count: number; severity: string } | null>(null);

  useEffect(() => {
    fetchDemoScenarios().then(setScenarios).catch(() => {});
  }, []);

  async function handleRunScenario(attackType: string) {
    setRunningScenario(attackType);
    setLastResult(null);
    try {
      const results = await runDemoScenario(attackType);
      setLastResult({
        scenario: attackType,
        count: results.length,
        severity: results[0]?.severity ?? "LOW",
      });
    } catch {
      setLastResult({ scenario: attackType, count: 0, severity: "LOW" });
    } finally {
      setRunningScenario(null);
    }
  }

  useEffect(() => {
    let lastCount: number | null = null;
    let cancelled = false;

    async function tick() {
      try {
        const s = await fetchEngineStatus();
        if (cancelled) return;
        setStatus(s);
        const delta = lastCount === null ? 0 : Math.max(s.packets_captured - lastCount, 0);
        lastCount = s.packets_captured;
        setTraffic((prev) => [...prev, { time: new Date().toLocaleTimeString(), packets: delta }].slice(-40));
      } catch {
        // best-effort polling
      }
    }

    tick();
    const id = setInterval(tick, 2000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  async function handleStart() {
    setBusy(true);
    setError(null);
    try {
      const s = await startEngine(iface || undefined);
      setStatus(s);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? "Failed to start capture.");
    } finally {
      setBusy(false);
    }
  }

  async function handleStop() {
    setBusy(true);
    try {
      const s = await stopEngine();
      setStatus(s);
    } finally {
      setBusy(false);
    }
  }

  return (
    <AppShell title="Live Monitor">
      <Card className="mb-4">
        <CardHeader>
          <CardTitle>Capture Control</CardTitle>
          <div className="flex items-center gap-2">
            <span className={`h-2 w-2 rounded-full ${status?.running ? "bg-ok-500 animate-pulse-dot" : "bg-ink-700"}`} />
            <span className="text-xs font-medium text-ink-500">{status?.running ? "Running" : "Stopped"}</span>
          </div>
        </CardHeader>
        <CardBody>
          {!canControl ? (
            <p className="text-sm text-ink-500">
              Your role ({auth?.role}) can view live traffic but cannot start or stop capture. Contact an Admin or
              Analyst.
            </p>
          ) : (
            <div className="flex flex-wrap items-end gap-3">
              <div>
                <label className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-ink-500">
                  Interface
                </label>
                <input
                  value={iface}
                  onChange={(e) => setIface(e.target.value)}
                  placeholder="eth0 / Wi-Fi (blank = default route)"
                  disabled={status?.running}
                  className="w-72 rounded-lg border border-base-600 bg-base-800 px-3 py-2 text-sm font-mono text-ink-100 outline-none placeholder:text-ink-700 focus:border-signal-500 focus:ring-1 focus:ring-signal-500 disabled:opacity-50"
                />
              </div>
              {status?.running ? (
                <Button variant="danger" onClick={handleStop} disabled={busy}>
                  <Square size={14} /> Stop Capture
                </Button>
              ) : (
                <Button onClick={handleStart} disabled={busy}>
                  <Play size={14} /> Start Capture
                </Button>
              )}
            </div>
          )}
          {error && (
            <p className="mt-3 rounded-lg border border-sev-critical/35 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
              {error}
            </p>
          )}
          <p className="mt-3 text-xs text-ink-700">
            Live capture requires the API process to run with root/Administrator privileges for raw-socket access.
            See backend/README.md.
          </p>
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        <MiniStat icon={Activity} label="Packets Captured" value={status?.packets_captured ?? 0} />
        <MiniStat icon={Radio} label="Packets Dropped" value={status?.packets_dropped ?? 0} />
        <MiniStat icon={Activity} label="Active Flows" value={status?.active_flows ?? 0} />
        <MiniStat icon={Activity} label="Detections" value={status?.detections_total ?? 0} />
      </div>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Traffic (packets / 2s)</CardTitle>
        </CardHeader>
        <CardBody className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={traffic}>
              <defs>
                <linearGradient id="trafficGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="var(--color-signal-400)" stopOpacity={0.4} />
                  <stop offset="100%" stopColor="var(--color-signal-400)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="var(--color-base-700)" strokeDasharray="3 3" vertical={false} />
              <XAxis dataKey="time" hide />
              <YAxis stroke="var(--color-ink-700)" fontSize={11} width={32} />
              <Tooltip contentStyle={{ background: "#0f141c", border: "1px solid #1b2431", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="packets" stroke="var(--color-signal-400)" fill="url(#trafficGradient)" strokeWidth={2} isAnimationActive={false} />
            </AreaChart>
          </ResponsiveContainer>
        </CardBody>
      </Card>

      {canControl && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FlaskConical size={15} /> Demo Simulation Mode
            </CardTitle>
          </CardHeader>
          <CardBody>
            <p className="mb-4 text-sm text-ink-500">
              Safely demonstrate any of the 12 supported attack types without needing a real attacker or live
              capture. Each scenario generates realistic synthetic traffic and runs it through the actual
              detection engine — a successful run is real evidence the detector works, not a scripted animation.
              Results appear in Threats tagged <span className="font-mono text-ink-300">DEMO</span>.
            </p>
            <div className="flex flex-wrap gap-2">
              {scenarios.map((scenario) => (
                <Button
                  key={scenario}
                  variant="secondary"
                  size="sm"
                  disabled={runningScenario !== null}
                  onClick={() => handleRunScenario(scenario)}
                >
                  {runningScenario === scenario ? "Running…" : scenario}
                </Button>
              ))}
            </div>
            {lastResult && (
              <div className="mt-4 flex items-center gap-3 rounded-lg border border-base-600 bg-base-800 px-4 py-3">
                {lastResult.count > 0 ? (
                  <>
                    <CheckCircle2 size={16} className="text-ok-500" />
                    <span className="text-sm text-ink-100">
                      <strong>{lastResult.scenario}</strong> triggered {lastResult.count} incident(s)
                    </span>
                    <SeverityBadge severity={lastResult.severity as any} />
                  </>
                ) : (
                  <span className="text-sm text-sev-critical">
                    {lastResult.scenario} did not trigger a detection — check backend logs.
                  </span>
                )}
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </AppShell>
  );
}

function MiniStat({ icon: Icon, label, value }: { icon: typeof Activity; label: string; value: number }) {
  return (
    <Card className="p-4">
      <div className="flex items-center gap-3">
        <div className="rounded-lg bg-base-700/60 p-2 text-signal-400">
          <Icon size={16} strokeWidth={1.75} />
        </div>
        <div>
          <p className="font-display text-xl font-semibold tabular-nums text-ink-100">{value.toLocaleString()}</p>
          <p className="text-[11px] uppercase tracking-wide text-ink-500">{label}</p>
        </div>
      </div>
    </Card>
  );
}
