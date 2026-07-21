import { useEffect, useMemo, useState } from "react";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { fetchThreatMap } from "../lib/api";
import type { ThreatMapEdge, Severity } from "../types";

const WIDTH = 1000;
const HEIGHT = 500;

const SEVERITY_COLOR: Record<Severity, string> = {
  LOW: "var(--color-sev-low)",
  MEDIUM: "var(--color-sev-medium)",
  HIGH: "var(--color-sev-high)",
  CRITICAL: "var(--color-sev-critical)",
};

const RANGES = [
  { label: "15 min", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
  { label: "24 hours", seconds: 86400 },
];

// Simple lat/lng graticule (grid lines), not a coastline trace - see
// api/geo.py for why this map deliberately does not attempt precise
// continent shapes from memory.
function Graticule() {
  const lines = [];
  for (let lng = -180; lng <= 180; lng += 30) {
    const x = ((lng + 180) / 360) * WIDTH;
    lines.push(
      <line key={`v${lng}`} x1={x} y1={0} x2={x} y2={HEIGHT} stroke="var(--color-base-700)" strokeWidth={0.5} />
    );
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const y = ((90 - lat) / 180) * HEIGHT;
    lines.push(
      <line key={`h${lat}`} x1={0} y1={y} x2={WIDTH} y2={y} stroke="var(--color-base-700)" strokeWidth={0.5} />
    );
  }
  return <g opacity={0.5}>{lines}</g>;
}

function arcPath(x1: number, y1: number, x2: number, y2: number): string {
  const mx = (x1 + x2) / 2;
  const my = (y1 + y2) / 2 - Math.min(120, Math.abs(x2 - x1) / 3 + 40);
  return `M ${x1} ${y1} Q ${mx} ${my} ${x2} ${y2}`;
}

export default function ThreatMap() {
  const [range, setRange] = useState(RANGES[1]);
  const [edges, setEdges] = useState<ThreatMapEdge[]>([]);
  const [hovered, setHovered] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      fetchThreatMap({ since_seconds: range.seconds, limit: 150 }).then((res) => {
        if (!cancelled) setEdges(res.edges);
      });
    };
    load();
    const id = setInterval(load, 3000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [range]);

  const hasApproximate = useMemo(
    () => edges.some((e) => e.source.is_approximate || e.destination?.is_approximate),
    [edges]
  );

  return (
    <AppShell title="Threat Map">
      <div className="mb-4 flex items-center justify-between">
        <div className="flex gap-2">
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
        <div className="flex items-center gap-4 text-[11px] font-mono uppercase tracking-wide text-ink-500">
          {(["LOW", "MEDIUM", "HIGH", "CRITICAL"] as Severity[]).map((sev) => (
            <span key={sev} className="flex items-center gap-1.5">
              <span className="h-2 w-2 rounded-full" style={{ background: SEVERITY_COLOR[sev] }} />
              {sev}
            </span>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Attack Traffic — Geographic View</CardTitle>
          <span className="text-xs font-mono text-ink-500">{edges.length} incident(s) shown</span>
        </CardHeader>
        <CardBody className="p-0">
          <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="w-full" style={{ background: "var(--color-base-900)" }}>
            <Graticule />

            {edges.map((edge) => {
              if (!edge.destination) return null;
              const color = SEVERITY_COLOR[edge.severity] ?? "var(--color-signal-400)";
              const isHovered = hovered === edge.incident_id;
              return (
                <g
                  key={edge.incident_id}
                  onMouseEnter={() => setHovered(edge.incident_id)}
                  onMouseLeave={() => setHovered(null)}
                  style={{ cursor: "pointer" }}
                >
                  <path
                    d={arcPath(edge.source.x, edge.source.y, edge.destination.x, edge.destination.y)}
                    fill="none"
                    stroke={color}
                    strokeWidth={isHovered ? 2 : 1}
                    opacity={isHovered ? 0.95 : 0.45}
                  />
                  <circle r={2.5} fill={color}>
                    <animateMotion
                      dur="2.4s"
                      repeatCount="indefinite"
                      path={arcPath(edge.source.x, edge.source.y, edge.destination.x, edge.destination.y)}
                    />
                  </circle>
                </g>
              );
            })}

            {edges.flatMap((edge) => {
              const points = [edge.source, ...(edge.destination ? [edge.destination] : [])];
              return points.map((p) => (
                <circle
                  key={`${edge.incident_id}-${p.ip}`}
                  cx={p.x}
                  cy={p.y}
                  r={3}
                  fill="var(--color-base-950)"
                  stroke={SEVERITY_COLOR[edge.severity] ?? "var(--color-signal-400)"}
                  strokeWidth={1.5}
                  className={hovered === edge.incident_id ? "animate-pulse-dot" : undefined}
                />
              ));
            })}
          </svg>
        </CardBody>
      </Card>

      {hovered && (
        <div className="mt-3">
          {edges
            .filter((e) => e.incident_id === hovered)
            .map((e) => (
              <Card key={e.incident_id}>
                <CardBody className="flex flex-wrap items-center gap-x-6 gap-y-1 text-sm">
                  <span className="font-display font-semibold text-ink-100">{e.attack_type}</span>
                  <span className="font-mono text-xs text-ink-500">
                    {e.source.ip} ({e.source.label}) → {e.destination?.ip} ({e.destination?.label})
                  </span>
                  <span className="text-xs font-mono uppercase" style={{ color: SEVERITY_COLOR[e.severity] }}>
                    {e.severity}
                  </span>
                  <span className="text-xs font-mono text-ink-700">risk {e.risk_score}</span>
                </CardBody>
              </Card>
            ))}
        </div>
      )}

      {hasApproximate && (
        <p className="mt-3 text-[11px] text-ink-700">
          Some points shown above are on private/internal networks and have no real-world location — they are
          plotted at a fixed, illustrative point for visualization only, not geolocated.
        </p>
      )}
    </AppShell>
  );
}
