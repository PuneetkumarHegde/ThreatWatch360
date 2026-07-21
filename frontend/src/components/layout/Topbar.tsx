import { useEffect, useRef, useState } from "react";
import { AreaChart, Area, ResponsiveContainer } from "recharts";
import { fetchEngineStatus } from "../../lib/api";
import type { EngineStatus } from "../../types";

interface PulsePoint {
  t: number;
  packets: number;
}

export function Topbar({ title }: { title: string }) {
  const [status, setStatus] = useState<EngineStatus | null>(null);
  const [pulse, setPulse] = useState<PulsePoint[]>([]);
  const lastCount = useRef<number | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function tick() {
      try {
        const s = await fetchEngineStatus();
        if (cancelled) return;
        setStatus(s);

        const delta = lastCount.current === null ? 0 : Math.max(s.packets_captured - lastCount.current, 0);
        lastCount.current = s.packets_captured;

        setPulse((prev) => {
          const next = [...prev, { t: Date.now(), packets: delta }];
          return next.slice(-30);
        });
      } catch {
        // Engine status is best-effort in the topbar; a failed poll just
        // means the sparkline pauses, it shouldn't disrupt the page.
      }
    }

    tick();
    const id = setInterval(tick, 2000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  const running = status?.running ?? false;

  return (
    <header className="flex h-16 shrink-0 items-center justify-between border-b border-base-700 bg-base-900/70 px-6 backdrop-blur-sm">
      <h1 className="font-display text-lg font-semibold text-ink-100">{title}</h1>

      <div className="flex items-center gap-5">
        <div className="hidden items-center gap-2 sm:flex">
          <span className="text-xs font-mono text-ink-500">
            {status ? `${status.packets_captured.toLocaleString()} pkts` : "—"}
          </span>
          <div className="h-8 w-24 opacity-90">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={pulse}>
                <defs>
                  <linearGradient id="pulseGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--color-signal-400)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--color-signal-400)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <Area
                  type="monotone"
                  dataKey="packets"
                  stroke="var(--color-signal-400)"
                  strokeWidth={1.5}
                  fill="url(#pulseGradient)"
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="flex items-center gap-2 rounded-full border border-base-600 bg-base-800 px-3 py-1.5">
          <span
            className={`h-2 w-2 rounded-full ${running ? "bg-ok-500 animate-pulse-dot" : "bg-ink-700"}`}
          />
          <span className="text-xs font-medium text-ink-300">
            {running ? `Monitoring ${status?.interface ?? ""}` : "Capture stopped"}
          </span>
        </div>
      </div>
    </header>
  );
}
