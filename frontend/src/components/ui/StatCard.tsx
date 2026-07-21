import type { LucideIcon } from "lucide-react";
import { clsx } from "clsx";
import { Card } from "./Card";

interface StatCardProps {
  label: string;
  value: string | number;
  icon?: LucideIcon;
  tone?: "default" | "signal" | "critical" | "ok";
  sublabel?: string;
}

const TONE_STYLES: Record<NonNullable<StatCardProps["tone"]>, string> = {
  default: "text-ink-100",
  signal: "text-signal-400",
  critical: "text-sev-critical",
  ok: "text-ok-500",
};

export function StatCard({ label, value, icon: Icon, tone = "default", sublabel }: StatCardProps) {
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider text-ink-500">{label}</p>
          <p className={clsx("mt-2 font-display text-3xl font-semibold tabular-nums", TONE_STYLES[tone])}>{value}</p>
          {sublabel && <p className="mt-1 text-xs text-ink-500 font-mono">{sublabel}</p>}
        </div>
        {Icon && (
          <div className="rounded-lg bg-base-700/60 p-2 text-ink-300">
            <Icon size={18} strokeWidth={1.75} />
          </div>
        )}
      </div>
    </Card>
  );
}
