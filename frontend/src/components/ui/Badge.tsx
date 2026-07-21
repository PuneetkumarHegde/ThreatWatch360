import { clsx } from "clsx";
import type { IncidentStatus, Severity } from "../../types";

const SEVERITY_STYLES: Record<Severity, string> = {
  LOW: "bg-sev-low/15 text-sev-low border-sev-low/35",
  MEDIUM: "bg-sev-medium/15 text-sev-medium border-sev-medium/35",
  HIGH: "bg-sev-high/15 text-sev-high border-sev-high/35",
  CRITICAL: "bg-sev-critical/15 text-sev-critical border-sev-critical/35",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={clsx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium font-mono tracking-wide uppercase",
        SEVERITY_STYLES[severity]
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

const STATUS_STYLES: Record<IncidentStatus, string> = {
  OPEN: "bg-base-700 text-ink-100 border-base-600",
  INVESTIGATING: "bg-signal-500/15 text-signal-400 border-signal-500/40",
  RESOLVED: "bg-ok-500/15 text-ok-500 border-ok-500/35",
  FALSE_POSITIVE: "bg-base-800 text-ink-500 border-base-600",
};

export function StatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={clsx("inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium", STATUS_STYLES[status])}>
      {status.replace("_", " ")}
    </span>
  );
}
