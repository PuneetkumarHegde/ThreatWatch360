import {
  LayoutDashboard,
  Radio,
  Laptop2,
  ShieldAlert,
  Globe,
  BarChart3,
  FileText,
  Settings as SettingsIcon,
  ShieldCheck,
  LogOut,
} from "lucide-react";
import { NavLink } from "react-router-dom";
import { clsx } from "clsx";
import { useAuth } from "../../context/AuthContext";

const NAV_ITEMS = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/live-monitor", label: "Live Monitor", icon: Radio },
  { to: "/devices", label: "Devices", icon: Laptop2 },
  { to: "/threats", label: "Threats", icon: ShieldAlert },
  { to: "/threat-map", label: "Threat Map", icon: Globe },
  { to: "/analytics", label: "Analytics", icon: BarChart3 },
  { to: "/reports", label: "Reports", icon: FileText },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

export function Sidebar() {
  const { auth, logout } = useAuth();

  return (
    <aside className="flex h-screen w-60 shrink-0 flex-col border-r border-base-700 bg-base-900">
      <div className="flex items-center gap-2.5 px-5 py-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-signal-500/15 text-signal-400">
          <ShieldCheck size={18} strokeWidth={2} />
        </div>
        <div>
          <p className="font-display text-sm font-semibold leading-tight text-ink-100">AlertIQ</p>
          <p className="text-[10px] font-mono uppercase tracking-widest text-ink-500">SOC Platform</p>
        </div>
      </div>

      <nav className="flex-1 space-y-0.5 px-3 py-2">
        {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              clsx(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
                isActive
                  ? "bg-signal-500/12 text-signal-400"
                  : "text-ink-500 hover:bg-base-800 hover:text-ink-100"
              )
            }
          >
            <Icon size={17} strokeWidth={1.75} />
            {label}
          </NavLink>
        ))}
      </nav>

      <div className="border-t border-base-700 px-3 py-3">
        <div className="flex items-center justify-between rounded-lg px-2 py-2">
          <div className="min-w-0">
            <p className="truncate text-sm font-medium text-ink-100">{auth?.username}</p>
            <p className="text-[11px] font-mono uppercase tracking-wide text-ink-500">{auth?.role}</p>
          </div>
          <button
            onClick={logout}
            className="rounded-md p-1.5 text-ink-500 hover:bg-base-800 hover:text-sev-critical transition-colors"
            title="Sign out"
          >
            <LogOut size={16} strokeWidth={1.75} />
          </button>
        </div>
      </div>
    </aside>
  );
}
