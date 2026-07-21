import { useEffect, useState } from "react";
import { AppShell } from "../components/layout/AppShell";
import { Card, CardBody, CardHeader, CardTitle } from "../components/ui/Card";
import { useAuth } from "../context/AuthContext";
import { fetchSettings, updateSettings } from "../lib/api";
import type { SettingsState } from "../types";

const TOGGLES: { key: keyof SettingsState; label: string; description: string }[] = [
  {
    key: "enable_rule_engine",
    label: "Rule Engine",
    description: "Signature/heuristic detection for scans, brute force, floods, spoofing, tunneling, and exfiltration.",
  },
  {
    key: "enable_ml",
    label: "ML Classifier",
    description: "Trained model confirmation for SYN Flood, DNS Tunneling, Data Exfiltration, Beaconing, and Botnet C2.",
  },
  {
    key: "enable_anomaly_detection",
    label: "Anomaly Detection",
    description: "Isolation Forest flags statistically abnormal traffic that matches no known signature (Unknown Attack).",
  },
  {
    key: "enable_notifications",
    label: "Notifications",
    description: "Real-time email alerts for new incidents (requires SMTP configured on the backend - see README).",
  },
  {
    key: "enable_automatic_response",
    label: "Automatic Response",
    description: "Automatically block the source IP at the host firewall for CRITICAL severity incidents. Requires the backend to run with root/Administrator privileges. Off by default - use with caution.",
  },
];

export default function Settings() {
  const { auth } = useAuth();
  const isAdmin = auth?.role === "admin";
  const [settings, setSettings] = useState<SettingsState | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    fetchSettings().then(setSettings);
  }, []);

  async function toggle(key: keyof SettingsState) {
    if (!settings || !isAdmin) return;
    setSaving(true);
    try {
      const updated = await updateSettings({ [key]: !settings[key] } as Partial<SettingsState>);
      setSettings(updated);
    } finally {
      setSaving(false);
    }
  }

  return (
    <AppShell title="Settings">
      <Card>
        <CardHeader>
          <CardTitle>Detection Features</CardTitle>
        </CardHeader>
        <CardBody className="p-0">
          <ul className="divide-y divide-base-700">
            {TOGGLES.map((t) => (
              <li key={t.key} className="flex items-center justify-between gap-6 px-5 py-4">
                <div>
                  <p className="text-sm font-medium text-ink-100">{t.label}</p>
                  <p className="mt-0.5 max-w-md text-xs text-ink-500">{t.description}</p>
                </div>
                <ToggleSwitch
                  checked={settings?.[t.key] === true}
                  disabled={!settings || !isAdmin || saving}
                  onClick={() => toggle(t.key)}
                />
              </li>
            ))}
          </ul>
        </CardBody>
      </Card>

      <Card className="mt-4">
        <CardHeader>
          <CardTitle>Capture Interface</CardTitle>
        </CardHeader>
        <CardBody>
          <p className="font-mono text-sm text-ink-100">{settings?.interface ?? "default route interface"}</p>
          <p className="mt-1 text-xs text-ink-500">
            Set the interface when starting capture from the Live Monitor page.
          </p>
        </CardBody>
      </Card>

      {!isAdmin && (
        <p className="mt-4 text-xs text-ink-700">
          Your role ({auth?.role}) can view settings but only Admins can change them.
        </p>
      )}
    </AppShell>
  );
}

function ToggleSwitch({ checked, disabled, onClick }: { checked: boolean; disabled: boolean; onClick: () => void }) {
  return (
    <button
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={onClick}
      className={`relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-40 ${
        checked ? "bg-signal-500" : "bg-base-600"
      }`}
    >
      <span
        className={`absolute top-0.5 left-0.5 h-5 w-5 rounded-full bg-white transition-transform ${
          checked ? "translate-x-5" : "translate-x-0"
        }`}
      />
    </button>
  );
}
