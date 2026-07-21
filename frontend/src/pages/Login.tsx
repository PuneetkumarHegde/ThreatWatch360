import { useState, type FormEvent } from "react";
import { Navigate } from "react-router-dom";
import { ShieldCheck, AlertCircle } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { Button } from "../components/ui/Button";

export default function Login() {
  const { auth, login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  if (auth) return <Navigate to="/" replace />;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(username, password);
    } catch {
      setError("Incorrect username or password.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative flex h-screen items-center justify-center overflow-hidden bg-base-950">
      {/* Ambient network-grid backdrop - subtle, not decorative noise */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage:
            "linear-gradient(var(--color-base-500) 1px, transparent 1px), linear-gradient(90deg, var(--color-base-500) 1px, transparent 1px)",
          backgroundSize: "42px 42px",
        }}
      />
      <div className="pointer-events-none absolute left-1/2 top-1/2 h-[420px] w-[420px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-signal-500/10 blur-3xl" />

      <div className="relative w-full max-w-sm px-6">
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-signal-500/15 text-signal-400 ring-1 ring-signal-500/30">
            <ShieldCheck size={24} strokeWidth={2} />
          </div>
          <h1 className="font-display text-2xl font-semibold text-ink-100">AlertIQ 2.0</h1>
          <p className="mt-1 text-sm text-ink-500">AI-Powered Network Intrusion Detection</p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="rounded-xl border border-base-700 bg-base-900/80 p-6 shadow-2xl backdrop-blur-sm"
        >
          <div className="space-y-4">
            <div>
              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-ink-500">
                Username
              </label>
              <input
                autoFocus
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full rounded-lg border border-base-600 bg-base-800 px-3 py-2.5 text-sm text-ink-100 outline-none placeholder:text-ink-700 focus:border-signal-500 focus:ring-1 focus:ring-signal-500"
                placeholder="admin"
                required
              />
            </div>
            <div>
              <label className="mb-1.5 block text-xs font-medium uppercase tracking-wide text-ink-500">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full rounded-lg border border-base-600 bg-base-800 px-3 py-2.5 text-sm text-ink-100 outline-none placeholder:text-ink-700 focus:border-signal-500 focus:ring-1 focus:ring-signal-500"
                placeholder="••••••••"
                required
              />
            </div>

            {error && (
              <div className="flex items-center gap-2 rounded-lg border border-sev-critical/35 bg-sev-critical/10 px-3 py-2 text-xs text-sev-critical">
                <AlertCircle size={14} />
                {error}
              </div>
            )}

            <Button type="submit" disabled={loading} className="w-full">
              {loading ? "Signing in…" : "Sign in"}
            </Button>
          </div>
        </form>

        <p className="mt-5 text-center text-xs text-ink-700">
          Default admin credentials: <span className="font-mono text-ink-500">admin / ChangeMe123!</span>
        </p>
      </div>
    </div>
  );
}
