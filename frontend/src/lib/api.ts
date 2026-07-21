import axios, { type AxiosInstance } from "axios";
import type {
  BlockResult,
  DemoIncidentSummary,
  Device,
  EngineStatus,
  Incident,
  IncidentStats,
  IncidentStatus,
  SettingsState,
  ThreatMapResponse,
  Token,
  UserOut,
  UserRole,
} from "../types";

const TOKEN_STORAGE_KEY = "alertiq.token";
const AUTH_STORAGE_KEY = "alertiq.auth";

export interface StoredAuth {
  token: string;
  username: string;
  role: UserRole;
}

export function loadStoredAuth(): StoredAuth | null {
  const raw = localStorage.getItem(AUTH_STORAGE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as StoredAuth;
  } catch {
    return null;
  }
}

export function saveStoredAuth(auth: StoredAuth) {
  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(auth));
  localStorage.setItem(TOKEN_STORAGE_KEY, auth.token);
}

export function clearStoredAuth() {
  localStorage.removeItem(AUTH_STORAGE_KEY);
  localStorage.removeItem(TOKEN_STORAGE_KEY);
}

const client: AxiosInstance = axios.create({ baseURL: "/api" });

client.interceptors.request.use((config) => {
  const token = localStorage.getItem(TOKEN_STORAGE_KEY);
  if (token) {
    config.headers = config.headers ?? {};
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

client.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error?.response?.status === 401) {
      clearStoredAuth();
      if (!window.location.pathname.startsWith("/login")) {
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

// ---- Auth ----
export async function login(username: string, password: string): Promise<Token> {
  const form = new URLSearchParams();
  form.set("username", username);
  form.set("password", password);
  const res = await client.post<Token>("/auth/login", form, {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  return res.data;
}

export async function fetchMe(): Promise<UserOut> {
  const res = await client.get<UserOut>("/auth/me");
  return res.data;
}

export async function createUser(username: string, password: string, role: UserRole): Promise<UserOut> {
  const res = await client.post<UserOut>("/auth/users", { username, password, role });
  return res.data;
}

// ---- Incidents ----
export async function fetchIncidents(params: {
  category?: string;
  severity?: string;
  status?: string;
  source_ip?: string;
  limit?: number;
} = {}): Promise<Incident[]> {
  const res = await client.get<Incident[]>("/incidents", { params });
  return res.data;
}

export async function fetchIncident(id: string): Promise<Incident> {
  const res = await client.get<Incident>(`/incidents/${id}`);
  return res.data;
}

export async function updateIncidentStatus(id: string, status: IncidentStatus): Promise<Incident> {
  const res = await client.patch<Incident>(`/incidents/${id}/status`, { status });
  return res.data;
}

export async function fetchIncidentStats(sinceSeconds = 86400): Promise<IncidentStats> {
  const res = await client.get<IncidentStats>("/incidents/stats/summary", {
    params: { since_seconds: sinceSeconds },
  });
  return res.data;
}

// ---- Devices ----
export async function fetchDevices(): Promise<Device[]> {
  const res = await client.get<Device[]>("/devices");
  return res.data;
}

export async function fetchDevice(mac: string): Promise<Device> {
  const res = await client.get<Device>(`/devices/${mac}`);
  return res.data;
}

// ---- Engine ----
export async function fetchEngineStatus(): Promise<EngineStatus> {
  const res = await client.get<EngineStatus>("/engine/status");
  return res.data;
}

export async function startEngine(iface?: string): Promise<EngineStatus> {
  const res = await client.post<EngineStatus>("/engine/start", { interface: iface ?? null });
  return res.data;
}

export async function stopEngine(): Promise<EngineStatus> {
  const res = await client.post<EngineStatus>("/engine/stop");
  return res.data;
}

// ---- Settings ----
export async function fetchSettings(): Promise<SettingsState> {
  const res = await client.get<SettingsState>("/settings");
  return res.data;
}

export async function updateSettings(patch: Partial<SettingsState>): Promise<SettingsState> {
  const res = await client.patch<SettingsState>("/settings", patch);
  return res.data;
}

// ---- Phase 5: Automatic response ----
export async function blockIncidentIp(incidentId: string): Promise<BlockResult> {
  const res = await client.post<BlockResult>(`/incidents/${incidentId}/block-ip`);
  return res.data;
}

export async function unblockIncidentIp(incidentId: string): Promise<BlockResult> {
  const res = await client.post<BlockResult>(`/incidents/${incidentId}/unblock-ip`);
  return res.data;
}

// ---- Phase 5: Demo Simulation Mode ----
export async function fetchDemoScenarios(): Promise<string[]> {
  const res = await client.get<string[]>("/demo/scenarios");
  return res.data;
}

export async function runDemoScenario(attackType: string): Promise<DemoIncidentSummary[]> {
  const res = await client.post<DemoIncidentSummary[]>("/demo/simulate", { attack_type: attackType });
  return res.data;
}

// ---- Phase 5: Reports ----
export async function downloadIncidentsPdf(sinceSeconds = 86400): Promise<void> {
  const res = await client.get("/reports/incidents.pdf", {
    params: { since_seconds: sinceSeconds },
    responseType: "blob",
  });
  triggerBlobDownload(res.data, "alertiq-incident-report.pdf");
}

export async function downloadIncidentsCsvServerSide(sinceSeconds = 86400): Promise<void> {
  const res = await client.get("/reports/incidents.csv", {
    params: { since_seconds: sinceSeconds },
    responseType: "blob",
  });
  triggerBlobDownload(res.data, "alertiq-incidents.csv");
}

// ---- Threat Map ----
export async function fetchThreatMap(params: { limit?: number; since_seconds?: number } = {}): Promise<ThreatMapResponse> {
  const res = await client.get<ThreatMapResponse>("/threat-map", { params });
  return res.data;
}

function triggerBlobDownload(data: BlobPart, filename: string) {
  const url = URL.createObjectURL(new Blob([data]));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export default client;
