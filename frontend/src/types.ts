// Mirrors backend/api/schemas.py exactly - keep in sync when the API changes.

export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type IncidentStatus = "OPEN" | "INVESTIGATING" | "RESOLVED" | "FALSE_POSITIVE";
export type UserRole = "admin" | "analyst" | "viewer";

export interface Token {
  access_token: string;
  token_type: string;
  role: UserRole;
  username: string;
}

export interface UserOut {
  id: string;
  username: string;
  role: UserRole;
  is_active: boolean;
}

export interface ShapFeature {
  feature: string;
  raw_feature?: string;
  shap_value?: number;
  value: number;
  direction?: "increases" | "decreases";
}

export interface Incident {
  id: string;
  timestamp: number;
  attack_type: string;
  category: string;
  severity: Severity;
  confidence: number;
  source_ip: string;
  destination_ip: string | null;
  destination_port: number | null;
  risk_score: number;
  status: IncidentStatus;
  evidence: Record<string, unknown>;
  explanation: string;
  mitre_technique_id: string | null;
  mitre_technique_name: string | null;
}

export interface IncidentStats {
  total_incidents: number;
  by_category: Record<string, number>;
  by_severity: Record<string, number>;
  top_attackers: { ip: string; count: number }[];
}

export interface Device {
  mac_address: string;
  ip_address: string;
  vendor: string | null;
  hostname: string | null;
  os_guess: string | null;
  first_seen: number;
  last_seen: number;
  status: "ONLINE" | "OFFLINE";
  risk_score: number;
  is_critical_asset: boolean;
}

export interface EngineStatus {
  running: boolean;
  interface: string | null;
  packets_captured: number;
  packets_dropped: number;
  active_flows: number;
  detections_total: number;
}

export interface SettingsState {
  enable_rule_engine: boolean;
  enable_ml: boolean;
  enable_anomaly_detection: boolean;
  enable_notifications: boolean;
  enable_automatic_response: boolean;
  interface: string | null;
}

export interface BlockResult {
  success: boolean;
  message: string;
  command: string | null;
}

export interface DemoIncidentSummary {
  id: string;
  attack_type: string;
  severity: string;
}

// ---- Threat Map ----
export interface ThreatMapPoint {
  ip: string;
  lat: number;
  lng: number;
  x: number;
  y: number;
  label: string;
  is_approximate: boolean;
}

export interface ThreatMapEdge {
  incident_id: string;
  timestamp: number;
  attack_type: string;
  severity: Severity;
  risk_score: number;
  source: ThreatMapPoint;
  destination: ThreatMapPoint | null;
}

export interface ThreatMapResponse {
  edges: ThreatMapEdge[];
  generated_at: number;
}
