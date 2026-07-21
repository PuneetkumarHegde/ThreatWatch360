"""
AlertIQ 2.0 - Phase 3 API Schemas
--------------------------------------
Pydantic models for request validation and response serialization.
Kept separate from the SQLAlchemy models (database/models.py) so the API
contract can evolve independently of the storage schema.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


# ---- Auth ----
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=72)
    role: str = "viewer"


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    username: str
    role: str
    is_active: bool


# ---- Incidents ----
class IncidentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    timestamp: float
    attack_type: str
    category: str
    severity: str
    confidence: float
    source_ip: str
    destination_ip: str | None
    destination_port: int | None
    risk_score: int
    status: str
    evidence: dict
    explanation: str
    mitre_technique_id: str | None
    mitre_technique_name: str | None


class IncidentStatusUpdate(BaseModel):
    status: str = Field(pattern="^(OPEN|INVESTIGATING|RESOLVED|FALSE_POSITIVE)$")


class IncidentStatsOut(BaseModel):
    total_incidents: int
    by_category: dict[str, int]
    by_severity: dict[str, int]
    top_attackers: list[dict]


# ---- Devices ----
class DeviceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    mac_address: str
    ip_address: str
    vendor: str | None
    hostname: str | None
    os_guess: str | None
    first_seen: float
    last_seen: float
    status: str
    risk_score: int
    is_critical_asset: bool


# ---- Engine control / settings ----
class EngineStatus(BaseModel):
    running: bool
    interface: str | None
    packets_captured: int
    packets_dropped: int
    active_flows: int
    detections_total: int


class EngineStartRequest(BaseModel):
    interface: str | None = None


class SettingsOut(BaseModel):
    enable_rule_engine: bool
    enable_ml: bool
    enable_anomaly_detection: bool
    enable_notifications: bool
    enable_automatic_response: bool
    interface: str | None


class SettingsUpdate(BaseModel):
    enable_rule_engine: bool | None = None
    enable_ml: bool | None = None
    enable_anomaly_detection: bool | None = None
    enable_notifications: bool | None = None
    enable_automatic_response: bool | None = None


# ---- Threat Map ----
class ThreatMapPoint(BaseModel):
    ip: str
    lat: float
    lng: float
    x: float
    y: float
    label: str
    is_approximate: bool


class ThreatMapEdge(BaseModel):
    incident_id: str
    timestamp: float
    attack_type: str
    severity: str
    risk_score: int
    source: ThreatMapPoint
    destination: ThreatMapPoint | None


class ThreatMapResponse(BaseModel):
    edges: list[ThreatMapEdge]
    generated_at: float
