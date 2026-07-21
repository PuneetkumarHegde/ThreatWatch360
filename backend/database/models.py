"""
AlertIQ 2.0 - Phase 3 Database Models
------------------------------------------
Three tables, deliberately kept simple and denormalized where it aids
query performance for a dashboard-heavy read pattern:

  - User      - auth + RBAC (Admin / Analyst / Viewer)
  - Incident  - persisted form of packet_capture.models.Detection
  - Device    - discovered network devices (from ARP observations)
"""
from __future__ import annotations

import enum
import time
import uuid

from sqlalchemy import JSON, Boolean, Enum, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from database.db import Base


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.VIEWER)
    created_at: Mapped[float] = mapped_column(Float, default=time.time)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Incident(Base):
    """Persisted form of a Detection (rule engine or ML pipeline)."""

    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp: Mapped[float] = mapped_column(Float, default=time.time, index=True)

    attack_type: Mapped[str] = mapped_column(String, index=True)
    category: Mapped[str] = mapped_column(String, index=True)
    severity: Mapped[str] = mapped_column(String, index=True)
    confidence: Mapped[float] = mapped_column(Float)

    source_ip: Mapped[str] = mapped_column(String, index=True)
    destination_ip: Mapped[str | None] = mapped_column(String, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    risk_score: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String, default="OPEN")  # OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE

    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    explanation: Mapped[str] = mapped_column(String, default="")

    # MITRE ATT&CK mapping shown on the Investigation page.
    mitre_technique_id: Mapped[str | None] = mapped_column(String, nullable=True)
    mitre_technique_name: Mapped[str | None] = mapped_column(String, nullable=True)


class Device(Base):
    """A discovered network device, keyed by MAC (stable across DHCP renewals)."""

    __tablename__ = "devices"

    mac_address: Mapped[str] = mapped_column(String, primary_key=True)
    ip_address: Mapped[str] = mapped_column(String, index=True)
    vendor: Mapped[str | None] = mapped_column(String, nullable=True)
    hostname: Mapped[str | None] = mapped_column(String, nullable=True)
    os_guess: Mapped[str | None] = mapped_column(String, nullable=True)

    first_seen: Mapped[float] = mapped_column(Float, default=time.time)
    last_seen: Mapped[float] = mapped_column(Float, default=time.time)

    status: Mapped[str] = mapped_column(String, default="ONLINE")  # ONLINE, OFFLINE
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    is_critical_asset: Mapped[bool] = mapped_column(Boolean, default=False)
