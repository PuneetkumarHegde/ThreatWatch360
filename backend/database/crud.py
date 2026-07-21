"""
AlertIQ 2.0 - Phase 3 CRUD Helpers
---------------------------------------
Thin data-access layer between the API routers / detection engine and
SQLAlchemy. Keeping this separate from the routers means the same
functions can be reused by main.py's detection callback (writing
incidents as they're detected) and by the REST API (reading them back).
"""
from __future__ import annotations

import time

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from database.models import Device, Incident, User, UserRole
from detection.mitre import lookup as mitre_lookup
from packet_capture.models import Detection


# ---------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------
def create_incident_from_detection(db: Session, detection: Detection) -> Incident:
    technique_id, technique_name = mitre_lookup(detection.attack_type)
    risk_score = detection.evidence.get("risk_score")
    if risk_score is None:
        # Rule-engine detections don't compute a risk score themselves
        # (Phase 1); fall back to a severity-based estimate so every
        # incident always has one.
        from ai_engine.risk_score import compute_risk_score

        risk_score = compute_risk_score(
            severity=detection.severity.value,
            model_confidence=detection.confidence or 0.8,
            shap_importance=0.5,
            anomaly_score=0.0,
            destination_ip=detection.destination_ip,
        )

    incident = Incident(
        id=detection.detection_id,
        timestamp=detection.timestamp,
        attack_type=detection.attack_type,
        category=detection.category.value,
        severity=detection.severity.value,
        confidence=detection.confidence,
        source_ip=detection.source_ip,
        destination_ip=detection.destination_ip,
        destination_port=detection.destination_port,
        risk_score=risk_score,
        status="OPEN",
        evidence=detection.evidence,
        explanation=detection.explanation,
        mitre_technique_id=technique_id,
        mitre_technique_name=technique_name,
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def list_incidents(
    db: Session,
    *,
    limit: int = 100,
    offset: int = 0,
    category: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source_ip: str | None = None,
) -> list[Incident]:
    stmt = select(Incident).order_by(Incident.timestamp.desc())
    if category:
        stmt = stmt.where(Incident.category == category)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if status:
        stmt = stmt.where(Incident.status == status)
    if source_ip:
        stmt = stmt.where(Incident.source_ip == source_ip)
    stmt = stmt.offset(offset).limit(limit)
    return list(db.scalars(stmt).all())


def get_incident(db: Session, incident_id: str) -> Incident | None:
    return db.get(Incident, incident_id)


def update_incident_status(db: Session, incident_id: str, status: str) -> Incident | None:
    incident = db.get(Incident, incident_id)
    if incident is None:
        return None
    incident.status = status
    db.commit()
    db.refresh(incident)
    return incident


def incident_stats(db: Session, since_seconds: float = 86400.0) -> dict:
    cutoff = time.time() - since_seconds
    total = db.scalar(select(func.count()).select_from(Incident).where(Incident.timestamp >= cutoff)) or 0

    by_category = dict(
        db.execute(
            select(Incident.category, func.count())
            .where(Incident.timestamp >= cutoff)
            .group_by(Incident.category)
        ).all()
    )
    by_severity = dict(
        db.execute(
            select(Incident.severity, func.count())
            .where(Incident.timestamp >= cutoff)
            .group_by(Incident.severity)
        ).all()
    )
    top_attackers = db.execute(
        select(Incident.source_ip, func.count().label("count"))
        .where(Incident.timestamp >= cutoff)
        .group_by(Incident.source_ip)
        .order_by(func.count().desc())
        .limit(10)
    ).all()

    return {
        "total_incidents": total,
        "by_category": by_category,
        "by_severity": by_severity,
        "top_attackers": [{"ip": ip, "count": count} for ip, count in top_attackers],
    }


# ---------------------------------------------------------------------
# Devices
# ---------------------------------------------------------------------
def upsert_device(
    db: Session,
    *,
    mac_address: str,
    ip_address: str,
    vendor: str | None = None,
    hostname: str | None = None,
) -> Device:
    device = db.get(Device, mac_address)
    now = time.time()
    if device is None:
        device = Device(
            mac_address=mac_address,
            ip_address=ip_address,
            vendor=vendor,
            hostname=hostname,
            first_seen=now,
            last_seen=now,
            status="ONLINE",
        )
        db.add(device)
    else:
        device.ip_address = ip_address
        device.last_seen = now
        device.status = "ONLINE"
        if vendor:
            device.vendor = vendor
        if hostname:
            device.hostname = hostname
    db.commit()
    db.refresh(device)
    return device


def list_devices(db: Session) -> list[Device]:
    stmt = select(Device).order_by(Device.last_seen.desc())
    return list(db.scalars(stmt).all())


def mark_stale_devices_offline(db: Session, offline_after_seconds: float = 300.0) -> int:
    cutoff = time.time() - offline_after_seconds
    devices = db.scalars(select(Device).where(Device.last_seen < cutoff, Device.status == "ONLINE")).all()
    for d in devices:
        d.status = "OFFLINE"
    db.commit()
    return len(devices)


# ---------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------
def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def create_user(db: Session, *, username: str, hashed_password: str, role: UserRole) -> User:
    user = User(username=username, hashed_password=hashed_password, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def ensure_default_admin(db: Session, hash_fn) -> None:
    """Seed a default admin account on first run so the SOC portal is
    usable immediately. Credentials are logged once at startup and
    should be changed via the Settings page in a real deployment."""
    if get_user_by_username(db, "admin") is not None:
        return
    create_user(db, username="admin", hashed_password=hash_fn("ChangeMe123!"), role=UserRole.ADMIN)
