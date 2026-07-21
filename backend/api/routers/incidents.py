"""
AlertIQ 2.0 - Phase 3 Incidents Router
--------------------------------------------
GET  /api/incidents                - list (filterable by category/severity/status/source_ip)
GET  /api/incidents/{id}           - single incident (Investigation page)
PATCH /api/incidents/{id}/status   - Analyst/Admin only: update triage status
GET  /api/incidents/stats/summary  - Dashboard/Analytics aggregates
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user, require_role
from database import crud
from database.db import get_db
from database.models import User, UserRole
from api.schemas import IncidentOut, IncidentStatsOut, IncidentStatusUpdate
from response.ip_blocker import block_ip, unblock_ip

router = APIRouter(prefix="/api/incidents", tags=["incidents"])


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    limit: int = Query(100, le=1000),
    offset: int = 0,
    category: str | None = None,
    severity: str | None = None,
    status_filter: str | None = Query(None, alias="status"),
    source_ip: str | None = None,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return crud.list_incidents(
        db,
        limit=limit,
        offset=offset,
        category=category,
        severity=severity,
        status=status_filter,
        source_ip=source_ip,
    )


@router.get("/stats/summary", response_model=IncidentStatsOut)
def incidents_summary(
    since_seconds: float = Query(86400.0, description="Look-back window in seconds (default 24h)"),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    return crud.incident_stats(db, since_seconds=since_seconds)


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(incident_id: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    incident = crud.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.patch("/{incident_id}/status", response_model=IncidentOut)
def update_status(
    incident_id: str,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    incident = crud.update_incident_status(db, incident_id, payload.status)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.post("/{incident_id}/block-ip")
def block_incident_source_ip(
    incident_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMIN)),
):
    incident = crud.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    result = block_ip(incident.source_ip)
    return result.to_dict()


@router.post("/{incident_id}/unblock-ip")
def unblock_incident_source_ip(
    incident_id: str,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMIN)),
):
    incident = crud.get_incident(db, incident_id)
    if incident is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    result = unblock_ip(incident.source_ip)
    return result.to_dict()
