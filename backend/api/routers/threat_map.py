"""
AlertIQ 2.0 - Phase 6 (Threat Map) Router
------------------------------------------
GET /api/threat-map - recent incidents enriched with source/destination
coordinates for the Threat Map dashboard page.

See api/geo.py for how coordinates are derived, and why private-network
IPs are shown at clearly-labeled illustrative points rather than real
geolocations.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api import geo
from api.schemas import ThreatMapEdge, ThreatMapPoint, ThreatMapResponse
from auth.dependencies import get_current_user
from database import crud
from database.db import get_db
from database.models import User

router = APIRouter(prefix="/api/threat-map", tags=["threat-map"])


def _to_point(ip: str) -> ThreatMapPoint:
    located = geo.locate(ip)
    x, y = geo.project_equirectangular(located["lat"], located["lng"])
    return ThreatMapPoint(
        ip=ip,
        lat=located["lat"],
        lng=located["lng"],
        x=x,
        y=y,
        label=located["label"],
        is_approximate=located["is_approximate"],
    )


@router.get("", response_model=ThreatMapResponse)
def get_threat_map(
    limit: int = 100,
    since_seconds: float = 3600.0,
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incidents = crud.list_incidents(db, limit=limit)
    cutoff = time.time() - since_seconds

    edges: list[ThreatMapEdge] = []
    for incident in incidents:
        if incident.timestamp < cutoff:
            continue
        source_point = _to_point(incident.source_ip)
        destination_point = _to_point(incident.destination_ip) if incident.destination_ip else None
        edges.append(
            ThreatMapEdge(
                incident_id=incident.id,
                timestamp=incident.timestamp,
                attack_type=incident.attack_type,
                severity=incident.severity,
                risk_score=incident.risk_score,
                source=source_point,
                destination=destination_point,
            )
        )

    return ThreatMapResponse(edges=edges, generated_at=time.time())
