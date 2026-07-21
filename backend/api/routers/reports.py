"""
AlertIQ 2.0 - Phase 5 Reports Router
------------------------------------------
GET /api/reports/incidents.pdf - branded PDF incident report
GET /api/reports/incidents.csv - CSV incident export (also available
                                   client-side from the Reports page;
                                   this server-side version is useful for
                                   scripting/automation and matches
                                   exactly what the PDF report covers)
"""
from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response, StreamingResponse
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user
from database import crud
from database.db import get_db
from database.models import User
from reports.pdf_generator import generate_incident_report_pdf

router = APIRouter(prefix="/api/reports", tags=["reports"])

_WINDOW_LABELS = {
    3600: "Last hour",
    86400: "Last 24 hours",
    604800: "Last 7 days",
    2592000: "Last 30 days",
}


@router.get("/incidents.pdf")
def incidents_pdf(
    since_seconds: float = Query(86400.0),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incidents = crud.list_incidents(db, limit=1000)
    cutoff_incidents = [i for i in incidents if i.timestamp >= _now_minus(since_seconds)]
    stats = crud.incident_stats(db, since_seconds=since_seconds)

    pdf_bytes = generate_incident_report_pdf(
        incidents=[_incident_to_dict(i) for i in cutoff_incidents],
        stats=stats,
        window_label=_WINDOW_LABELS.get(int(since_seconds), f"Last {int(since_seconds / 3600)}h"),
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=alertiq-incident-report.pdf"},
    )


@router.get("/incidents.csv")
def incidents_csv(
    since_seconds: float = Query(86400.0),
    db: Session = Depends(get_db),
    _user: User = Depends(get_current_user),
):
    incidents = crud.list_incidents(db, limit=1000)
    cutoff_incidents = [i for i in incidents if i.timestamp >= _now_minus(since_seconds)]

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["id", "timestamp", "attack_type", "category", "severity", "confidence", "source_ip",
         "destination_ip", "destination_port", "risk_score", "status", "mitre_technique_id", "explanation"]
    )
    for i in cutoff_incidents:
        writer.writerow(
            [i.id, i.timestamp, i.attack_type, i.category, i.severity, i.confidence, i.source_ip,
             i.destination_ip or "", i.destination_port or "", i.risk_score, i.status,
             i.mitre_technique_id or "", i.explanation]
        )
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=alertiq-incidents.csv"},
    )


def _now_minus(seconds: float) -> float:
    import time

    return time.time() - seconds


def _incident_to_dict(incident) -> dict:
    return {
        "timestamp": incident.timestamp,
        "attack_type": incident.attack_type,
        "source_ip": incident.source_ip,
        "destination_ip": incident.destination_ip,
        "severity": incident.severity,
        "risk_score": incident.risk_score,
        "status": incident.status,
    }
