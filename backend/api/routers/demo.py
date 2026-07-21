"""
AlertIQ 2.0 - Phase 5 Demo Mode Router
--------------------------------------------
GET  /api/demo/scenarios      - list the 12 available demo scenarios
POST /api/demo/simulate       - Admin/Analyst: run one scenario through
                                  the real detection engine and persist
                                  the resulting incident(s)

Demo Mode requires no live capture, no root privileges, and no real
attacker - it's meant for safe presentations/demonstrations.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from auth.dependencies import require_role
from database.models import User, UserRole
from api.engine_manager import engine_manager
from detection.demo_simulator import ALL_SCENARIO_NAMES

router = APIRouter(prefix="/api/demo", tags=["demo"])


class DemoSimulateRequest(BaseModel):
    attack_type: str


class DemoIncidentSummary(BaseModel):
    id: str
    attack_type: str
    severity: str


@router.get("/scenarios", response_model=list[str])
def list_scenarios(_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER))):
    return ALL_SCENARIO_NAMES


@router.post("/simulate", response_model=list[DemoIncidentSummary])
def simulate(
    payload: DemoSimulateRequest,
    _user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        return engine_manager.run_demo(payload.attack_type)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
