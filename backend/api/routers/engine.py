"""
AlertIQ 2.0 - Phase 3 Engine Control Router
--------------------------------------------------
POST /api/engine/start  - Admin/Analyst: begin live capture on an interface
POST /api/engine/stop   - Admin/Analyst: stop live capture
GET  /api/engine/status - current capture stats (Dashboard/Live Monitor)

Live capture needs raw-socket privileges (root/Administrator) on the host
running this API process - see backend/README.md.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from auth.dependencies import require_role
from database.models import User, UserRole
from api.engine_manager import engine_manager
from api.schemas import EngineStartRequest, EngineStatus

router = APIRouter(prefix="/api/engine", tags=["engine"])


@router.get("/status", response_model=EngineStatus)
def engine_status(_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER))):
    return engine_manager.stats()


@router.post("/start", response_model=EngineStatus)
def start_engine(
    payload: EngineStartRequest,
    _user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    try:
        engine_manager.start(interface=payload.interface)
    except Exception as e:  # noqa: BLE001 - surface capture/permission errors to the caller
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to start capture (are you running with sufficient privileges?): {e}",
        )
    return engine_manager.stats()


@router.post("/stop", response_model=EngineStatus)
def stop_engine(_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))):
    engine_manager.stop()
    return engine_manager.stats()
