"""
AlertIQ 2.0 - Phase 3 Devices Router
------------------------------------------
GET /api/devices              - list all discovered devices
GET /api/devices/{mac}        - single device profile (Device Profile page)
POST /api/devices/sweep-stale - Admin/Analyst: mark devices with no
                                 recent activity as OFFLINE
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from auth.dependencies import get_current_user, require_role
from database import crud
from database.db import get_db
from database.models import Device, User, UserRole
from api.schemas import DeviceOut

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=list[DeviceOut])
def list_devices(db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    return crud.list_devices(db)


@router.get("/{mac_address}", response_model=DeviceOut)
def get_device(mac_address: str, db: Session = Depends(get_db), _user: User = Depends(get_current_user)):
    device = db.get(Device, mac_address)
    if device is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return device


@router.post("/sweep-stale")
def sweep_stale_devices(
    offline_after_seconds: float = 300.0,
    db: Session = Depends(get_db),
    _user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST)),
):
    count = crud.mark_stale_devices_offline(db, offline_after_seconds=offline_after_seconds)
    return {"marked_offline": count}
