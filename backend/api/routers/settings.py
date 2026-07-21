"""
AlertIQ 2.0 - Phase 3 + 5 Settings Router
------------------------------------------
GET   /api/settings - current feature toggles + capture interface
PATCH /api/settings - Admin only: update feature toggles

Mirrors the project spec's Settings page: choose network interface,
enable/disable ML, rule engine, anomaly detection, notifications, and
(Phase 5) automatic response.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from auth.dependencies import require_role
from config import settings
from database.models import User, UserRole
from api.schemas import SettingsOut, SettingsUpdate

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _current() -> SettingsOut:
    return SettingsOut(
        enable_rule_engine=settings.enable_rule_engine,
        enable_ml=settings.enable_ml,
        enable_anomaly_detection=settings.enable_anomaly_detection,
        enable_notifications=settings.enable_notifications,
        enable_automatic_response=settings.enable_automatic_response,
        interface=settings.capture.interface,
    )


@router.get("", response_model=SettingsOut)
def get_settings(_user: User = Depends(require_role(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER))):
    return _current()


@router.patch("", response_model=SettingsOut)
def update_settings(
    payload: SettingsUpdate,
    _user: User = Depends(require_role(UserRole.ADMIN)),
):
    if payload.enable_rule_engine is not None:
        settings.enable_rule_engine = payload.enable_rule_engine
    if payload.enable_ml is not None:
        settings.enable_ml = payload.enable_ml
    if payload.enable_anomaly_detection is not None:
        settings.enable_anomaly_detection = payload.enable_anomaly_detection
    if payload.enable_notifications is not None:
        settings.enable_notifications = payload.enable_notifications
    if payload.enable_automatic_response is not None:
        settings.enable_automatic_response = payload.enable_automatic_response

    return _current()
