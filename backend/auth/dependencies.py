"""
AlertIQ 2.0 - Phase 3 Auth Dependencies
--------------------------------------------
FastAPI dependency functions: `get_current_user` extracts + validates the
JWT bearer token; `require_role(...)` builds a dependency that further
enforces RBAC (Admin / Analyst / Viewer) for a specific endpoint.
"""
from __future__ import annotations

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from auth.security import decode_access_token
from database.crud import get_user_by_username
from database.db import get_db
from database.models import User, UserRole

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    if payload is None or "sub" not in payload:
        raise _CREDENTIALS_EXCEPTION
    user = get_user_by_username(db, payload["sub"])
    if user is None or not user.is_active:
        raise _CREDENTIALS_EXCEPTION
    return user


def require_role(*allowed_roles: UserRole):
    """Usage: `current_user: User = Depends(require_role(UserRole.ADMIN))`"""

    def _dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {[r.value for r in allowed_roles]}",
            )
        return current_user

    return _dependency
