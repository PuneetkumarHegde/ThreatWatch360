"""
AlertIQ 2.0 - Phase 3 Security
------------------------------------
Password hashing (raw `bcrypt`, not passlib - passlib's bcrypt backend has
a well-known incompatibility with bcrypt>=4.1 that raises
`AttributeError: module 'bcrypt' has no attribute '__about__'`) and JWT
issuance/verification via `python-jose`.
"""
from __future__ import annotations

import os
import time

import bcrypt
from jose import JWTError, jwt

SECRET_KEY = os.environ.get("ALERTIQ_JWT_SECRET", "dev-secret-change-me-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_SECONDS = 8 * 60 * 60  # 8-hour SOC shift


def hash_password(plain_password: str) -> str:
    # bcrypt has a hard 72-byte input limit; truncate defensively.
    return bcrypt.hashpw(plain_password.encode("utf-8")[:72], bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8")[:72], hashed_password.encode("utf-8"))
    except ValueError:
        return False


def create_access_token(*, subject: str, role: str) -> str:
    now = time.time()
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_TOKEN_EXPIRE_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
