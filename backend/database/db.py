"""
AlertIQ 2.0 - Phase 3 Database Setup
----------------------------------------
SQLite via SQLAlchemy. SQLite is sufficient for a single-box SOC deployment
(per the project spec) and needs no separate DB server to run.
"""
from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DB_PATH = Path(os.environ.get("ALERTIQ_DB_PATH", Path(__file__).parent / "alertiq.db"))
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # needed for SQLite + FastAPI's threaded requests
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    """FastAPI dependency: yields a DB session, always closed after the request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create all tables. Safe to call repeatedly (no-op if tables exist)."""
    # Import models so they're registered on Base.metadata before create_all.
    from database import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
