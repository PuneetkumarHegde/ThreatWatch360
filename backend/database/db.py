
"""
AlertIQ 2.0 - Database Configuration
Supports PostgreSQL (Supabase/Render) and SQLite (local development).
"""

from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


# Local SQLite database path
DB_PATH = Path(
    os.environ.get(
        "ALERTIQ_DB_PATH",
        str(Path(__file__).parent / "alertiq.db"),
    )
)

# Prefer PostgreSQL when DATABASE_URL is configured.
DATABASE_URL = os.environ.get("DATABASE_URL")

if not DATABASE_URL:
    DATABASE_URL = f"sqlite:///{DB_PATH}"
elif DATABASE_URL.startswith("postgres://"):
    # Normalize older PostgreSQL URL format.
    DATABASE_URL = DATABASE_URL.replace(
        "postgres://",
        "postgresql://",
        1,
    )

# Configure SQLAlchemy for the selected database.
engine_options = {}

if DATABASE_URL.startswith("sqlite"):
    engine_options["connect_args"] = {
        "check_same_thread": False
    }

engine = create_engine(
    DATABASE_URL,
    **engine_options,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


class Base(DeclarativeBase):
    pass


def get_db():
    """Provide a database session and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create missing tables registered with SQLAlchemy models."""
    from database import models  # noqa: F401

    Base.metadata.create_all(bind=engine)
