"""
AlertIQ 2.0 - Phase 3 FastAPI Application
-----------------------------------------------
Run with:
    uvicorn api.app:app --host 0.0.0.0 --port 8000 --reload

On startup:
  - creates DB tables if they don't exist
  - seeds a default admin user (username: admin / password: ChangeMe123!)
    if no users exist yet - CHANGE THIS PASSWORD before any real deployment.

Live packet capture is NOT started automatically - call
POST /api/engine/start (Admin/Analyst) once the API is up, since it
needs raw-socket privileges on the host.
"""
from __future__ import annotations

import logging

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from auth.security import hash_password
from database.crud import ensure_default_admin
from database.db import SessionLocal, init_db
from api.routers import auth, demo, devices, engine, incidents, reports, threat_map, settings as settings_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("alertiq.api")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    db = SessionLocal()
    try:
        ensure_default_admin(db, hash_password)
    finally:
        db.close()
    logger.info("AlertIQ API ready. Default admin credentials: admin / ChangeMe123! (change immediately).")
    yield


app = FastAPI(
    title="AlertIQ 2.0 API",
    description="AI-Powered Real-Time Network Intrusion Detection & SOC Platform",
    version="0.5.0",  # Phase 5
    lifespan=lifespan,
)

# The React SOC portal (Phase 4) runs on a different origin during
# development (Vite dev server), so CORS needs to allow it explicitly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(devices.router)
app.include_router(engine.router)
app.include_router(settings_router.router)
app.include_router(reports.router)
app.include_router(demo.router)
app.include_router(threat_map.router)


@app.get("/api/health", tags=["health"])
def health_check():
    return {"status": "ok", "service": "AlertIQ 2.0 API"}
