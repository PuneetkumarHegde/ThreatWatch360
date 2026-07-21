"""
Phase 3 API tests, using FastAPI's TestClient (httpx) against a fresh,
isolated SQLite DB per test run (never touches the real alertiq.db).

Covers: login, JWT auth, RBAC (admin vs analyst vs viewer), incident
CRUD, device listing, and settings updates.
"""
import os
import sys
import tempfile
from pathlib import Path

# Isolate the test DB BEFORE importing anything that touches database.db
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["ALERTIQ_DB_PATH"] = _tmp_db.name

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.app import app  # noqa: E402
from database.crud import create_user  # noqa: E402
from database.db import SessionLocal, init_db  # noqa: E402
from database.models import Incident, UserRole  # noqa: E402
from auth.security import hash_password  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    db = SessionLocal()
    create_user(db, username="analyst1", hashed_password=hash_password("AnalystPass1!"), role=UserRole.ANALYST)
    create_user(db, username="viewer1", hashed_password=hash_password("ViewerPass1!"), role=UserRole.VIEWER)
    # Seed one incident directly so list/get endpoints have data to return.
    db.add(Incident(
        id="test-incident-1",
        timestamp=1751800000.0,
        attack_type="Port Scan",
        category="Reconnaissance",
        severity="MEDIUM",
        confidence=0.8,
        source_ip="10.0.0.5",
        destination_ip="10.0.0.10",
        destination_port=None,
        risk_score=55,
        status="OPEN",
        evidence={"distinct_destination_ports": 23},
        explanation="Test incident",
        mitre_technique_id="T1046",
        mitre_technique_name="Network Service Discovery",
    ))
    db.commit()
    db.close()

    with TestClient(app) as c:
        yield c


def _login(client, username, password):
    resp = client.post("/api/auth/login", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_health_check(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_default_admin_seeded_and_can_login(client):
    token = _login(client, "admin", "ChangeMe123!")
    assert token

    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["username"] == "admin"
    assert resp.json()["role"] == "admin"


def test_wrong_password_rejected(client):
    resp = client.post("/api/auth/login", data={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_unauthenticated_request_rejected(client):
    resp = client.get("/api/incidents")
    assert resp.status_code == 401


def test_list_and_get_incident(client):
    token = _login(client, "admin", "ChangeMe123!")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/incidents", headers=headers)
    assert resp.status_code == 200
    incidents = resp.json()
    assert any(i["id"] == "test-incident-1" for i in incidents)

    resp = client.get("/api/incidents/test-incident-1", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["attack_type"] == "Port Scan"
    assert body["mitre_technique_id"] == "T1046"


def test_incident_filtering_by_category(client):
    token = _login(client, "admin", "ChangeMe123!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/incidents", params={"category": "Reconnaissance"}, headers=headers)
    assert resp.status_code == 200
    assert all(i["category"] == "Reconnaissance" for i in resp.json())

    resp = client.get("/api/incidents", params={"category": "Data Theft"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json() == []


def test_viewer_cannot_update_incident_status(client):
    token = _login(client, "viewer1", "ViewerPass1!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.patch("/api/incidents/test-incident-1/status", json={"status": "RESOLVED"}, headers=headers)
    assert resp.status_code == 403


def test_analyst_can_update_incident_status(client):
    token = _login(client, "analyst1", "AnalystPass1!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.patch("/api/incidents/test-incident-1/status", json={"status": "RESOLVED"}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["status"] == "RESOLVED"


def test_viewer_cannot_create_user(client):
    token = _login(client, "viewer1", "ViewerPass1!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/auth/users",
        json={"username": "newuser", "password": "SomePass123!", "role": "viewer"},
        headers=headers,
    )
    assert resp.status_code == 403


def test_admin_can_create_user(client):
    token = _login(client, "admin", "ChangeMe123!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post(
        "/api/auth/users",
        json={"username": "newanalyst", "password": "SomePass123!", "role": "analyst"},
        headers=headers,
    )
    assert resp.status_code == 201
    assert resp.json()["role"] == "analyst"


def test_devices_endpoint_returns_list(client):
    token = _login(client, "admin", "ChangeMe123!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/devices", headers=headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_settings_get_and_admin_only_patch(client):
    token = _login(client, "admin", "ChangeMe123!")
    headers = {"Authorization": f"Bearer {token}"}

    resp = client.get("/api/settings", headers=headers)
    assert resp.status_code == 200
    assert "enable_rule_engine" in resp.json()

    resp = client.patch("/api/settings", json={"enable_ml": False}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["enable_ml"] is False

    # Restore for any later tests / manual runs
    client.patch("/api/settings", json={"enable_ml": True}, headers=headers)

    viewer_token = _login(client, "viewer1", "ViewerPass1!")
    resp = client.patch(
        "/api/settings", json={"enable_ml": False}, headers={"Authorization": f"Bearer {viewer_token}"}
    )
    assert resp.status_code == 403


def test_incident_stats_summary(client):
    token = _login(client, "admin", "ChangeMe123!")
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/api/incidents/stats/summary", params={"since_seconds": 999999999}, headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_incidents"] >= 1
    assert "Reconnaissance" in body["by_category"]
