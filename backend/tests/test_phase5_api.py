"""
Phase 5 API tests: reports (PDF/CSV), demo mode, IP block/unblock, and
the new automatic-response settings field. Reuses the same isolated
temp-DB pattern as test_api.py.
"""
import os
import sys
import tempfile
from pathlib import Path

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
os.environ["ALERTIQ_DB_PATH"] = _tmp_db.name

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from api.app import app  # noqa: E402
from database.db import SessionLocal, init_db  # noqa: E402
from database.models import Incident  # noqa: E402


@pytest.fixture(scope="module")
def client():
    init_db()
    db = SessionLocal()
    db.add(Incident(
        id="phase5-incident-1",
        timestamp=1751800000.0,
        attack_type="SYN Flood",
        category="Network Attacks",
        severity="CRITICAL",
        confidence=0.9,
        source_ip="203.0.113.99",
        destination_ip="10.0.0.10",
        destination_port=443,
        risk_score=88,
        status="OPEN",
        evidence={},
        explanation="Test critical incident for Phase 5",
        mitre_technique_id="T1498.001",
        mitre_technique_name="Direct Network Flood",
    ))
    db.commit()
    db.close()
    with TestClient(app) as c:
        yield c


def _login(client, username="admin", password="ChangeMe123!"):
    resp = client.post("/api/auth/login", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_pdf_report_is_a_valid_pdf(client):
    token = _login(client)
    resp = client.get("/api/reports/incidents.pdf", params={"since_seconds": 999999999}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content.startswith(b"%PDF")


def test_csv_report_contains_incident(client):
    token = _login(client)
    resp = client.get("/api/reports/incidents.csv", params={"since_seconds": 999999999}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert "phase5-incident-1" in resp.text
    assert "SYN Flood" in resp.text


def test_demo_scenarios_list_has_12_entries(client):
    token = _login(client)
    resp = client.get("/api/demo/scenarios", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert len(resp.json()) == 12


def test_demo_simulate_port_scan_creates_real_incident(client):
    token = _login(client)
    resp = client.post("/api/demo/simulate", json={"attack_type": "Port Scan"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    results = resp.json()
    assert len(results) >= 1
    # Scanning many ports on a single host legitimately triggers BOTH
    # Port Scan and Service Enumeration rules (they're closely related
    # reconnaissance signatures with different thresholds) - so we check
    # for presence, not that Port Scan is specifically first in the list.
    attack_types = [r["attack_type"] for r in results]
    assert "Port Scan" in attack_types

    port_scan_result = next(r for r in results if r["attack_type"] == "Port Scan")
    detail = client.get(f"/api/incidents/{port_scan_result['id']}", headers={"Authorization": f"Bearer {token}"})
    assert detail.status_code == 200
    assert detail.json()["evidence"]["demo"] is True


def test_demo_simulate_invalid_scenario_rejected(client):
    token = _login(client)
    resp = client.post("/api/demo/simulate", json={"attack_type": "Not A Real Attack"}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 422


def test_viewer_cannot_run_demo(client):
    admin_token = _login(client)
    client.post(
        "/api/auth/users",
        json={"username": "viewerP5", "password": "ViewerPass1!", "role": "viewer"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    viewer_token = _login(client, "viewerP5", "ViewerPass1!")
    resp = client.post("/api/demo/simulate", json={"attack_type": "Port Scan"}, headers={"Authorization": f"Bearer {viewer_token}"})
    assert resp.status_code == 403


def test_block_and_unblock_ip_endpoint_responds(client):
    """We don't assert success=True here since the test environment may
    not have iptables/firewall tools available or sufficient privileges -
    what we verify is that the endpoint is wired correctly (RBAC enforced,
    returns a well-formed BlockResult) rather than crashing."""
    token = _login(client)
    resp = client.post("/api/incidents/phase5-incident-1/block-ip", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert "success" in body and "message" in body

    resp = client.post("/api/incidents/phase5-incident-1/unblock-ip", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_analyst_cannot_block_ip(client):
    admin_token = _login(client)
    client.post(
        "/api/auth/users",
        json={"username": "analystP5", "password": "AnalystPass1!", "role": "analyst"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    analyst_token = _login(client, "analystP5", "AnalystPass1!")
    resp = client.post("/api/incidents/phase5-incident-1/block-ip", headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 403


def test_settings_includes_automatic_response_field(client):
    token = _login(client)
    resp = client.get("/api/settings", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    body = resp.json()
    assert "enable_automatic_response" in body
    assert body["enable_automatic_response"] is False  # off by default

    resp = client.patch("/api/settings", json={"enable_automatic_response": True}, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["enable_automatic_response"] is True
    # restore
    client.patch("/api/settings", json={"enable_automatic_response": False}, headers={"Authorization": f"Bearer {token}"})
