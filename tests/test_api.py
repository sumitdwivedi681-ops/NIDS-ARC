"""
Integration tests for NIDS ARC REST API Endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from backend.app import app

client = TestClient(app)


def test_health_endpoints():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert "status" in data


def test_dashboard_overview():
    res = client.get("/api/v1/dashboard/overview")
    assert res.status_code == 200
    data = res.json()
    assert "total_alerts" in data
    assert "severity_distribution" in data


def test_detection_engines_status():
    res = client.get("/api/v1/detections/engines")
    assert res.status_code == 200


def test_rules_api():
    res = client.get("/api/v1/rules")
    assert res.status_code == 200
    data = res.json()
    assert "rules" in data
    assert len(data["rules"]) > 0

    # Toggle a rule
    rule_id = data["rules"][0]["id"]
    toggle_res = client.put(f"/api/v1/rules/{rule_id}/toggle", json={"enabled": False})
    assert toggle_res.status_code == 200
    assert toggle_res.json()["enabled"] is False

    # Toggle back
    toggle_res2 = client.put(f"/api/v1/rules/{rule_id}/toggle", json={"enabled": True})
    assert toggle_res2.status_code == 200
    assert toggle_res2.json()["enabled"] is True


def test_settings_api():
    res = client.get("/api/v1/settings")
    assert res.status_code == 200
    data = res.json()
    assert "app_mode" in data

    # Update settings
    up_res = client.put("/api/v1/settings", json={"simulation_events_per_second": 15})
    assert up_res.status_code == 200
    assert up_res.json()["settings"]["simulation_events_per_second"] == 15


def test_maintenance_cleanup():
    res = client.post("/api/v1/maintenance/cleanup", json={})
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "success"
