from fastapi.testclient import TestClient
from backend.main import app
import backend.database as database

client = TestClient(app)


def test_api_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy"}


def test_api_root():
    response = client.get("/")
    assert response.status_code == 200
    assert "CyberSage" in response.json()["project"]


def test_api_llm_status():
    response = client.get("/config/llm-status")
    assert response.status_code == 200
    data = response.json()
    assert "has_api_key" in data
    assert "model" in data
    assert "status" in data


def test_api_alerts_and_metrics():
    response = client.get("/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)

    metrics_resp = client.get("/metrics")
    assert metrics_resp.status_code == 200
    data = metrics_resp.json()
    assert "total_alerts" in data
    assert "by_severity" in data


def test_api_triage_mock_mode():
    payload = {
        "alert_type": "brute_force_login",
        "source_ip": "203.0.113.88",
        "destination_ip": "192.168.1.22",
        "severity": "high",
        "evidence": {
            "target_port": 22,
            "service": "SSH",
            "failed_attempt_count": 6,
        },
        "mode": "mock",
    }
    response = client.post("/alerts/triage", json=payload)
    assert response.status_code == 200
    res = response.json()
    assert "summary" in res
    assert "likely_cause" in res
    assert res["severity"] == "high"
    assert res["confidence"] >= 0.8
    assert any("T1110" in x for x in res["mitre_attack"])


def test_api_status_update_and_notes(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test_api_alerts.db")
    database.initialize_database()

    alert_id = database.save_alert({
        "rule_id": "TEST_001",
        "alert_type": "possible_port_scan",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "severity": "medium",
    })

    # Update status
    patch_resp = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "investigating", "assigned_to": "Analyst Alice"},
    )
    assert patch_resp.status_code == 200
    assert patch_resp.json()["alert"]["status"] == "investigating"
    assert patch_resp.json()["alert"]["assigned_to"] == "Analyst Alice"

    # Add note
    note_resp = client.post(
        f"/alerts/{alert_id}/notes",
        json={"note": "Confirmed Nessus scan from security subnet.", "author": "Analyst Alice"},
    )
    assert note_resp.status_code == 200
    assert "Nessus" in note_resp.json()["alert"]["analyst_notes"]


def test_api_analytics_endpoints():
    timeline_resp = client.get("/analytics/timeline")
    assert timeline_resp.status_code == 200
    assert isinstance(timeline_resp.json(), list)

    graph_resp = client.get("/analytics/graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "links" in graph_data
