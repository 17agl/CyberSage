
import backend.database as database


def test_save_and_retrieve_alert(tmp_path, monkeypatch):
    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "test_alerts.db"
    )

    database.initialize_database()

    alert = {
        "rule_id": "PORT_SCAN_001",
        "alert_type": "possible_port_scan",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "severity": "medium",
        "timestamp": "2026-10-11T00:00:00+00:00",
        "evidence": {
            "unique_destination_ports": [21, 22, 80, 443, 8080],
            "port_count": 5,
            "window_seconds": 60,
        },
    }

    alert_id = database.save_alert(alert)
    results = database.get_alerts()

    assert alert_id == 1
    assert len(results) == 1
    assert results[0]["rule_id"] == "PORT_SCAN_001"
    assert results[0]["evidence"]["port_count"] == 5
