
from triage.llm_client import mock_triage


def test_port_scan_triage():
    alert = {
        "alert_type": "possible_port_scan",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "severity": "medium",
        "evidence": {
            "unique_destination_ports": [22, 80, 443, 3306, 8080],
            "port_count": 5,
        },
    }

    result = mock_triage(alert)

    assert result.severity == "medium"
    assert "port" in result.summary.lower()
    assert result.recommended_actions
    assert 0 <= result.confidence <= 1
