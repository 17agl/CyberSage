
from datetime import datetime, timezone, timedelta

from detectors.port_scan import detect_port_scans


def test_detects_port_scan():
    start = datetime(2026, 10, 11, tzinfo=timezone.utc)
    events = []

    for port in [21, 22, 23, 80, 443, 8080]:
        events.append({
            "timestamp": (
                start + timedelta(seconds=len(events))
            ).isoformat(),
            "source_ip": "192.168.1.10",
            "source_port": 50000 + len(events),
            "destination_ip": "192.168.1.20",
            "destination_port": port,
            "protocol": "tcp",
        })

    alerts = detect_port_scans(events)

    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "possible_port_scan"
    assert alerts[0]["evidence"]["port_count"] >= 5


def test_normal_traffic_does_not_trigger():
    events = [{
        "timestamp": "2026-10-11T00:00:00+00:00",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "destination_port": 443,
    }]

    assert detect_port_scans(events) == []
