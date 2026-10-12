from detectors.brute_force import detect_brute_force
from detectors.data_exfiltration import detect_data_exfiltration
from detectors.dns_tunneling import detect_dns_tunneling
from detectors.port_scan import detect_port_scans
from detectors.registry import run_all_detectors
from detectors.suspicious_outbound import detect_suspicious_outbound


def test_brute_force_detection():
    events = []
    for i in range(6):
        events.append({
            "timestamp": f"2026-10-12T10:00:0{i}+00:00",
            "source_ip": "203.0.113.88",
            "destination_ip": "192.168.1.50",
            "destination_port": 22,
            "connection_state": "REJ",
            "bytes_received": 0,
        })

    alerts = detect_brute_force(events, attempt_threshold=5)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "BRUTE_FORCE_001"
    assert alerts[0]["alert_type"] == "brute_force_login"
    assert alerts[0]["evidence"]["failed_attempt_count"] >= 5


def test_suspicious_outbound_detection():
    events = [{
        "timestamp": "2026-10-12T10:00:00+00:00",
        "source_ip": "192.168.1.15",
        "destination_ip": "198.51.100.23",
        "destination_port": 9050,  # Tor SOCKS
        "protocol": "tcp",
    }]
    alerts = detect_suspicious_outbound(events)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "SUSPICIOUS_OUTBOUND_001"
    assert "Tor" in alerts[0]["evidence"]["threat_category"]


def test_data_exfiltration_detection():
    events = [{
        "timestamp": "2026-10-12T10:00:00+00:00",
        "source_ip": "192.168.1.99",
        "destination_ip": "198.51.100.23",
        "destination_port": 443,
        "bytes_sent": 2_500_000,
        "bytes_received": 1000,
    }]
    alerts = detect_data_exfiltration(events, byte_threshold=1_000_000)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "DATA_EXFILTRATION_001"
    assert alerts[0]["severity"] in ["high", "critical"]


def test_dns_tunneling_detection():
    events = [{
        "timestamp": "2026-10-12T10:00:00+00:00",
        "source_ip": "192.168.1.77",
        "destination_ip": "185.220.101.5",
        "destination_port": 53,
        "bytes_sent": 2500,  # Oversized DNS
        "bytes_received": 3000,
        "protocol": "udp",
    }]
    alerts = detect_dns_tunneling(events, payload_threshold=1200)
    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "DNS_TUNNEL_001"


def test_subnet_sweep_detection():
    events = []
    for i in range(6):
        events.append({
            "timestamp": f"2026-10-12T10:00:0{i}+00:00",
            "source_ip": "192.168.1.105",
            "destination_ip": f"192.168.1.{20 + i}",
            "destination_port": 445,
            "protocol": "tcp",
        })

    alerts = detect_port_scans(events, subnet_sweep_threshold=5)
    sweep_alerts = [a for a in alerts if a["rule_id"] == "PORT_SCAN_002"]
    assert len(sweep_alerts) == 1
    assert sweep_alerts[0]["alert_type"] == "subnet_sweep"


def test_run_all_detectors():
    events = [
        # Normal
        {
            "timestamp": "2026-10-12T10:00:00+00:00",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "destination_port": 53,
            "bytes_sent": 50,
            "bytes_received": 120,
        },
        # Suspicious Outbound
        {
            "timestamp": "2026-10-12T10:01:00+00:00",
            "source_ip": "192.168.1.10",
            "destination_ip": "198.51.100.23",
            "destination_port": 4444,
        },
    ]
    alerts = run_all_detectors(events)
    assert len(alerts) >= 1
    assert any(a["rule_id"] == "SUSPICIOUS_OUTBOUND_001" for a in alerts)
