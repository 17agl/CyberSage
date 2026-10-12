from ml.anomaly_detector import NetworkAnomalyDetector
from ml.feature_extractor import extract_features


def test_extract_features():
    events = [
        {
            "timestamp": "2026-10-12T10:00:00+00:00",
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": 443,
            "bytes_sent": 500,
            "bytes_received": 1500,
            "protocol": "tcp",
            "connection_state": "SF",
        }
    ]
    X, valid = extract_features(events)
    assert len(X) == 1
    assert len(valid) == 1
    assert X.shape[1] == 8


def test_ml_anomaly_detector_detects_outlier():
    # 25 normal flows
    events = []
    for i in range(25):
        events.append({
            "timestamp": f"2026-10-12T10:00:{i:02d}+00:00",
            "source_ip": "192.168.1.15",
            "destination_ip": "192.168.1.20",
            "destination_port": 443,
            "bytes_sent": 200 + i,
            "bytes_received": 800 + i,
            "protocol": "tcp",
            "connection_state": "SF",
        })

    # 1 massive outlier flow
    events.append({
        "timestamp": "2026-10-12T10:05:00+00:00",
        "source_ip": "192.168.1.99",
        "destination_ip": "198.51.100.23",
        "destination_port": 31337,
        "bytes_sent": 25_000_000,
        "bytes_received": 100,
        "protocol": "tcp",
        "connection_state": "RSTO",
    })

    detector = NetworkAnomalyDetector(contamination=0.08)
    detector.fit(events)
    alerts = detector.detect_anomalies(events)

    assert len(alerts) >= 1
    outlier = alerts[0]
    assert outlier["rule_id"] == "ML_ANOMALY_001"
    assert outlier["alert_type"] == "ml_traffic_anomaly"
    assert outlier["source_ip"] == "192.168.1.99"
    assert "anomaly_score" in outlier["evidence"]
