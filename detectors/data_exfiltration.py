from datetime import datetime
from typing import Any, Dict, List


def _parse_ts(ts_val: Any) -> float:
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            return datetime.fromisoformat(ts_val.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return float(ts_val)
    return 0.0


def detect_data_exfiltration(
    events: List[Dict[str, Any]],
    byte_threshold: int = 1_000_000,  # 1 MB threshold for demo/lab detection
    asymmetry_ratio: float = 5.0,     # Sent at least 5x more than received
) -> List[Dict[str, Any]]:
    """
    Detects unusually large outbound byte transfers or severe transfer asymmetry
    suggestive of data exfiltration or unauthorized bulk staging.
    """
    seen_flows = set()
    alerts = []

    for event in events:
        try:
            bytes_sent = event.get("bytes_sent")
            bytes_recv = event.get("bytes_received") or 0

            if bytes_sent is None or bytes_sent < byte_threshold:
                continue

            ratio = bytes_sent / (bytes_recv + 1)
            if ratio >= asymmetry_ratio:
                source_ip = event["source_ip"]
                dest_ip = event["destination_ip"]
                flow_key = (source_ip, dest_ip, event.get("destination_port"))

                if flow_key in seen_flows:
                    continue
                seen_flows.add(flow_key)

                timestamp = _parse_ts(event.get("timestamp", 0))
                severity = "critical" if bytes_sent >= 10_000_000 else "high"

                alerts.append({
                    "rule_id": "DATA_EXFILTRATION_001",
                    "alert_type": "unusual_traffic_volume",
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "severity": severity,
                    "timestamp": datetime.fromtimestamp(
                        timestamp
                    ).astimezone().isoformat() if timestamp else event.get("timestamp"),
                    "evidence": {
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_recv,
                        "asymmetry_ratio": round(ratio, 2),
                        "destination_port": event.get("destination_port"),
                        "protocol": event.get("protocol", "tcp"),
                        "human_readable_sent": f"{bytes_sent / (1024 * 1024):.2f} MB",
                    },
                })
        except (KeyError, TypeError, ValueError):
            continue

    return alerts
