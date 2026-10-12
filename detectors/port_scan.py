from collections import defaultdict
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


def detect_port_scans(
    events: List[Dict[str, Any]],
    port_threshold: int = 5,
    window_seconds: int = 60,
    subnet_sweep_threshold: int = 5,
) -> List[Dict[str, Any]]:
    """
    Detects two types of scanning behaviors:
    1. Single-Target Port Scan (PORT_SCAN_001): A source IP probing multiple distinct ports on a single host.
    2. Subnet Sweep (PORT_SCAN_002): A source IP probing the same port across multiple distinct destination hosts.
    """
    pair_grouped = defaultdict(list)
    sweep_grouped = defaultdict(list)

    for event in events:
        try:
            timestamp = _parse_ts(event.get("timestamp", 0))
            source_ip = event["source_ip"]
            dest_ip = event["destination_ip"]
            dest_port = int(event["destination_port"])

            event_record = {
                "timestamp": timestamp,
                "source_ip": source_ip,
                "destination_ip": dest_ip,
                "port": dest_port,
                "raw_timestamp": event.get("timestamp"),
            }

            pair_grouped[(source_ip, dest_ip)].append(event_record)
            sweep_grouped[(source_ip, dest_port)].append(event_record)

        except (KeyError, TypeError, ValueError):
            continue

    alerts = []

    # 1. Single-Target Port Scan (Multiple ports on same destination)
    for (source_ip, destination_ip), connections in pair_grouped.items():
        connections.sort(key=lambda item: item["timestamp"])
        left = 0

        for right, current in enumerate(connections):
            while current["timestamp"] - connections[left]["timestamp"] > window_seconds:
                left += 1

            window = connections[left:right + 1]
            unique_ports = sorted({item["port"] for item in window})

            if len(unique_ports) >= port_threshold:
                alerts.append({
                    "rule_id": "PORT_SCAN_001",
                    "alert_type": "possible_port_scan",
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "severity": "medium",
                    "timestamp": datetime.fromtimestamp(
                        current["timestamp"]
                    ).astimezone().isoformat(),
                    "evidence": {
                        "scan_type": "vertical_port_scan",
                        "unique_destination_ports": unique_ports,
                        "port_count": len(unique_ports),
                        "window_seconds": window_seconds,
                    },
                })
                break

    # 2. Subnet Sweep (Probing the same port across multiple hosts)
    for (source_ip, target_port), connections in sweep_grouped.items():
        connections.sort(key=lambda item: item["timestamp"])
        left = 0

        for right, current in enumerate(connections):
            while current["timestamp"] - connections[left]["timestamp"] > window_seconds:
                left += 1

            window = connections[left:right + 1]
            unique_destinations = sorted({item["destination_ip"] for item in window})

            if len(unique_destinations) >= subnet_sweep_threshold:
                alerts.append({
                    "rule_id": "PORT_SCAN_002",
                    "alert_type": "subnet_sweep",
                    "source_ip": source_ip,
                    "destination_ip": f"Subnet ({len(unique_destinations)} hosts)",
                    "severity": "high",
                    "timestamp": datetime.fromtimestamp(
                        current["timestamp"]
                    ).astimezone().isoformat(),
                    "evidence": {
                        "scan_type": "horizontal_subnet_sweep",
                        "target_port": target_port,
                        "probed_hosts": unique_destinations,
                        "host_count": len(unique_destinations),
                        "window_seconds": window_seconds,
                    },
                })
                break

    return alerts
