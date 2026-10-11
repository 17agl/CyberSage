
from collections import defaultdict
from datetime import datetime


def detect_port_scans(
    events,
    port_threshold=5,
    window_seconds=60
):
    """
    Detect a source contacting multiple distinct ports
    on the same destination within a time window.
    """
    grouped = defaultdict(list)

    for event in events:
        try:
            timestamp = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            ).timestamp()

            key = (
                event["source_ip"],
                event["destination_ip"]
            )

            grouped[key].append({
                "timestamp": timestamp,
                "port": int(event["destination_port"]),
                "source_ip": event["source_ip"],
                "destination_ip": event["destination_ip"],
            })

        except (KeyError, TypeError, ValueError):
            continue

    alerts = []

    for (source_ip, destination_ip), connections in grouped.items():
        connections.sort(key=lambda item: item["timestamp"])

        left = 0

        for right, current in enumerate(connections):
            while (
                current["timestamp"] -
                connections[left]["timestamp"] > window_seconds
            ):
                left += 1

            window = connections[left:right + 1]
            unique_ports = sorted({
                item["port"] for item in window
            })

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
                        "unique_destination_ports": unique_ports,
                        "port_count": len(unique_ports),
                        "window_seconds": window_seconds,
                    },
                })

                # Avoid producing repeated alerts for the same pair.
                break

    return alerts
