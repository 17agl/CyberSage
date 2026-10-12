from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

AUTH_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    88: "Kerberos",
    445: "SMB",
    3389: "RDP",
    5900: "VNC",
}

# Connection states indicating failed or reset handshakes
FAILED_STATES = {"REJ", "RSTO", "RSTOS0", "S0", "SH", "SHR"}


def _parse_ts(ts_val: Any) -> float:
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            return datetime.fromisoformat(ts_val.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return float(ts_val)
    return 0.0


def detect_brute_force(
    events: List[Dict[str, Any]],
    attempt_threshold: int = 5,
    window_seconds: int = 60,
) -> List[Dict[str, Any]]:
    """
    Detects repeated failed connection attempts to sensitive authentication ports
    (e.g., SSH, RDP, FTP, Telnet, SMB) from the same source to the same destination.
    """
    grouped = defaultdict(list)

    for event in events:
        try:
            dest_port = int(event["destination_port"])
            if dest_port not in AUTH_PORTS:
                continue

            conn_state = event.get("connection_state", "-")
            bytes_rx = event.get("bytes_received") or 0

            # Failed connection or reset attempt
            if conn_state in FAILED_STATES or bytes_rx == 0:
                timestamp = _parse_ts(event.get("timestamp", 0))
                source_ip = event["source_ip"]
                dest_ip = event["destination_ip"]

                grouped[(source_ip, dest_ip, dest_port)].append({
                    "timestamp": timestamp,
                    "service": AUTH_PORTS[dest_port],
                    "conn_state": conn_state,
                    "source_port": event.get("source_port"),
                })
        except (KeyError, TypeError, ValueError):
            continue

    alerts = []

    for (source_ip, dest_ip, dest_port), attempts in grouped.items():
        attempts.sort(key=lambda x: x["timestamp"])
        left = 0

        for right, current in enumerate(attempts):
            while current["timestamp"] - attempts[left]["timestamp"] > window_seconds:
                left += 1

            window = attempts[left:right + 1]
            if len(window) >= attempt_threshold:
                service_name = AUTH_PORTS[dest_port]
                alerts.append({
                    "rule_id": "BRUTE_FORCE_001",
                    "alert_type": "brute_force_login",
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "severity": "high",
                    "timestamp": datetime.fromtimestamp(
                        current["timestamp"]
                    ).astimezone().isoformat(),
                    "evidence": {
                        "target_port": dest_port,
                        "service": service_name,
                        "failed_attempt_count": len(window),
                        "window_seconds": window_seconds,
                        "observed_states": list({x["conn_state"] for x in window}),
                    },
                })
                break

    return alerts
