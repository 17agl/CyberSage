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


def detect_dns_tunneling(
    events: List[Dict[str, Any]],
    payload_threshold: int = 1200,   # Byte payload on DNS flow exceeding typical request
    burst_threshold: int = 8,        # Rapid sequence of anomalous DNS requests
    window_seconds: int = 60,
) -> List[Dict[str, Any]]:
    """
    Detects DNS tunneling indicators such as:
    1. Oversized DNS requests/responses (iodine, dnscat2, Cobalt Strike DNS C2).
    2. High-frequency DNS traffic burst to the same destination resolver.
    """
    dns_events = defaultdict(list)
    large_dns_alerts = []
    seen_large = set()

    for event in events:
        try:
            dest_port = int(event["destination_port"])
            proto = str(event.get("protocol", "")).lower()

            # Check if DNS port or service
            if dest_port == 53 or event.get("service") == "dns":
                source_ip = event["source_ip"]
                dest_ip = event["destination_ip"]
                bytes_sent = event.get("bytes_sent") or 0
                bytes_recv = event.get("bytes_received") or 0
                timestamp = _parse_ts(event.get("timestamp", 0))

                # 1. Single flow with abnormally large payload
                if bytes_sent >= payload_threshold or bytes_recv >= (payload_threshold * 2):
                    key = (source_ip, dest_ip)
                    if key not in seen_large:
                        seen_large.add(key)
                        large_dns_alerts.append({
                            "rule_id": "DNS_TUNNEL_001",
                            "alert_type": "dns_tunneling_indicator",
                            "source_ip": source_ip,
                            "destination_ip": dest_ip,
                            "severity": "high",
                            "timestamp": datetime.fromtimestamp(
                                timestamp
                            ).astimezone().isoformat() if timestamp else event.get("timestamp"),
                            "evidence": {
                                "indicator": "oversized_dns_payload",
                                "bytes_sent": bytes_sent,
                                "bytes_received": bytes_recv,
                                "threshold": payload_threshold,
                                "protocol": proto,
                            },
                        })

                dns_events[(source_ip, dest_ip)].append({
                    "timestamp": timestamp,
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_recv,
                })
        except (KeyError, TypeError, ValueError):
            continue

    # 2. Burst of rapid DNS flows
    burst_alerts = []
    for (source_ip, dest_ip), queries in dns_events.items():
        if (source_ip, dest_ip) in seen_large:
            continue

        queries.sort(key=lambda x: x["timestamp"])
        left = 0

        for right, current in enumerate(queries):
            while current["timestamp"] - queries[left]["timestamp"] > window_seconds:
                left += 1

            window = queries[left:right + 1]
            if len(window) >= burst_threshold:
                total_sent = sum(x["bytes_sent"] for x in window)
                burst_alerts.append({
                    "rule_id": "DNS_TUNNEL_002",
                    "alert_type": "dns_tunneling_indicator",
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "severity": "high",
                    "timestamp": datetime.fromtimestamp(
                        current["timestamp"]
                    ).astimezone().isoformat(),
                    "evidence": {
                        "indicator": "dns_query_burst_rate",
                        "query_count": len(window),
                        "total_bytes_sent": total_sent,
                        "window_seconds": window_seconds,
                    },
                })
                break

    return large_dns_alerts + burst_alerts
