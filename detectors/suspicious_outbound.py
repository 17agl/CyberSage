from datetime import datetime
from typing import Any, Dict, List

# High risk ports associated with C2, proxies, cryptominers, and malicious services
SUSPICIOUS_PORTS = {
    6667: "IRC (potential botnet C2)",
    7000: "IRC SSL (potential botnet C2)",
    9001: "Tor Relay / Directory",
    9050: "Tor SOCKS Proxy",
    9051: "Tor Control Port",
    9150: "Tor Browser SOCKS",
    3333: "Stratum / Crypto Mining Pool",
    4444: "Metasploit default listener / C2",
    5555: "Android ADB remote exploitation / C2",
    8332: "Bitcoin RPC interface",
    8333: "Bitcoin P2P network",
    14444: "Monero / Crypto Mining Pool",
    31337: "Back Orifice / Legacy Trojan C2",
}


def _parse_ts(ts_val: Any) -> float:
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            return datetime.fromisoformat(ts_val.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return float(ts_val)
    return 0.0


def detect_suspicious_outbound(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Detects outbound connections directed to known high-risk, proxy, mining, or C2 ports.
    """
    seen_pairs = set()
    alerts = []

    for event in events:
        try:
            dest_port = int(event["destination_port"])
            if dest_port in SUSPICIOUS_PORTS:
                source_ip = event["source_ip"]
                dest_ip = event["destination_ip"]
                pair_key = (source_ip, dest_ip, dest_port)

                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                timestamp = _parse_ts(event.get("timestamp", 0))
                threat_desc = SUSPICIOUS_PORTS[dest_port]

                alerts.append({
                    "rule_id": "SUSPICIOUS_OUTBOUND_001",
                    "alert_type": "suspicious_outbound_connection",
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "severity": "high",
                    "timestamp": datetime.fromtimestamp(
                        timestamp
                    ).astimezone().isoformat() if timestamp else event.get("timestamp"),
                    "evidence": {
                        "destination_port": dest_port,
                        "threat_category": threat_desc,
                        "protocol": event.get("protocol", "tcp"),
                        "connection_state": event.get("connection_state", "-"),
                        "bytes_sent": event.get("bytes_sent"),
                        "bytes_received": event.get("bytes_received"),
                    },
                })
        except (KeyError, TypeError, ValueError):
            continue

    return alerts
