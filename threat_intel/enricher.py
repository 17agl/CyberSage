import ipaddress
from typing import Any, Dict, List, Optional

RFC_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

# Known threat indicators (simulated public intelligence feeds like AbuseIPDB / AlienVault / Tor)
KNOWN_PUBLIC_THREATS: Dict[str, Dict[str, Any]] = {
    "198.51.100.23": {
        "reputation": "malicious",
        "threat_score": 95,
        "threat_tags": ["Known C2 Server", "Cobalt Strike Beacon", "Ransomware Distribution"],
        "country": "NL",
        "asn": "AS49981 WorldStream B.V.",
    },
    "203.0.113.88": {
        "reputation": "malicious",
        "threat_score": 88,
        "threat_tags": ["Mirai Botnet Scanner", "SSH Brute-Forcer"],
        "country": "RU",
        "asn": "AS12389 Rostelecom",
    },
    "185.220.101.5": {
        "reputation": "suspicious",
        "threat_score": 75,
        "threat_tags": ["Tor Exit Node", "Anonymization Service"],
        "country": "DE",
        "asn": "AS208298 Zwiebelfreunde",
    },
    "45.33.32.156": {
        "reputation": "suspicious",
        "threat_score": 60,
        "threat_tags": ["Internet Wide Port Scanner", "Shadowserver/Research Probe"],
        "country": "US",
        "asn": "AS63949 Linode, LLC",
    },
    "8.8.8.8": {
        "reputation": "clean",
        "threat_score": 0,
        "threat_tags": ["Public DNS Resolver", "Google Anycast"],
        "country": "US",
        "asn": "AS15169 Google LLC",
    },
    "1.1.1.1": {
        "reputation": "clean",
        "threat_score": 0,
        "threat_tags": ["Public DNS Resolver", "Cloudflare Anycast"],
        "country": "US",
        "asn": "AS13335 Cloudflare, Inc.",
    },
}


def is_private_ip(ip_str: str) -> bool:
    """
    Checks whether an IP is in RFC 1918, loopback, or link-local private space.
    Strictly differentiates internal enterprise IPs from external public IPs.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in RFC_PRIVATE_NETWORKS)
    except ValueError:
        return False


def get_ip_reputation(ip_str: str) -> Dict[str, Any]:
    """
    Evaluates reputation for an IP address.
    Strictly safeguards RFC 1918 private IPs from false positive external threat categorization.
    """
    cleaned_ip = ip_str.strip()

    if not cleaned_ip or cleaned_ip.lower() in ("unknown", "-"):
        return {
            "ip": cleaned_ip,
            "scope": "Unknown",
            "is_private": False,
            "reputation": "unknown",
            "threat_score": 0,
            "threat_tags": [],
            "notes": "No valid IP provided",
        }

    # Internal private IP check
    if is_private_ip(cleaned_ip):
        return {
            "ip": cleaned_ip,
            "scope": "Internal RFC 1918",
            "is_private": True,
            "reputation": "internal",
            "threat_score": 0,
            "threat_tags": ["Internal Asset", "Private Network"],
            "notes": "Private network address. Not subject to external threat list matches.",
        }

    # Public IP: lookup in intelligence database
    if cleaned_ip in KNOWN_PUBLIC_THREATS:
        match = KNOWN_PUBLIC_THREATS[cleaned_ip]
        return {
            "ip": cleaned_ip,
            "scope": "External Public",
            "is_private": False,
            "reputation": match["reputation"],
            "threat_score": match["threat_score"],
            "threat_tags": match["threat_tags"],
            "country": match.get("country", "Unknown"),
            "asn": match.get("asn", "Unknown"),
            "notes": "Matched known Threat Intelligence reputation database.",
        }

    # Unknown public IP
    return {
        "ip": cleaned_ip,
        "scope": "External Public",
        "is_private": False,
        "reputation": "unrated",
        "threat_score": 10,
        "threat_tags": ["External Host", "Unrated"],
        "country": "Unknown",
        "asn": "Unknown",
        "notes": "External public IP with no historical malicious report on record.",
    }


def enrich_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enriches an alert dictionary with Threat Intelligence context for both
    source and destination IP addresses.
    """
    source_ip = alert.get("source_ip", "")
    dest_ip = alert.get("destination_ip", "")

    src_intel = get_ip_reputation(source_ip)
    dst_intel = get_ip_reputation(dest_ip)

    highest_score = max(src_intel.get("threat_score", 0), dst_intel.get("threat_score", 0))

    alert["threat_intel"] = {
        "source": src_intel,
        "destination": dst_intel,
        "max_threat_score": highest_score,
        "is_external_involved": (not src_intel["is_private"]) or (not dst_intel["is_private"]),
    }

    # If public IP has high threat score, elevate severity if not already high/critical
    if highest_score >= 80 and alert.get("severity") in ["low", "medium"]:
        alert["severity"] = "high"

    return alert
