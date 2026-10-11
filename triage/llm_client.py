
from triage.schemas import TriageResult


def mock_triage(alert: dict) -> TriageResult:
    """Generate a structured triage result without calling an LLM."""

    evidence_data = alert.get("evidence", {})
    alert_type = alert.get("alert_type", "unknown")
    source_ip = alert.get("source_ip", "unknown")
    destination_ip = alert.get("destination_ip", "unknown")

    if alert_type == "possible_port_scan":
        ports = evidence_data.get("unique_destination_ports", [])

        return TriageResult(
            summary=(
                f"Host {source_ip} contacted multiple ports on "
                f"{destination_ip}. This activity may indicate "
                "port scanning."
            ),
            likely_cause=(
                "Possible service discovery or reconnaissance. "
                "The alert alone does not prove malicious intent."
            ),
            severity=alert.get("severity", "medium"),
            confidence=0.70,
            evidence=[
                f"Source IP: {source_ip}",
                f"Destination IP: {destination_ip}",
                f"Distinct destination ports: {ports}",
                f"Port count: {len(ports)}",
            ],
            false_positive_considerations=[
                "Authorized vulnerability scanning",
                "Internal asset inventory tools",
                "Legitimate applications contacting multiple services",
            ],
            recommended_actions=[
                "Review source and destination asset ownership",
                "Check surrounding connection and authentication logs",
                "Compare the activity with approved scanning schedules",
                "Escalate for analyst review if the activity is unauthorized",
            ],
            mitre_attack=["T1046"],
        )

    return TriageResult(
        summary=f"Alert type '{alert_type}' requires further investigation.",
        likely_cause="Insufficient information to determine the cause.",
        severity=alert.get("severity", "low"),
        confidence=0.30,
        evidence=[
            f"Source IP: {source_ip}",
            f"Destination IP: {destination_ip}",
        ],
        false_positive_considerations=[
            "The alert may be caused by legitimate network activity."
        ],
        recommended_actions=[
            "Review the raw network events",
            "Correlate with other alerts",
            "Request analyst review",
        ],
        mitre_attack=[],
    )
