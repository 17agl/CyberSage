from typing import Any, Dict
from triage.schemas import TriageResult


def mock_triage(alert: Dict[str, Any]) -> TriageResult:
    """
    Generates an expert, structured triage assessment without requiring an external LLM API.
    Provides contextualized explanations for port scans, brute force, C2 connections,
    data exfiltration, DNS tunneling, and ML anomaly alerts.
    """
    evidence_data = alert.get("evidence", {})
    alert_type = alert.get("alert_type", "unknown")
    source_ip = alert.get("source_ip", "unknown")
    dest_ip = alert.get("destination_ip", "unknown")
    severity = alert.get("severity", "medium")

    # 1. Single-Target Port Scan
    if alert_type == "possible_port_scan":
        ports = evidence_data.get("unique_destination_ports", [])
        return TriageResult(
            summary=(
                f"Source host {source_ip} probed {len(ports)} unique destination ports "
                f"on {dest_ip} within a brief time window, characteristic of network reconnaissance."
            ),
            likely_cause="Network service enumeration, port vulnerability scanning, or automated network mapping.",
            severity=severity,
            confidence=0.88,
            evidence=[
                f"Source IP: {source_ip}",
                f"Destination IP: {dest_ip}",
                f"Probed ports: {ports}",
                f"Port count: {len(ports)}",
                f"Window duration: {evidence_data.get('window_seconds', 60)}s",
            ],
            false_positive_considerations=[
                "Authorized security vulnerability scan (e.g., Nessus, Qualys)",
                "Internal IT asset discovery or inventory daemon",
                "Developer debugging microservices across multiple ports",
            ],
            recommended_actions=[
                "Verify whether source IP is an authorized vulnerability scanner",
                "Isolate or block source host at internal firewall if unauthorized",
                "Check destination host authentication and application logs for subsequent exploit attempts",
                "Review host ownership in asset inventory",
            ],
            mitre_attack=["T1046 (Network Service Discovery)"],
        )

    # 2. Horizontal Subnet Sweep
    if alert_type == "subnet_sweep":
        target_port = evidence_data.get("target_port", "unknown")
        probed_hosts = evidence_data.get("probed_hosts", [])
        return TriageResult(
            summary=(
                f"Source host {source_ip} swept port {target_port} across {len(probed_hosts)} "
                f"distinct destination hosts on the subnet, indicating lateral movement reconnaissance."
            ),
            likely_cause="Horizontal network sweep to locate vulnerable services (e.g., SSH, SMB, RDP) across the subnet.",
            severity=severity,
            confidence=0.92,
            evidence=[
                f"Source IP: {source_ip}",
                f"Target probed port: {target_port}",
                f"Unique target hosts scanned: {len(probed_hosts)}",
                f"Window duration: {evidence_data.get('window_seconds', 60)}s",
            ],
            false_positive_considerations=[
                "Network monitoring system health check",
                "Configuration management sweep (Ansible, Puppet, Chef)",
            ],
            recommended_actions=[
                "Inspect the source machine for compromise or unauthorized scanning tools (nmap, masscan)",
                "Verify if the source host's account credentials were recently compromised",
                "Enforce network segmentation between user subnets and server zones",
            ],
            mitre_attack=["T1046 (Network Service Discovery)", "T1018 (Remote System Discovery)"],
        )

    # 3. Brute Force Login
    if alert_type == "brute_force_login":
        service = evidence_data.get("service", "Authentication Service")
        attempts = evidence_data.get("failed_attempt_count", 0)
        return TriageResult(
            summary=(
                f"Host {source_ip} initiated {attempts} rapid failed connection attempts "
                f"against {service} (port {evidence_data.get('target_port')}) on {dest_ip}."
            ),
            likely_cause=f"Automated credential stuffing or password brute-force attack targeting {service}.",
            severity=severity,
            confidence=0.95,
            evidence=[
                f"Target service: {service} (Port {evidence_data.get('target_port')})",
                f"Failed attempts recorded: {attempts}",
                f"Observed connection states: {evidence_data.get('observed_states', [])}",
                f"Attacker source: {source_ip} -> Target: {dest_ip}",
            ],
            false_positive_considerations=[
                "Misconfigured service with expired service account password",
                "Automated backup script attempting authentication with stale key",
            ],
            recommended_actions=[
                f"Check {service} authentication logs on {dest_ip} for specific targeted usernames",
                "Apply rate limiting and fail2ban / IP shunning on external perimeter",
                "Verify whether any login attempt succeeded following the failed burst",
                "Enforce multi-factor authentication (MFA) on the affected service",
            ],
            mitre_attack=["T1110 (Brute Force)", "T1110.001 (Password Guessing)"],
        )

    # 4. Suspicious Outbound Connection
    if alert_type == "suspicious_outbound_connection":
        threat = evidence_data.get("threat_category", "High-risk port")
        port = evidence_data.get("destination_port")
        return TriageResult(
            summary=(
                f"Internal host {source_ip} established an outbound connection to "
                f"{dest_ip}:{port} associated with {threat}."
            ),
            likely_cause=f"Command and Control (C2) communication, cryptocurrency mining, or anonymized proxy traffic ({threat}).",
            severity=severity,
            confidence=0.91,
            evidence=[
                f"Internal host: {source_ip}",
                f"Destination: {dest_ip}:{port}",
                f"Identified category: {threat}",
                f"Protocol: {evidence_data.get('protocol', 'tcp')}",
            ],
            false_positive_considerations=[
                "Legitimate IRC or specialized developer application",
                "Authorized privacy research proxy",
            ],
            recommended_actions=[
                "Immediately quarantine or isolate source host from internal network",
                "Inspect running processes on source host for unauthorized miner or backdoor executable",
                "Block outbound access to the destination IP and port at the perimeter firewall",
                "Extract memory or triage artifact from source host for forensic analysis",
            ],
            mitre_attack=["T1071 (Application Layer Protocol)", "T1571 (Non-Standard Port)", "T1090 (Proxy)"],
        )

    # 5. Data Exfiltration / Unusual Volume
    if alert_type == "unusual_traffic_volume":
        sent = evidence_data.get("human_readable_sent", "Large payload")
        ratio = evidence_data.get("asymmetry_ratio", 0)
        return TriageResult(
            summary=(
                f"Internal host {source_ip} transmitted {sent} to external host {dest_ip} "
                f"with severe outbound transfer asymmetry (ratio {ratio}x)."
            ),
            likely_cause="Potential data exfiltration, unauthorized archive staging, or unauthorized cloud backup.",
            severity=severity,
            confidence=0.89,
            evidence=[
                f"Total bytes sent: {sent}",
                f"Upload asymmetry ratio: {ratio}x",
                f"Destination endpoint: {dest_ip}:{evidence_data.get('destination_port')}",
                f"Protocol: {evidence_data.get('protocol', 'tcp')}",
            ],
            false_positive_considerations=[
                "Authorized cloud storage backup (e.g., OneDrive, Google Drive, AWS S3)",
                "OS or application software update upload",
                "Large video upload or streaming conference session",
            ],
            recommended_actions=[
                "Review user activity and file system modification logs on the source host around alert timestamp",
                "Identify what files were accessed or compressed (e.g. .zip, .7z, .tar) prior to transfer",
                "Check DLP (Data Loss Prevention) sensors for matching sensitive document signatures",
                "Block further outbound transfers to the destination IP pending authorization review",
            ],
            mitre_attack=["T1048 (Exfiltration Over Alternative Protocol)", "T1567 (Exfiltration Over Web Service)"],
        )

    # 6. DNS Tunneling Indicator
    if alert_type == "dns_tunneling_indicator":
        indicator = evidence_data.get("indicator", "DNS covert channel")
        return TriageResult(
            summary=(
                f"DNS traffic between {source_ip} and {dest_ip} exhibited {indicator}, "
                f"exceeding standard protocol baseline."
            ),
            likely_cause="DNS tunneling for command-and-control beaconing or slow data exfiltration (e.g., dnscat2, iodine).",
            severity=severity,
            confidence=0.90,
            evidence=[
                f"Observed pattern: {indicator}",
                f"Source host: {source_ip} -> Resolver: {dest_ip}",
                f"Payload details: {evidence_data}",
            ],
            false_positive_considerations=[
                "DNSSEC resolution containing oversized cryptographic resource records",
                "Internal domain controller zone transfer over port 53",
            ],
            recommended_actions=[
                "Inspect passive DNS logs for high-entropy subdomains or repetitive TXT record queries",
                "Enforce internal DNS forwarding and block direct outbound port 53 traffic from workstations",
                "Check endpoint process parentage for PowerShell, cmd, or suspicious network daemons",
            ],
            mitre_attack=["T1071.004 (DNS)", "T1572 (Protocol Tunneling)", "T1048.003 (Exfiltration Over DNS)"],
        )

    # 7. Machine Learning Anomaly
    if alert_type == "ml_traffic_anomaly":
        score = evidence_data.get("anomaly_score", 0.0)
        factors = evidence_data.get("contributing_factors", [])
        return TriageResult(
            summary=(
                f"Unsupervised Isolation Forest detected statistical flow anomaly between "
                f"{source_ip} and {dest_ip} (anomaly score: {score:.1%})."
            ),
            likely_cause="Network behavior significantly deviated from learned baseline distribution metrics.",
            severity=severity,
            confidence=round(min(float(score), 0.95), 2),
            evidence=[
                f"Model: {evidence_data.get('model', 'Isolation Forest')}",
                f"Normalized anomaly score: {score}",
                f"Contributing deviations: {', '.join(factors) if factors else 'Multivariate outlier'}",
                f"Flow parameters: {evidence_data.get('bytes_sent', 0)} bytes sent, port {evidence_data.get('destination_port')}",
            ],
            false_positive_considerations=[
                "Rare but legitimate administrative operation or batch script run",
                "New application deployment not represented in initial baseline training set",
            ],
            recommended_actions=[
                "Cross-reference this anomaly with concurrent rule-based alerts",
                "Review the endpoint processes active at the time of the flow",
                "If confirmed benign, incorporate flow profile into retraining dataset",
            ],
            mitre_attack=["T1071 (Application Layer Protocol)", "T1046 (Network Service Discovery)"],
        )

    # Fallback generic investigation
    return TriageResult(
        summary=f"Alert type '{alert_type}' generated by security sensors between {source_ip} and {dest_ip}.",
        likely_cause="Network event triggered defensive security heuristics; requires analyst investigation.",
        severity=severity,
        confidence=0.60,
        evidence=[
            f"Source IP: {source_ip}",
            f"Destination IP: {dest_ip}",
            f"Raw evidence: {str(evidence_data)}",
        ],
        false_positive_considerations=["Unclassified benign network behavior."],
        recommended_actions=[
            "Inspect raw Zeek connection records",
            "Correlate with endpoint and firewall logs",
            "Escalate to SOC Tier 2 if malicious indicators are observed",
        ],
        mitre_attack=[],
    )
