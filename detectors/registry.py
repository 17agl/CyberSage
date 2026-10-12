import logging
from typing import Any, Callable, Dict, List

from detectors.brute_force import detect_brute_force
from detectors.data_exfiltration import detect_data_exfiltration
from detectors.dns_tunneling import detect_dns_tunneling
from detectors.port_scan import detect_port_scans
from detectors.suspicious_outbound import detect_suspicious_outbound

logger = logging.getLogger(__name__)

# List of registered detection functions
DETECTOR_REGISTRY: List[Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]] = [
    detect_port_scans,
    detect_brute_force,
    detect_suspicious_outbound,
    detect_data_exfiltration,
    detect_dns_tunneling,
]


def register_detector(detector_func: Callable[[List[Dict[str, Any]]], List[Dict[str, Any]]]) -> None:
    """Dynamically register a new detection function into the pipeline."""
    if detector_func not in DETECTOR_REGISTRY:
        DETECTOR_REGISTRY.append(detector_func)


def run_all_detectors(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Executes all registered detection rules against the normalized network events.
    Returns aggregated list of alerts.
    """
    all_alerts: List[Dict[str, Any]] = []

    for detector in DETECTOR_REGISTRY:
        try:
            alerts = detector(events)
            all_alerts.extend(alerts)
        except Exception as exc:
            logger.error(f"Detector {detector.__name__} failed: {exc}", exc_info=True)

    return all_alerts
