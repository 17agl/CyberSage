import json
import logging
from pathlib import Path
from typing import Any, Dict, List

from backend.database import initialize_database, save_alert
from detectors.registry import run_all_detectors
from ml.anomaly_detector import NetworkAnomalyDetector
from pipeline.normalizer import normalize_zeek_conn
from tests.create_sample_traffic import generate_sample_traffic
from threat_intel.enricher import enrich_alert
from triage.dispatcher import triage_alert_hybrid

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("CyberSagePipeline")

INPUT_LOG = Path("data/processed/conn.log")
OUTPUT_CSV = Path("data/processed/connections.csv")
OUTPUT_JSON = Path("data/processed/alerts.json")


def execute_pipeline(
    input_log: Path = INPUT_LOG,
    output_csv: Path = OUTPUT_CSV,
    output_json: Path = OUTPUT_JSON,
    auto_generate_if_missing: bool = True,
    perform_auto_triage: bool = True,
) -> Dict[str, Any]:
    """
    Executes the complete CyberSage Security Pipeline:
    1. Ingest & Normalize Zeek Connection Logs.
    2. Execute Rule-Based Threat Detectors (Port scan, Subnet sweep, Brute-force, Exfil, C2, DNS tunnel).
    3. Execute Machine Learning Isolation Forest Anomaly Detection.
    4. Enrich alerts with Public/Private IP Threat Intelligence.
    5. Perform defensive AI/Mock Triage & map MITRE ATT&CK.
    6. Persist enriched alerts into SQLite and export JSON report.
    """
    logger.info("=== Starting CyberSage SOC Detection & Triage Pipeline ===")

    # Step 0: Ensure input logs exist; generate multi-vector synthetic data if missing
    if not input_log.exists():
        if auto_generate_if_missing:
            logger.warning(f"Input log {input_log} not found. Generating synthetic multi-threat traffic...")
            generate_sample_traffic(input_log)
        else:
            raise FileNotFoundError(f"Input log not found: {input_log}")

    # Step 1: Normalize Zeek Connection Logs to CSV and structured event dicts
    logger.info(f"Normalizing Zeek logs from: {input_log}")
    events = normalize_zeek_conn(str(input_log), str(output_csv))
    logger.info(f"Normalized {len(events)} connection events.")

    # Step 2: Rule-Based Detection Engine
    logger.info("Running registered rule-based threat detectors...")
    rule_alerts = run_all_detectors(events)
    logger.info(f"Rule-based detectors triggered {len(rule_alerts)} alerts.")

    # Step 3: Machine Learning Anomaly Detection
    logger.info("Running Unsupervised Isolation Forest ML anomaly detector...")
    ml_detector = NetworkAnomalyDetector(contamination=0.08)
    ml_alerts = ml_detector.detect_anomalies(events)
    logger.info(f"Machine learning model flagged {len(ml_alerts)} anomalous flows.")

    # Step 4: Aggregate All Detections
    combined_alerts: List[Dict[str, Any]] = rule_alerts + ml_alerts

    # Step 5: Threat Intelligence Enrichment & Automated Triage
    enriched_alerts: List[Dict[str, Any]] = []
    logger.info("Enriching alerts with Threat Intelligence & AI/Mock Triage...")

    for alert in combined_alerts:
        # Threat Intelligence enrichment
        enriched = enrich_alert(alert)

        # AI-assisted structured triage
        if perform_auto_triage:
            try:
                triage_res = triage_alert_hybrid(enriched, mode="auto")
                enriched["triage_result"] = triage_res.model_dump()
            except Exception as exc:
                logger.warning(f"Auto-triage skipped for alert {enriched.get('rule_id')}: {exc}")

        enriched_alerts.append(enriched)

    # Step 6: Initialize SQLite Database and Persist
    initialize_database()
    saved_ids = []
    for alert in enriched_alerts:
        alert_id = save_alert(alert)
        saved_ids.append(alert_id)
        logger.info(
            f" [ALERT #{alert_id}] {alert['rule_id']} | "
            f"Severity={alert['severity'].upper()} | "
            f"{alert['alert_type']} | "
            f"{alert['source_ip']} -> {alert['destination_ip']}"
        )

    # Step 7: Export JSON Report
    output_json.parent.mkdir(parents=True, exist_ok=True)
    with output_json.open("w", encoding="utf-8") as file:
        json.dump(enriched_alerts, file, indent=2)

    logger.info(f"Pipeline finished. Saved {len(enriched_alerts)} alerts to SQLite and {output_json}.")

    return {
        "status": "success",
        "events_count": len(events),
        "alerts_count": len(enriched_alerts),
        "alerts": enriched_alerts,
        "saved_ids": saved_ids,
    }


def main():
    execute_pipeline()


if __name__ == "__main__":
    main()
