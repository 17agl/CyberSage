
import csv
import json
from pathlib import Path

from pipeline.normalizer import normalize_zeek_conn
from detectors.port_scan import detect_port_scans
from backend.database import initialize_database, save_alert


INPUT_LOG = "data/processed/conn.log"
OUTPUT_CSV = "data/processed/connections.csv"
OUTPUT_JSON = "data/processed/alerts.json"


def main():
    print("\n=== Detection Pipeline + LLM Alert Triage ===")

    # 1. Normalize Zeek connection logs.
    events = normalize_zeek_conn(INPUT_LOG, OUTPUT_CSV)

    # 2. Detect possible port scans.
    alerts = detect_port_scans(events)

    # 3. Initialize the SQLite database.
    initialize_database()

    # 4. Save detected alerts.
    for alert in alerts:
        alert_id = save_alert(alert)
        print(
            f"[ALERT] ID={alert_id} | "
            f"{alert['alert_type']} | "
            f"{alert['source_ip']} -> "
            f"{alert['destination_ip']}"
        )

    # 5. Save a JSON report.
    output_path = Path(OUTPUT_JSON)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(alerts, file, indent=2)

    print(f"\nEvents analyzed: {len(events)}")
    print(f"Alerts detected: {len(alerts)}")
    print(f"JSON report: {OUTPUT_JSON}")
    print("Pipeline completed.")


if __name__ == "__main__":
    main()
