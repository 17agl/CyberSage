
import json
import sqlite3
from pathlib import Path

DB_PATH = Path("data/alerts.db")


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'new'
            )
        """)

    print(f"Database initialized: {DB_PATH}")


def save_alert(alert):
    evidence = json.dumps(alert.get("evidence", {}))

    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO alerts (
                rule_id, alert_type, source_ip, destination_ip,
                severity, timestamp, evidence_json, status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["rule_id"],
            alert["alert_type"],
            alert["source_ip"],
            alert["destination_ip"],
            alert["severity"],
            alert["timestamp"],
            evidence,
            "new",
        ))

        return cursor.lastrowid


def get_alerts():
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT * FROM alerts ORDER BY id DESC
        """).fetchall()

    results = []

    for row in rows:
        alert = dict(row)
        alert["evidence"] = json.loads(alert.pop("evidence_json"))
        results.append(alert)

    return results
