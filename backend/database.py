import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DB_PATH = Path("data/alerts.db")


def set_db_path(path: Path | str) -> None:
    """Allow configuring the database path (useful for testing)."""
    global DB_PATH
    DB_PATH = Path(path)


@contextmanager
def get_db():
    """Context manager for SQLite connections that guarantees proper closure."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    try:
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
                status TEXT NOT NULL DEFAULT 'new',
                analyst_notes TEXT DEFAULT '',
                assigned_to TEXT DEFAULT 'Unassigned',
                triage_result_json TEXT DEFAULT '',
                threat_intel_json TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            )
        """)
        yield connection
        connection.commit()
    finally:
        connection.close()


def get_connection():
    """Backward compatibility connection getter."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    """Initializes tables and ensures any missing columns are migrated."""
    with get_db() as connection:
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
                status TEXT NOT NULL DEFAULT 'new',
                analyst_notes TEXT DEFAULT '',
                assigned_to TEXT DEFAULT 'Unassigned',
                triage_result_json TEXT DEFAULT '',
                threat_intel_json TEXT DEFAULT '',
                updated_at TEXT DEFAULT ''
            )
        """)

        # Graceful migration for existing databases with older schemas
        existing_cols = {
            row["name"] for row in connection.execute("PRAGMA table_info(alerts)").fetchall()
        }
        for col, col_type, default in [
            ("analyst_notes", "TEXT", "''"),
            ("assigned_to", "TEXT", "'Unassigned'"),
            ("triage_result_json", "TEXT", "''"),
            ("threat_intel_json", "TEXT", "''"),
            ("updated_at", "TEXT", "''"),
        ]:
            if col not in existing_cols:
                connection.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_type} DEFAULT {default}")

    print(f"Database initialized: {DB_PATH}")


def save_alert(alert: Dict[str, Any]) -> int:
    """Saves a detected alert and returns its new ID."""
    evidence = json.dumps(alert.get("evidence", {}))
    triage_result = json.dumps(alert.get("triage_result", {})) if alert.get("triage_result") else ""
    threat_intel = json.dumps(alert.get("threat_intel", {})) if alert.get("threat_intel") else ""
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db() as connection:
        cursor = connection.execute("""
            INSERT INTO alerts (
                rule_id, alert_type, source_ip, destination_ip,
                severity, timestamp, evidence_json, status,
                analyst_notes, assigned_to, triage_result_json,
                threat_intel_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert["rule_id"],
            alert["alert_type"],
            alert["source_ip"],
            alert["destination_ip"],
            alert.get("severity", "medium"),
            alert.get("timestamp", now_iso),
            evidence,
            alert.get("status", "new"),
            alert.get("analyst_notes", ""),
            alert.get("assigned_to", "Unassigned"),
            triage_result,
            threat_intel,
            now_iso,
        ))

        return cursor.lastrowid


def _format_alert_row(row: sqlite3.Row) -> Dict[str, Any]:
    """Helper to convert sqlite3.Row to full dictionary with parsed JSON fields."""
    alert = dict(row)
    # Parse evidence
    if "evidence_json" in alert:
        raw_evidence = alert.pop("evidence_json", "{}")
        try:
            alert["evidence"] = json.loads(raw_evidence) if raw_evidence else {}
        except (json.JSONDecodeError, TypeError):
            alert["evidence"] = {}

    # Parse triage result
    raw_triage = alert.pop("triage_result_json", "")
    try:
        alert["triage_result"] = json.loads(raw_triage) if raw_triage else None
    except (json.JSONDecodeError, TypeError):
        alert["triage_result"] = None

    # Parse threat intel
    raw_intel = alert.pop("threat_intel_json", "")
    try:
        alert["threat_intel"] = json.loads(raw_intel) if raw_intel else None
    except (json.JSONDecodeError, TypeError):
        alert["threat_intel"] = None

    return alert


def get_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    search: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Retrieves alerts with optional filtering and ordering by most recent first."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if status and status.lower() != "all":
        query += " AND LOWER(status) = LOWER(?)"
        params.append(status)

    if severity and severity.lower() != "all":
        query += " AND LOWER(severity) = LOWER(?)"
        params.append(severity)

    if alert_type and alert_type.lower() != "all":
        query += " AND alert_type = ?"
        params.append(alert_type)

    if search:
        search_pattern = f"%{search.strip()}%"
        query += " AND (source_ip LIKE ? OR destination_ip LIKE ? OR rule_id LIKE ? OR alert_type LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern])

    query += " ORDER BY id DESC"

    with get_db() as connection:
        rows = connection.execute(query, params).fetchall()

    return [_format_alert_row(row) for row in rows]


def get_alert_by_id(alert_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single alert by its primary key ID."""
    with get_db() as connection:
        row = connection.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()

    if not row:
        return None
    return _format_alert_row(row)


def update_alert_status(
    alert_id: int,
    status: str,
    analyst_notes: Optional[str] = None,
    assigned_to: Optional[str] = None,
) -> bool:
    """Updates status, assignment, and notes for an alert."""
    now_iso = datetime.now(timezone.utc).isoformat()
    current = get_alert_by_id(alert_id)
    if not current:
        return False

    notes = analyst_notes if analyst_notes is not None else current.get("analyst_notes", "")
    assigned = assigned_to if assigned_to is not None else current.get("assigned_to", "Unassigned")

    with get_db() as connection:
        cursor = connection.execute("""
            UPDATE alerts
            SET status = ?, analyst_notes = ?, assigned_to = ?, updated_at = ?
            WHERE id = ?
        """, (status, notes, assigned, now_iso, alert_id))
        return cursor.rowcount > 0


def add_analyst_note(alert_id: int, note: str, author: str = "Analyst") -> bool:
    """Appends a timestamped note to the alert's investigation record."""
    current = get_alert_by_id(alert_id)
    if not current:
        return False

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    formatted_entry = f"[{now_str}] {author}: {note.strip()}"

    existing_notes = current.get("analyst_notes", "")
    updated_notes = f"{existing_notes}\n{formatted_entry}".strip() if existing_notes else formatted_entry

    return update_alert_status(alert_id, current.get("status", "new"), analyst_notes=updated_notes)


def save_triage_result(alert_id: int, triage_result: Dict[str, Any]) -> bool:
    """Persists structured LLM or mock triage findings to the alert record."""
    now_iso = datetime.now(timezone.utc).isoformat()
    triage_json = json.dumps(triage_result)

    with get_db() as connection:
        cursor = connection.execute("""
            UPDATE alerts
            SET triage_result_json = ?, updated_at = ?
            WHERE id = ?
        """, (triage_json, now_iso, alert_id))
        return cursor.rowcount > 0


def save_threat_intel(alert_id: int, threat_intel: Dict[str, Any]) -> bool:
    """Persists threat intelligence enrichment to the alert record."""
    now_iso = datetime.now(timezone.utc).isoformat()
    intel_json = json.dumps(threat_intel)

    with get_db() as connection:
        cursor = connection.execute("""
            UPDATE alerts
            SET threat_intel_json = ?, updated_at = ?
            WHERE id = ?
        """, (intel_json, now_iso, alert_id))
        return cursor.rowcount > 0


def get_alert_metrics() -> Dict[str, Any]:
    """Calculates summary KPIs and metric breakdowns for the SOC dashboard."""
    alerts = get_alerts()
    total = len(alerts)
    by_status = {"new": 0, "investigating": 0, "resolved": 0, "false_positive": 0}
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    by_type = {}
    source_counts = {}

    for a in alerts:
        st = a.get("status", "new").lower()
        by_status[st] = by_status.get(st, 0) + 1

        sev = a.get("severity", "medium").lower()
        by_severity[sev] = by_severity.get(sev, 0) + 1

        atype = a.get("alert_type", "unknown")
        by_type[atype] = by_type.get(atype, 0) + 1

        src = a.get("source_ip", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1

    top_sources = sorted(source_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total_alerts": total,
        "high_or_critical": by_severity.get("high", 0) + by_severity.get("critical", 0),
        "new_alerts": by_status.get("new", 0),
        "investigating": by_status.get("investigating", 0),
        "resolved": by_status.get("resolved", 0),
        "false_positive": by_status.get("false_positive", 0),
        "by_status": by_status,
        "by_severity": by_severity,
        "by_type": by_type,
        "top_sources": dict(top_sources),
    }
