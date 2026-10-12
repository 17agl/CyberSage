import os
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from backend.database import (
    add_analyst_note,
    get_alert_by_id,
    get_alert_metrics,
    get_alerts,
    initialize_database,
    save_alert,
    save_threat_intel,
    save_triage_result,
    update_alert_status,
)
from triage.dispatcher import triage_alert_hybrid, triage_alert_hybrid_with_meta


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="CyberSage — AI-Assisted SOC Platform API",
    description="Backend API for network security detection, ML anomaly detection, Threat Intel, and LLM triage.",
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for flexible dashboard and client connectivity
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TriageRequest(BaseModel):
    alert_id: Optional[int] = None
    alert_type: str = "possible_port_scan"
    source_ip: str = "192.168.1.10"
    destination_ip: str = "192.168.1.20"
    severity: str = "medium"
    evidence: Dict[str, Any] = {}
    mode: str = Field(default="auto", description="'auto', 'real', or 'mock'")


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., description="'new', 'investigating', 'resolved', or 'false_positive'")
    analyst_notes: Optional[str] = None
    assigned_to: Optional[str] = None


class AnalystNoteRequest(BaseModel):
    note: str
    author: str = "SOC Analyst"


@app.get("/")
def root():
    return {
        "project": "CyberSage — AI-Assisted SOC Platform",
        "version": "2.0.0",
        "status": "operational",
        "docs": "/docs",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/alerts")
def list_alerts(
    status: Optional[str] = Query(None, description="Filter by status (new, investigating, resolved, false_positive)"),
    severity: Optional[str] = Query(None, description="Filter by severity (low, medium, high, critical)"),
    alert_type: Optional[str] = Query(None, description="Filter by rule type"),
    search: Optional[str] = Query(None, description="Search across IP or rule ID"),
):
    return get_alerts(status=status, severity=severity, alert_type=alert_type, search=search)


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")
    return alert


@app.patch("/alerts/{alert_id}/status")
def change_alert_status(alert_id: int, request: StatusUpdateRequest):
    valid_statuses = {"new", "investigating", "resolved", "false_positive"}
    if request.status.lower() not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status '{request.status}'. Must be one of: {', '.join(valid_statuses)}",
        )

    success = update_alert_status(
        alert_id=alert_id,
        status=request.status.lower(),
        analyst_notes=request.analyst_notes,
        assigned_to=request.assigned_to,
    )
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")

    return {"message": "Alert status updated", "alert": get_alert_by_id(alert_id)}


@app.post("/alerts/{alert_id}/notes")
def post_analyst_note(alert_id: int, request: AnalystNoteRequest):
    if not request.note.strip():
        raise HTTPException(status_code=400, detail="Note cannot be empty.")

    success = add_analyst_note(alert_id=alert_id, note=request.note, author=request.author)
    if not success:
        raise HTTPException(status_code=404, detail=f"Alert with ID {alert_id} not found.")

    return {"message": "Note added successfully", "alert": get_alert_by_id(alert_id)}


@app.get("/config/llm-status")
def get_llm_status():
    """Returns configuration status for OpenAI API and triage engine."""
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=".env", override=True)
    raw_key = os.getenv("OPENAI_API_KEY", "")
    clean_key = raw_key.strip().strip('<>"\'').strip()
    has_key = bool(clean_key and len(clean_key) > 20 and not clean_key.startswith("your_"))
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    mode = os.getenv("CYBERSAGE_TRIAGE_MODE", "auto")

    return {
        "has_api_key": has_key,
        "masked_key": f"{clean_key[:7]}...{clean_key[-4:]}" if has_key else "Not Configured",
        "model": model,
        "configured_mode": mode,
        "status": "ready" if has_key else "fallback_mock",
    }


@app.post("/alerts/triage")
def triage_alert(request: TriageRequest):
    """
    Analyzes an alert using defensive structured LLM prompting (or deterministic mock).
    If alert_id is provided, findings are persisted directly to the SQLite database.
    """
    try:
        alert_payload = request.model_dump()
        result, meta = triage_alert_hybrid_with_meta(alert_payload, mode=request.mode)
        result_dict = result.model_dump()
        result_dict["engine_used"] = meta.get("engine", "deterministic_expert")
        result_dict["engine_model"] = meta.get("model", "CyberSage Heuristics")
        result_dict["engine_notice"] = meta.get("notice", "")

        # If alert_id is present, persist to database
        if request.alert_id:
            save_triage_result(request.alert_id, result_dict)

        return result_dict
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Triage failed: {exc}") from exc


@app.get("/metrics")
def get_metrics():
    """Returns SOC Key Performance Indicators and metric distributions."""
    return get_alert_metrics()


@app.post("/pipeline/run")
def trigger_pipeline():
    """Executes the end-to-end detection, ML anomaly, and Threat Intel pipeline."""
    try:
        import run_pipeline
        result = run_pipeline.execute_pipeline()
        return {
            "status": "success",
            "message": "Pipeline completed successfully",
            "events_analyzed": result.get("events_count", 0),
            "alerts_generated": result.get("alerts_count", 0),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Pipeline execution failed: {exc}") from exc


@app.get("/analytics/timeline")
def get_attack_timeline():
    """Generates an ordered timeline of detected events and alerts."""
    alerts = get_alerts()
    timeline = []
    for a in alerts:
        timeline.append({
            "id": a["id"],
            "timestamp": a.get("timestamp"),
            "source_ip": a.get("source_ip"),
            "destination_ip": a.get("destination_ip"),
            "alert_type": a.get("alert_type"),
            "severity": a.get("severity"),
            "status": a.get("status"),
            "rule_id": a.get("rule_id"),
        })
    # Sort chronologically
    timeline.sort(key=lambda x: str(x.get("timestamp", "")))
    return timeline


@app.get("/analytics/graph")
def get_network_graph():
    """Generates graph nodes and links representing hosts, targets, and threat relationships."""
    alerts = get_alerts()
    nodes = {}
    links = []

    for a in alerts:
        src = a.get("source_ip", "unknown")
        dst = a.get("destination_ip", "unknown")
        atype = a.get("alert_type", "alert")
        sev = a.get("severity", "medium")

        if src not in nodes:
            nodes[src] = {"id": src, "type": "source", "label": src, "alerts": 0}
        nodes[src]["alerts"] += 1

        if dst not in nodes:
            nodes[dst] = {"id": dst, "type": "destination", "label": dst, "alerts": 0}
        nodes[dst]["alerts"] += 1

        links.append({
            "source": src,
            "target": dst,
            "alert_type": atype,
            "severity": sev,
            "alert_id": a["id"],
        })

    return {"nodes": list(nodes.values()), "links": links}
