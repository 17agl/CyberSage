
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from backend.database import get_alerts
from triage.real_llm_client import triage_with_llm


app = FastAPI(
    title="Detection Pipeline + LLM Alert Triage",
    description="API for network security alerts and triage.",
    version="1.0.0",
)


class TriageRequest(BaseModel):
    alert_type: str
    source_ip: str
    destination_ip: str
    severity: str = "medium"
    evidence: dict = {}


@app.get("/")
def root():
    return {
        "project": "Detection Pipeline + LLM Alert Triage",
        "status": "running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/alerts")
def list_alerts():
    return get_alerts()


@app.post("/alerts/triage")
def triage_alert(request: TriageRequest):
    try:
        result = triage_with_llm(request.model_dump())
        return result.model_dump()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Triage failed: {exc}",
        ) from exc
