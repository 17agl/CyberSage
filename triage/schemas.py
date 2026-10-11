
from typing import Literal
from pydantic import BaseModel, Field


class TriageResult(BaseModel):
    summary: str
    likely_cause: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str]
    false_positive_considerations: list[str]
    recommended_actions: list[str]
    mitre_attack: list[str]
