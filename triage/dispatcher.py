import logging
import os
from typing import Any, Dict, Tuple

from dotenv import load_dotenv

from triage.llm_client import mock_triage
from triage.schemas import TriageResult

load_dotenv(dotenv_path=".env")
logger = logging.getLogger(__name__)


def triage_alert_hybrid_with_meta(
    alert: Dict[str, Any],
    mode: str = "auto"
) -> Tuple[TriageResult, Dict[str, Any]]:
    """
    Intelligent triage router with detailed execution metadata:
    - mode="mock": uses deterministic rule-based mock triage
    - mode="real": forces OpenAI LLM triage (raises if unconfigured/failed)
    - mode="auto": attempts OpenAI LLM triage if OPENAI_API_KEY is configured;
                   falls back gracefully to expert deterministic triage if key is invalid.
    """
    raw_key = os.getenv("OPENAI_API_KEY", "")
    api_key = raw_key.strip().strip('<>"\'').strip()
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini").strip()
    configured_mode = os.getenv("CYBERSAGE_TRIAGE_MODE", mode).lower()

    has_valid_format = bool(api_key and len(api_key) > 20 and not api_key.startswith("your_"))

    if configured_mode == "mock" or (configured_mode == "auto" and not has_valid_format):
        res = mock_triage(alert)
        return res, {
            "engine": "deterministic_expert",
            "model": "CyberSage Expert Rule Heuristics",
            "notice": "Offline mode active (deterministic security heuristics).",
        }

    # Attempt OpenAI Triage
    try:
        from triage.real_llm_client import triage_with_llm
        res = triage_with_llm(alert)
        return res, {
            "engine": "openai",
            "model": model,
            "notice": f"AI investigation completed via OpenAI ({model}).",
        }
    except Exception as exc:
        err_msg = str(exc)
        logger.warning(f"OpenAI triage failed: {err_msg}. Activating deterministic expert triage.")

        if configured_mode == "real":
            raise exc

        res = mock_triage(alert)
        return res, {
            "engine": "deterministic_expert",
            "model": "CyberSage Expert Rule Heuristics",
            "notice": f"OpenAI authentication/quota error ({err_msg[:90]}...). High-fidelity deterministic triage displayed.",
        }


def triage_alert_hybrid(alert: Dict[str, Any], mode: str = "auto") -> TriageResult:
    """Backward compatibility wrapper returning only TriageResult."""
    result, _ = triage_alert_hybrid_with_meta(alert, mode=mode)
    return result
