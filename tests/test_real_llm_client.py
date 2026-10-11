
import json
from unittest.mock import MagicMock, patch

import pytest

from triage.real_llm_client import triage_with_llm


@pytest.fixture
def valid_llm_response():
    return {
        "summary": "Multiple destination ports were contacted.",
        "likely_cause": "Possible port scanning activity.",
        "severity": "medium",
        "confidence": 0.85,
        "evidence": [
            "Five unique destination ports were observed."
        ],
        "false_positive_considerations": [
            "Could be an authorized vulnerability scan."
        ],
        "recommended_actions": [
            "Review the source host and surrounding network logs."
        ],
        "mitre_attack": ["T1046"],
    }


def test_real_llm_client_validates_response(valid_llm_response):
    mock_response = MagicMock()
    mock_response.choices[0].message.content = json.dumps(
        valid_llm_response
    )

    with patch(
        "triage.real_llm_client.OpenAI"
    ) as mock_openai:
        mock_client = mock_openai.return_value
        mock_client.chat.completions.create.return_value = mock_response

        with patch.dict(
            "os.environ",
            {"OPENAI_API_KEY": "test-key"},
        ):
            result = triage_with_llm({
                "alert_type": "possible_port_scan",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "severity": "medium",
                "evidence": {"port_count": 5},
            })

    assert result.summary == valid_llm_response["summary"]
    assert result.severity == "medium"
    assert result.confidence == 0.85
    mock_client.chat.completions.create.assert_called_once()


def test_real_llm_client_rejects_invalid_response():
    invalid_response = {
        "summary": "Test",
        "likely_cause": "Unknown",
        "severity": "impossible",
        "confidence": 2.0,
        "evidence": [],
        "false_positive_considerations": [],
        "recommended_actions": [],
        "mitre_attack": [],
    }

    mock_response = MagicMock()
    mock_response.choices[0].message.content = json.dumps(
        invalid_response
    )

    with patch(
        "triage.real_llm_client.OpenAI"
    ) as mock_openai:
        mock_client = mock_openai.return_value
        mock_client.chat.completions.create.return_value = mock_response

        with patch.dict(
            "os.environ",
            {"OPENAI_API_KEY": "test-key"},
        ):
            with pytest.raises(ValueError):
                triage_with_llm({
                    "alert_type": "possible_port_scan",
                    "source_ip": "192.168.1.10",
                    "destination_ip": "192.168.1.20",
                    "severity": "medium",
                    "evidence": {},
                })


def test_real_llm_client_requires_api_key():
    with patch.dict("os.environ", {}, clear=True):
        with pytest.raises(RuntimeError, match="OPENAI_API_KEY"):
            triage_with_llm({
                "alert_type": "possible_port_scan",
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "severity": "medium",
                "evidence": {},
            })
