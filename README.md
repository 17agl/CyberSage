# 🛡️ CyberSage — Detection Pipeline + LLM Alert Triage

**Turning network security logs into actionable security insights.**

CyberSage is a cybersecurity project that processes network connection logs, detects suspicious activity using rule-based detection, stores security alerts, and uses Large Language Models (LLMs) to assist with alert investigation and triage.

The project combines network security monitoring, Python-based detection, a REST API, structured LLM responses, and an interactive dashboard to help analysts understand potential threats more efficiently.

## ✨ Features

- **Network Log Processing:** Parses Zeek connection logs and normalizes network events into structured CSV data.
- **Port Scan Detection:** Identifies potential port scanning by detecting multiple unique destination ports contacted by the same source within a configurable time window.
- **Alert Management:** Stores detected alerts in a SQLite database.
- **LLM-Assisted Triage:** Generates a summary, likely cause, severity assessment, confidence score, evidence, false-positive considerations, and recommended actions.
- **REST API:** Provides endpoints for health checks, retrieving alerts, and analyzing alerts through FastAPI.
- **Interactive Dashboard:** Displays security alerts, severity statistics, alert details, and triage results using Streamlit.
- **Automated Testing:** Includes tests for detection logic, database operations, and triage response validation.
- **Synthetic Test Data:** Supports controlled testing without requiring a live attack.

## 🎯 Problem Statement

Security monitoring systems can generate large volumes of network events and alerts. Manually investigating every alert can be time-consuming, especially when analysts must correlate network activity, understand detection evidence, and decide which alerts need further investigation.

CyberSage aims to simplify this process by combining deterministic detection rules with LLM-assisted explanations and a centralized dashboard.

## 💡 Proposed Solution

CyberSage follows a detection-and-triage workflow:

1. Collect or obtain network traffic logs from Zeek.
2. Normalize the logs into structured network events.
3. Apply detection rules to identify suspicious patterns.
4. Store generated alerts in a SQLite database.
5. Expose alerts through a FastAPI backend.
6. Analyze selected alerts using an LLM and validate its structured response.
7. Display alerts and triage results in a Streamlit dashboard.

## 🏗️ System Architecture

```text
Network Traffic / Zeek Logs
            |
            v
    Log Normalization
            |
            v
   Structured Network Events
            |
            v
   Rule-Based Detection
     (Port Scan Detector)
            |
            v
       Alert Generation
            |
            v
       SQLite Database
            |
            v
        FastAPI Backend
            |
            v
       Streamlit Dashboard
            |
            v
     LLM-Assisted Triage
            |
            v
 Summary | Evidence | Severity
 Recommendations | False Positives
```

## 🧰 Technology Stack

| Component | Technology |
|---|---|
| Operating system | Kali Linux |
| Network log analysis | Zeek |
| Programming language | Python |
| Data processing | Python CSV utilities |
| Detection engine | Custom Python rules |
| Backend API | FastAPI |
| Database | SQLite |
| Data validation | Pydantic |
| LLM integration | OpenAI-compatible API |
| Dashboard | Streamlit |
| HTTP communication | Requests |
| Testing | Pytest |
| Version control | Git and GitHub |

## 📁 Project Structure

```text
llm-alert-triage/
├── backend/
│   ├── __init__.py
│   ├── database.py
│   └── main.py
├── detectors/
│   ├── __init__.py
│   └── port_scan.py
├── pipeline/
│   └── normalizer.py
├── triage/
│   ├── __init__.py
│   ├── schemas.py
│   ├── llm_client.py
│   └── real_llm_client.py
├── tests/
│   ├── create_sample_traffic.py
│   ├── test_database.py
│   ├── test_port_scan.py
│   ├── test_real_llm_client.py
│   └── test_triage.py
├── data/
│   ├── raw/
│   └── processed/
├── dashboard.py
├── run_pipeline.py
├── requirements.txt
├── .env
├── .gitignore
└── README.md
```

## ⚙️ Installation and Setup

### Prerequisites

Install or prepare the following:

- Kali Linux or a compatible Linux environment
- Python 3 and `venv`
- Git
- Docker, if you want to run Zeek using its Docker image
- An API key from a compatible LLM provider for real LLM-based triage

### 1. Clone the repository

```bash
git clone https://github.com/17agl/CyberSage.git
cd CyberSage
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

If creating the virtual environment fails because `venv` is unavailable on Kali Linux, install the required package:

```bash
sudo apt update
sudo apt install -y python3-venv
```

Then create and activate the environment again.

### 
