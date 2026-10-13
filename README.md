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
CyberSage/
├── backend/
│   ├── __init__.py
│   ├── database.py             # SQLite alert storage with lifecycle & note tracking
│   └── main.py                 # FastAPI REST API (CRUD, triage, analytics, metrics)
├── detectors/
│   ├── __init__.py
│   ├── registry.py             # Pluggable detector runner and registry
│   ├── port_scan.py            # Vertical port scans & horizontal subnet sweeps
│   ├── brute_force.py          # Authentication brute-force on SSH, RDP, FTP, Telnet
│   ├── suspicious_outbound.py  # C2, Tor, Miner, and high-risk port connections
│   ├── data_exfiltration.py    # Large volume outbound transfers & upload asymmetry
│   └── dns_tunneling.py        # Oversized DNS payloads & rapid query burst rates
├── ml/
│   ├── __init__.py
│   ├── feature_extractor.py    # Network flow feature extraction & normalization
│   └── anomaly_detector.py     # Unsupervised Isolation Forest outlier detector
├── threat_intel/
│   ├── __init__.py
│   └── enricher.py             # RFC 1918 classification & public IP threat reputation
├── pipeline/
│   ├── __init__.py
│   └── normalizer.py           # Zeek conn.log parser and event normalizer
├── triage/
│   ├── __init__.py
│   ├── schemas.py              # Pydantic TriageResult schema (evidence, actions, MITRE)
│   ├── dispatcher.py           # Auto-router between OpenAI and mock triage
│   ├── llm_client.py           # Comprehensive defensive mock triage generator
│   └── real_llm_client.py      # OpenAI client with prompt hardening & schema validation
├── tests/
│   ├── create_sample_traffic.py# Synthetic multi-vector Zeek conn.log generator
│   ├── test_api.py             # FastAPI integration tests
│   ├── test_database.py        # SQLite persistence and note tracking tests
│   ├── test_detectors.py       # Rule-based detector unit tests
│   ├── test_ml_anomaly.py      # Isolation Forest anomaly scoring tests
│   ├── test_port_scan.py       # Port scan detector tests
│   ├── test_real_llm_client.py # Mocked OpenAI client tests
│   ├── test_threat_intel.py    # RFC 1918 protection and TI lookup tests
│   └── test_triage.py          # Structured triage validation tests
├── dashboard.py                # Streamlit SOC Dashboard (Queue, Timeline, Graph)
├── run_pipeline.py             # End-to-end pipeline runner (Normalize -> Detect -> ML -> TI -> DB)
├── requirements.txt            # Python dependencies
├── .env.example                # Configuration template
├── .gitignore                  # Git exclusions
└── README.md                   # Project documentation
```

## ⚙️ Installation and Setup

### Prerequisites

- Python 3.10+ (tested on Python 3.10–3.14 on Linux, macOS, and Windows)
- Git
- Virtual environment (`venv`)
- *(Optional)* OpenAI API key if testing live LLM triage (the system includes an automated mock triage fallback if unconfigured)

---

### 1. Clone the repository

```bash
git clone https://github.com/17agl/CyberSage.git
cd CyberSage
```

### 2. Create and activate a virtual environment

**On Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

**On Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables (Optional)

Copy the configuration template:
```bash
cp .env.example .env
```
*(On Windows: `copy .env.example .env`)*

Edit `.env` if you have an OpenAI API key:
```env
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4.1-mini
CYBERSAGE_TRIAGE_MODE=auto
```
> **Note:** If `OPENAI_API_KEY` is not provided or remains default, CyberSage automatically runs in high-fidelity mock triage mode so all features work seamlessly offline without API costs!

---

## 🚀 Running CyberSage

### Step 1: Generate Traffic & Run the Detection Pipeline

Run the end-to-end pipeline. If no Zeek logs exist, it automatically creates a multi-vector synthetic dataset (`data/processed/conn.log`), normalizes it, runs all detection rules, trains the Isolation Forest ML model, enriches with Threat Intelligence, and stores alerts in SQLite:

```bash
python run_pipeline.py
```

### Step 2: Start the FastAPI Backend

In your first terminal, launch the backend API:

```bash
uvicorn backend.main:app --reload --port 8000
```
- Interactive API Documentation: **http://127.0.0.1:8000/docs**
- Health Check: **http://127.0.0.1:8000/health**

### Step 3: Launch the Streamlit SOC Dashboard

In a second terminal (with your virtual environment activated), start the dashboard:

```bash
streamlit run dashboard.py
```
- Open your browser to: **http://localhost:8501**

---

## 🧪 Running Automated Tests

Run the full pytest suite (25 automated tests):

```bash
pytest tests/ -v
```
