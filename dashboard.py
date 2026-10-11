
import requests
import pandas as pd
import streamlit as st

API_URL = "http://127.0.0.1:8000"

st.set_page_config(
    page_title="LLM Alert Triage",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Detection Pipeline + LLM Alert Triage")
st.caption("Network security monitoring and alert investigation dashboard")

# Check whether the API is available
try:
    health_response = requests.get(
        f"{API_URL}/health",
        timeout=3,
    )
    api_online = health_response.ok
except requests.RequestException:
    api_online = False

if api_online:
    st.success("FastAPI backend connected")
else:
    st.error(
        "Backend is offline. Start FastAPI on port 8000 "
        "in another terminal."
    )
    st.stop()

# Load stored alerts from the backend
try:
    response = requests.get(
        f"{API_URL}/alerts",
        timeout=5,
    )
    response.raise_for_status()
    alerts = response.json()
except requests.RequestException as error:
    st.error(f"Could not load alerts: {error}")
    st.stop()

# Dashboard metrics
total_alerts = len(alerts)
high_alerts = sum(
    1 for alert in alerts
    if alert.get("severity", "").lower() in ["high", "critical"]
)
medium_alerts = sum(
    1 for alert in alerts
    if alert.get("severity", "").lower() == "medium"
)
new_alerts = sum(
    1 for alert in alerts
    if alert.get("status", "new").lower() == "new"
)

col1, col2, col3, col4 = st.columns(4)

col1.metric("Total Alerts", total_alerts)
col2.metric("High / Critical", high_alerts)
col3.metric("Medium Severity", medium_alerts)
col4.metric("New Alerts", new_alerts)

st.divider()

# Stored alerts
st.subheader("📋 Security Alerts")

if alerts:
    table_data = []

    for alert in alerts:
        table_data.append({
            "ID": alert.get("id"),
            "Alert Type": alert.get("alert_type"),
            "Source IP": alert.get("source_ip"),
            "Destination IP": alert.get("destination_ip"),
            "Severity": alert.get("severity"),
            "Status": alert.get("status", "new"),
            "Timestamp": alert.get("timestamp"),
        })

    df = pd.DataFrame(table_data)
    st.dataframe(df, use_container_width=True)

    selected_id = st.selectbox(
        "Select an alert to investigate",
        options=[alert.get("id") for alert in alerts],
    )

    selected_alert = next(
        alert for alert in alerts
        if alert.get("id") == selected_id
    )

    st.subheader("🔎 Alert Details")
    st.json(selected_alert)

    if st.button("Analyze Selected Alert"):
        with st.spinner("Analyzing alert..."):
            try:
                payload = {
                    "alert_type": selected_alert["alert_type"],
                    "source_ip": selected_alert["source_ip"],
                    "destination_ip": selected_alert["destination_ip"],
                    "severity": selected_alert["severity"],
                    "evidence": selected_alert.get("evidence", {}),
                }

                triage_response = requests.post(
                    f"{API_URL}/alerts/triage",
                    json=payload,
                    timeout=15,
                )
                triage_response.raise_for_status()
                result = triage_response.json()

                st.subheader("🧠 Triage Analysis")
                st.write("**Summary:**", result["summary"])
                st.write("**Likely cause:**", result["likely_cause"])
                st.write("**Severity:**", result["severity"])
                st.write(
                    "**Confidence:**",
                    f'{result["confidence"]:.0%}',
                )

                st.write("**Evidence**")
                for item in result["evidence"]:
                    st.write(f"- {item}")

                st.write("**False-positive considerations**")
                for item in result["false_positive_considerations"]:
                    st.write(f"- {item}")

                st.write("**Recommended actions**")
                for item in result["recommended_actions"]:
                    st.write(f"- {item}")

                st.write("**MITRE ATT&CK references**")
                st.write(", ".join(result["mitre_attack"]) or "None")

                st.info(
                    "This is rule-based mock triage, not a real LLM "
                    "or an autonomous security decision."
                )

            except (requests.RequestException, KeyError, ValueError) as error:
                st.error(f"Triage request failed: {error}")

else:
    st.info(
        "No alerts are stored yet. Run your detection pipeline "
        "on suitable network traffic to populate this table."
    )

st.divider()

# Test triage independently of stored alerts
st.subheader("🧪 Test Alert Triage")
st.caption(
    "Use a synthetic example to verify the triage API, "
    "even when the database has no alerts."
)

if st.button("Run Sample Port-Scan Analysis"):
    sample_alert = {
        "alert_type": "possible_port_scan",
        "source_ip": "192.168.1.10",
        "destination_ip": "192.168.1.20",
        "severity": "medium",
        "evidence": {
            "unique_destination_ports": [22, 80, 443, 3306, 8080],
            "port_count": 5,
            "window_seconds": 60,
        },
    }

    try:
        with st.spinner("Analyzing synthetic test alert..."):
            result_response = requests.post(
                f"{API_URL}/alerts/triage",
                json=sample_alert,
                timeout=15,
            )
            result_response.raise_for_status()
            result = result_response.json()

        st.write("**Summary:**", result["summary"])
        st.write("**Likely cause:**", result["likely_cause"])
        st.write("**Severity:**", result["severity"])
        st.write("**Confidence:**", f'{result["confidence"]:.0%}')
        st.write("**Recommended actions:**")

        for action in result["recommended_actions"]:
            st.write(f"- {action}")

        st.info(
            "Synthetic test only. This example does not represent "
            "a real detected attack and is not saved to the database."
        )

    except requests.RequestException as error:
        st.error(f"Sample analysis failed: {error}")
