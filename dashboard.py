import io
import json
import os
from datetime import datetime
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

API_URL = os.getenv("CYBERSAGE_API_URL", "http://127.0.0.1:8000")

# Streamlit Page Config
st.set_page_config(
    page_title="CyberSage — AI-Assisted SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom High-End Cyber SOC Styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', sans-serif;
    }

    code, pre {
        font-family: 'JetBrains Mono', monospace !important;
    }

    /* Main Container Background */
    .stApp {
        background: radial-gradient(circle at 15% 15%, #0f172a 0%, #0b0f19 50%, #05070e 100%);
        color: #f1f5f9;
    }

    /* Glassmorphic Cards */
    .glass-card {
        background: rgba(30, 41, 59, 0.65);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 18px 22px;
        margin-bottom: 16px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .glass-card:hover {
        border-color: rgba(99, 102, 241, 0.4);
    }

    /* KPI Stat Box */
    .kpi-box {
        background: linear-gradient(135deg, rgba(30, 41, 59, 0.8) 0%, rgba(15, 23, 42, 0.9) 100%);
        border: 1px solid rgba(255, 255, 255, 0.07);
        border-radius: 12px;
        padding: 16px;
        text-align: center;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
    }
    .kpi-value {
        font-size: 2.2rem;
        font-weight: 700;
        margin: 4px 0;
        background: linear-gradient(90deg, #60a5fa, #a78bfa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .kpi-label {
        font-size: 0.82rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 600;
    }

    /* Severity Badges */
    .badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 11px;
        font-weight: 700;
        letter-spacing: 0.05em;
        text-transform: uppercase;
    }
    .badge-critical {
        background: rgba(239, 68, 68, 0.15);
        color: #fca5a5;
        border: 1px solid #ef4444;
        box-shadow: 0 0 10px rgba(239, 68, 68, 0.3);
    }
    .badge-high {
        background: rgba(249, 115, 22, 0.15);
        color: #fdba74;
        border: 1px solid #f97316;
    }
    .badge-medium {
        background: rgba(234, 179, 8, 0.15);
        color: #fde047;
        border: 1px solid #eab308;
    }
    .badge-low {
        background: rgba(16, 185, 129, 0.15);
        color: #6ee7b7;
        border: 1px solid #10b981;
    }

    /* Status Badges */
    .badge-new {
        background: rgba(59, 130, 246, 0.15);
        color: #93c5fd;
        border: 1px solid #3b82f6;
    }
    .badge-investigating {
        background: rgba(168, 85, 247, 0.15);
        color: #d8b4fe;
        border: 1px solid #a855f7;
    }
    .badge-resolved {
        background: rgba(16, 185, 129, 0.15);
        color: #6ee7b7;
        border: 1px solid #10b981;
    }
    .badge-false_positive {
        background: rgba(100, 116, 139, 0.15);
        color: #cbd5e1;
        border: 1px solid #64748b;
    }

    /* MITRE ATT&CK Chips */
    .mitre-chip {
        display: inline-block;
        background: #1e1b4b;
        color: #c7d2fe;
        border: 1px solid #6366f1;
        padding: 4px 9px;
        border-radius: 6px;
        font-size: 12px;
        margin: 3px 4px 3px 0;
        font-family: 'JetBrains Mono', monospace;
    }

    /* Threat Intel Badge */
    .ti-tag {
        display: inline-block;
        background: #312e81;
        color: #e0e7ff;
        border-radius: 4px;
        padding: 2px 7px;
        font-size: 11px;
        margin: 2px;
    }
</style>
""", unsafe_allow_html=True)

# Fetch Backend Health & Configuration
try:
    health_resp = requests.get(f"{API_URL}/health", timeout=3)
    api_online = health_resp.ok
except requests.RequestException:
    api_online = False

llm_status_info = {}
if api_online:
    try:
        cfg_resp = requests.get(f"{API_URL}/config/llm-status", timeout=3)
        if cfg_resp.ok:
            llm_status_info = cfg_resp.json()
    except Exception:
        pass

# Sidebar: Mission Control & Intelligence Feed
with st.sidebar:
    st.markdown("""
    <div style='text-align: center; padding-bottom: 8px;'>
        <img src='https://img.icons8.com/fluency/96/shield.png' width='54' />
        <h2 style='margin: 4px 0 0 0; color: #f8fafc; font-weight: 700;'>CyberSage SOC</h2>
        <span style='color: #64748b; font-size: 12px;'>AI Threat Defense & Alert Triage</span>
    </div>
    """, unsafe_allow_html=True)

    # API Connection Banner
    if api_online:
        st.markdown(
            "<div style='background: rgba(16,185,129,0.12); border: 1px solid #10b981; border-radius: 8px; padding: 7px 12px; font-size: 12px; color: #a7f3d0; text-align: center; margin-bottom: 12px;'>"
            "🟢 <b>FastAPI Backend Connected</b> (:8000)</div>",
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            "<div style='background: rgba(239,68,68,0.15); border: 1px solid #ef4444; border-radius: 8px; padding: 8px 12px; font-size: 12px; color: #fca5a5; text-align: center; margin-bottom: 12px;'>"
            "🔴 <b>FastAPI Backend Offline</b><br><small>Start with: <code>uvicorn backend.main:app --port 8000</code></small></div>",
            unsafe_allow_html=True,
        )
        st.stop()

    # AI Triage Engine Status
    has_api_key = llm_status_info.get("has_api_key", False)
    model_name = llm_status_info.get("model", "gpt-4o-mini")

    st.markdown("### 🧠 AI Copilot Status")
    if has_api_key:
        st.markdown(
            f"""
            <div style='background: #1e1b4b; border: 1px solid #6366f1; border-radius: 8px; padding: 10px 12px; font-size: 12px; color: #c7d2fe;'>
                <b>Model:</b> <code>{model_name}</code><br>
                <b>Status:</b> <span style='color:#a7f3d0;'>● Live OpenAI API Key Loaded</span><br>
                <b>Masked Key:</b> <code>{llm_status_info.get("masked_key", "sk-proj-***")}</code>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style='background: #1e293b; border: 1px solid #475569; border-radius: 8px; padding: 10px 12px; font-size: 12px; color: #cbd5e1;'>
                <b>Mode:</b> Expert Deterministic Copilot<br>
                <b>Fallback:</b> <span style='color:#fde047;'>● Active (Zero-Cost Offline)</span><br>
                <small>To activate live OpenAI: add <code>OPENAI_API_KEY</code> to <code>.env</code></small>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.divider()

    # Pipeline Trigger Action
    st.markdown("### ⚡ Threat Ingestion")
    if st.button("🚀 Run Full Detection Pipeline", use_container_width=True):
        with st.spinner("Ingesting logs, executing detectors & training ML model..."):
            try:
                res = requests.post(f"{API_URL}/pipeline/run", timeout=35)
                if res.ok:
                    data = res.json()
                    st.success(f"Detections Refreshed! Analyzed {data.get('events_analyzed')} flows, generated {data.get('alerts_generated')} alerts.")
                    st.rerun()
                else:
                    st.error(f"Pipeline error: {res.text}")
            except Exception as e:
                st.error(f"Connection failed: {e}")

    st.divider()

    # Search and Filtering Controls
    st.markdown("### 🔍 Alert Filters")
    filter_status = st.selectbox(
        "Incident Status",
        options=["All", "new", "investigating", "resolved", "false_positive"],
        index=0,
    )
    filter_severity = st.selectbox(
        "Threat Severity",
        options=["All", "critical", "high", "medium", "low"],
        index=0,
    )
    search_query = st.text_input("Search IP, Port, or Rule", placeholder="e.g. 198.51.100.23")

# Fetch Alerts & Metrics from Backend
try:
    params = {}
    if filter_status != "All":
        params["status"] = filter_status
    if filter_severity != "All":
        params["severity"] = filter_severity
    if search_query:
        params["search"] = search_query

    alerts_resp = requests.get(f"{API_URL}/alerts", params=params, timeout=6)
    alerts: List[Dict[str, Any]] = alerts_resp.json() if alerts_resp.ok else []

    metrics_resp = requests.get(f"{API_URL}/metrics", timeout=6)
    metrics: Dict[str, Any] = metrics_resp.json() if metrics_resp.ok else {}
except requests.RequestException as exc:
    st.error(f"Backend API communication failed: {exc}")
    st.stop()

# Header Presentation Banner
st.markdown("""
<div style='display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 12px; margin-bottom: 18px;'>
    <div>
        <h1 style='margin: 0; font-size: 1.85rem; font-weight: 700; color: #f8fafc;'>
            🛡️ CyberSage — Security Operations Center (SOC) Console
        </h1>
        <p style='margin: 4px 0 0 0; color: #94a3b8; font-size: 0.95rem;'>
            Network Intrusion Detection &bull; Unsupervised ML Anomaly Scoring &bull; Threat Intelligence &bull; AI Alert Triage
        </p>
    </div>
    <div style='text-align: right;'>
        <span style='background: #1e293b; color: #94a3b8; padding: 4px 12px; border-radius: 6px; font-size: 12px; border: 1px solid #334155;'>
            Platform v2.0.0
        </span>
    </div>
</div>
""", unsafe_allow_html=True)

# Top SOC Metric KPI Cards
c1, c2, c3, c4, c5 = st.columns(5)
with c1:
    st.markdown(f"""
    <div class='kpi-box'>
        <div class='kpi-label'>Total Alerts</div>
        <div class='kpi-value'>{metrics.get('total_alerts', len(alerts))}</div>
    </div>
    """, unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class='kpi-box'>
        <div class='kpi-label'>High / Critical</div>
        <div class='kpi-value' style='background: linear-gradient(90deg, #f87171, #fb923c); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
            {metrics.get('high_or_critical', 0)}
        </div>
    </div>
    """, unsafe_allow_html=True)

with c3:
    st.markdown(f"""
    <div class='kpi-box'>
        <div class='kpi-label'>New (Triage Queue)</div>
        <div class='kpi-value' style='background: linear-gradient(90deg, #60a5fa, #38bdf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
            {metrics.get('new_alerts', 0)}
        </div>
    </div>
    """, unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class='kpi-box'>
        <div class='kpi-label'>Under Investigation</div>
        <div class='kpi-value' style='background: linear-gradient(90deg, #c084fc, #e879f9); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
            {metrics.get('investigating', 0)}
        </div>
    </div>
    """, unsafe_allow_html=True)

with c5:
    st.markdown(f"""
    <div class='kpi-box'>
        <div class='kpi-label'>Resolved / Closed</div>
        <div class='kpi-value' style='background: linear-gradient(90deg, #4ade80, #2dd4bf); -webkit-background-clip: text; -webkit-text-fill-color: transparent;'>
            {metrics.get('resolved', 0)}
        </div>
    </div>
    """, unsafe_allow_html=True)

st.write("")

# Navigation Tabs
tab_queue, tab_timeline, tab_graph, tab_raw = st.tabs([
    "🚨 Incident Queue & Investigation",
    "📈 Attack Timeline & Analytics",
    "🕸️ Threat Relationship Graph",
    "📄 Zeek Telemetry & Pipeline Inspector",
])

# -------------------------------------------------------------
# TAB 1: Incident Queue & AI Investigation
# -------------------------------------------------------------
with tab_queue:
    if not alerts:
        st.info("No security alerts matching the current filter criteria. Click 'Run Full Detection Pipeline' in the sidebar to populate alerts.")
    else:
        # Build Table View
        table_records = []
        for a in alerts:
            table_records.append({
                "ID": a.get("id"),
                "Rule ID": a.get("rule_id"),
                "Alert Type": a.get("alert_type"),
                "Source IP": a.get("source_ip"),
                "Destination IP": a.get("destination_ip"),
                "Severity": a.get("severity", "").upper(),
                "Status": a.get("status", "new").upper(),
                "Assigned To": a.get("assigned_to", "Unassigned"),
                "Timestamp": a.get("timestamp"),
            })
        df_alerts = pd.DataFrame(table_records)

        col_list, col_inspect = st.columns([1.1, 1.3])

        with col_list:
            st.markdown("### 📋 Active Alert Feed")
            st.dataframe(
                df_alerts,
                use_container_width=True,
                height=420,
                hide_index=True,
            )

            # Selector
            alert_ids = [a["id"] for a in alerts]
            selected_id = st.selectbox(
                "Select Alert to Investigate:",
                options=alert_ids,
                format_func=lambda x: f"Alert #{x} - {next((a['alert_type'] for a in alerts if a['id'] == x), '')} ({next((a['severity'] for a in alerts if a['id'] == x), '').upper()})",
            )

        selected_alert = next((a for a in alerts if a["id"] == selected_id), None)

        with col_inspect:
            if selected_alert:
                sev = selected_alert.get("severity", "medium").lower()
                stat = selected_alert.get("status", "new").lower()
                atype = selected_alert.get("alert_type")
                rule = selected_alert.get("rule_id")

                st.markdown(f"""
                <div class='glass-card' style='padding: 16px 20px;'>
                    <div style='display: flex; justify-content: space-between; align-items: center;'>
                        <h3 style='margin: 0; color: #f8fafc;'>🔎 Alert #{selected_alert['id']}: {atype}</h3>
                        <div>
                            <span class='badge badge-{sev}'>{sev}</span>
                            <span class='badge badge-{stat}'>{stat}</span>
                        </div>
                    </div>
                    <div style='margin-top: 8px; color: #94a3b8; font-size: 13px;'>
                        <b>Rule:</b> <code>{rule}</code> &bull;
                        <b>Source:</b> <code>{selected_alert.get('source_ip')}</code> &rarr;
                        <b>Target:</b> <code>{selected_alert.get('destination_ip')}</code>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Sub-tabs for cleanly separated alert investigation
                subtab_triage, subtab_intel, subtab_mitigation, subtab_workflow, subtab_raw = st.tabs([
                    "🧠 AI Assessment",
                    "🌐 Threat Intel",
                    "🛡️ Playbook",
                    "📝 Incident Response",
                    "📦 Raw Evidence",
                ])

                # -------------------------------------------------------------
                # SUB-TAB 1: AI Triage & Assessment
                # -------------------------------------------------------------
                with subtab_triage:
                    triage = selected_alert.get("triage_result")

                    # Engine selection & trigger row
                    tc1, tc2 = st.columns([1.4, 1])
                    with tc1:
                        triage_mode = st.radio(
                            "Triage Mode:",
                            options=["auto", "mock", "real"],
                            index=0,
                            horizontal=True,
                            help="Auto uses OpenAI if valid key is set, else uses local expert deterministic triage.",
                            key=f"mode_sel_{selected_id}",
                        )
                    with tc2:
                        st.write("")
                        re_triage_btn = st.button("⚡ Re-run AI Analysis", key=f"btn_retriage_{selected_id}", use_container_width=True)

                    if re_triage_btn or not triage:
                        with st.spinner("Analyzing telemetry with defensive triage engine..."):
                            try:
                                payload = {
                                    "alert_id": selected_alert["id"],
                                    "alert_type": selected_alert["alert_type"],
                                    "rule_id": selected_alert.get("rule_id"),
                                    "source_ip": selected_alert["source_ip"],
                                    "destination_ip": selected_alert["destination_ip"],
                                    "severity": selected_alert.get("severity", "medium"),
                                    "evidence": selected_alert.get("evidence", {}),
                                    "mode": triage_mode,
                                }
                                resp = requests.post(f"{API_URL}/alerts/triage", json=payload, timeout=25)
                                if resp.ok:
                                    triage = resp.json()
                                    st.success("Triage findings persisted to database!")
                                else:
                                    st.error(f"Triage request failed: {resp.text}")
                            except Exception as exc:
                                st.error(f"Triage connection error: {exc}")

                    if triage:
                        engine_used = triage.get("engine_used", "deterministic_expert")
                        engine_model = triage.get("engine_model", "CyberSage Copilot")
                        engine_notice = triage.get("engine_notice")

                        if engine_used == "openai":
                            st.markdown(
                                f"<div style='background: rgba(99,102,241,0.15); border: 1px solid #6366f1; border-radius: 6px; padding: 6px 12px; font-size: 12px; color: #c7d2fe; margin-bottom: 12px;'>"
                                f"🧠 <b>Live OpenAI Engine:</b> <code>{engine_model}</code></div>",
                                unsafe_allow_html=True,
                            )
                        else:
                            st.markdown(
                                f"<div style='background: rgba(148,163,184,0.12); border: 1px solid #64748b; border-radius: 6px; padding: 6px 12px; font-size: 12px; color: #cbd5e1; margin-bottom: 12px;'>"
                                f"⚡ <b>Deterministic Security Copilot:</b> <code>{engine_model}</code>"
                                + (f"<br><small style='color: #fbbf24;'>{engine_notice}</small>" if engine_notice else "")
                                + "</div>",
                                unsafe_allow_html=True,
                            )

                        st.markdown(f"**Executive Summary:** {triage.get('summary')}")
                        st.markdown(f"**Adversary Intent:** {triage.get('likely_cause')}")

                        m_col1, m_col2 = st.columns([1, 1.5])
                        with m_col1:
                            st.metric("Triage Confidence", f"{triage.get('confidence', 0):.0%}")
                        with m_col2:
                            mitre_list = triage.get("mitre_attack", [])
                            st.markdown("**Candidate MITRE ATT&CK:**")
                            if mitre_list:
                                chips = "".join(f"<span class='mitre-chip'>{t}</span>" for t in mitre_list)
                                st.markdown(chips, unsafe_allow_html=True)
                            else:
                                st.markdown("None mapped")

                        st.markdown("**Telemetry Evidence:**")
                        for e in triage.get("evidence", []):
                            st.markdown(f"- 🔎 {e}")

                # -------------------------------------------------------------
                # SUB-TAB 2: Threat Intelligence & Telemetry
                # -------------------------------------------------------------
                with subtab_intel:
                    ti = selected_alert.get("threat_intel")
                    if ti:
                        ti_col1, ti_col2 = st.columns(2)
                        with ti_col1:
                            s = ti.get("source", {})
                            st.markdown("#### 📤 Source Host")
                            st.markdown(f"**IP:** `{s.get('ip')}`")
                            st.markdown(f"**Scope:** `{s.get('scope')}`")
                            st.markdown(f"**Reputation:** `{s.get('reputation', 'unknown').upper()}`")
                            if s.get("threat_tags"):
                                st.write("Tags:", ", ".join(f"`{t}`" for t in s.get("threat_tags", [])))

                        with ti_col2:
                            d = ti.get("destination", {})
                            st.markdown("#### 📥 Destination Target")
                            st.markdown(f"**IP:** `{d.get('ip')}`")
                            st.markdown(f"**Scope:** `{d.get('scope')}`")
                            st.markdown(f"**Reputation:** `{d.get('reputation', 'unknown').upper()}`")
                            if d.get("country") and d.get("country") != "Unknown":
                                st.markdown(f"**Geo / ASN:** {d.get('country')} &bull; `{d.get('asn')}`")
                            if d.get("threat_tags"):
                                st.write("Tags:", ", ".join(f"`{t}`" for t in d.get("threat_tags", [])))

                        st.divider()
                        st.markdown("#### 🛡️ Scope & Network Categorization")
                        if s.get("is_private") and d.get("is_private"):
                            st.info("Both hosts reside within RFC 1918 Private Address Space. Activity represents internal/east-west network communications.")
                        elif s.get("is_private") and not d.get("is_private"):
                            st.warning("Internal host communicating outbound with external public IP address. Potential egress/C2 channel.")
                        elif not s.get("is_private") and d.get("is_private"):
                            st.error("External public host communicating inbound against internal infrastructure. Ingress attack indicator.")
                    else:
                        st.info("No threat intelligence records associated with this alert.")

                # -------------------------------------------------------------
                # SUB-TAB 3: Mitigation & Playbook
                # -------------------------------------------------------------
                with subtab_mitigation:
                    if triage:
                        st.markdown("#### 🛡️ Actionable Containment Checklist")
                        for act in triage.get("recommended_actions", []):
                            st.markdown(f"- [ ] **Action:** {act}")

                        st.write("")
                        st.markdown("#### ⚠️ False-Positive Considerations")
                        for fp in triage.get("false_positive_considerations", []):
                            st.markdown(f"- 🟡 {fp}")
                    else:
                        st.info("Run AI Triage to generate response playbook and containment steps.")

                # -------------------------------------------------------------
                # SUB-TAB 4: Incident Response Workflow
                # -------------------------------------------------------------
                with subtab_workflow:
                    w_col1, w_col2 = st.columns(2)
                    with w_col1:
                        new_status = st.selectbox(
                            "Incident Status",
                            options=["new", "investigating", "resolved", "false_positive"],
                            index=["new", "investigating", "resolved", "false_positive"].index(stat) if stat in ["new", "investigating", "resolved", "false_positive"] else 0,
                            key=f"status_sel_{selected_id}",
                        )
                    with w_col2:
                        assignee = st.text_input(
                            "Assigned SOC Analyst",
                            value=selected_alert.get("assigned_to", "SOC Analyst 1"),
                            key=f"assignee_txt_{selected_id}",
                        )

                    new_note = st.text_area(
                        "Add Investigation Note",
                        placeholder="e.g. Verified with sysadmin; authorized vulnerability assessment.",
                        key=f"note_txt_{selected_id}",
                    )

                    c_save, c_export = st.columns([1, 1])
                    with c_save:
                        if st.button("💾 Save Status & Notes", key=f"btn_save_status_{selected_id}", use_container_width=True):
                            try:
                                requests.patch(
                                    f"{API_URL}/alerts/{selected_id}/status",
                                    json={"status": new_status, "assigned_to": assignee},
                                    timeout=5,
                                )
                                if new_note.strip():
                                    requests.post(
                                        f"{API_URL}/alerts/{selected_id}/notes",
                                        json={"note": new_note.strip(), "author": assignee},
                                        timeout=5,
                                    )
                                st.success("Incident updated!")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Failed to update incident: {e}")

                    with c_export:
                        ti_data = selected_alert.get("threat_intel") or {}
                        triage_data_exp = selected_alert.get("triage_result") or {}
                        report_md = f"""# 🛡️ CyberSage Incident Brief: Alert #{selected_alert['id']}
**Generated At:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}
**Threat Type:** {selected_alert.get('alert_type')} ({selected_alert.get('rule_id')})
**Severity:** {selected_alert.get('severity', '').upper()}
**Status:** {selected_alert.get('status', '').upper()}
**Assigned Analyst:** {selected_alert.get('assigned_to', 'Unassigned')}

## Flow Telemetry
- **Source:** {selected_alert.get('source_ip')} ({ti_data.get('source', {}).get('scope', 'Unknown')})
- **Target:** {selected_alert.get('destination_ip')} ({ti_data.get('destination', {}).get('scope', 'Unknown')})
- **Timestamp:** {selected_alert.get('timestamp')}

## AI Assessment
- **Summary:** {triage_data_exp.get('summary', 'Pending triage')}
- **Likely Cause:** {triage_data_exp.get('likely_cause', 'N/A')}
- **Confidence:** {triage_data_exp.get('confidence', 0):.0%}
- **MITRE ATT&CK:** {', '.join(triage_data_exp.get('mitre_attack', []))}

## Mitigation Actions
{chr(10).join(f"- [ ] {a}" for a in triage_data_exp.get('recommended_actions', []))}

## Analyst Activity Log
{selected_alert.get('analyst_notes', 'No notes recorded.')}
"""
                        st.download_button(
                            "📥 Download Incident Brief (.MD)",
                            data=report_md,
                            file_name=f"Incident_Alert_{selected_id}.md",
                            mime="text/markdown",
                            key=f"btn_dl_{selected_id}",
                            use_container_width=True,
                        )

                    if selected_alert.get("analyst_notes"):
                        st.markdown("**Analyst Activity Trail:**")
                        st.text_area(
                            "Audit Trail",
                            value=selected_alert.get("analyst_notes"),
                            height=90,
                            disabled=True,
                            key=f"notes_hist_{selected_id}",
                        )

                # -------------------------------------------------------------
                # SUB-TAB 5: Raw Evidence JSON
                # -------------------------------------------------------------
                with subtab_raw:
                    st.json(selected_alert.get("evidence", {}))

# -------------------------------------------------------------
# TAB 2: Attack Timeline & Analytics
# -------------------------------------------------------------
with tab_timeline:
    st.markdown("### 📈 Security Telemetry Analytics & Attack Timeline")

    if alerts:
        a_row1_c1, a_row1_c2 = st.columns(2)

        with a_row1_c1:
            type_counts = pd.Series([a["alert_type"] for a in alerts]).value_counts().reset_index()
            type_counts.columns = ["Alert Type", "Count"]
            fig_type = px.pie(
                type_counts,
                names="Alert Type",
                values="Count",
                title="Threat Distribution by Detection Vector",
                hole=0.45,
                color_discrete_sequence=px.colors.qualitative.Prism,
            )
            fig_type.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                margin=dict(t=40, b=10, l=10, r=10),
            )
            st.plotly_chart(fig_type, use_container_width=True)

        with a_row1_c2:
            sev_counts = pd.Series([a.get("severity", "medium").upper() for a in alerts]).value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            fig_sev = px.bar(
                sev_counts,
                x="Severity",
                y="Count",
                title="Alert Breakdown by Severity Tier",
                color="Severity",
                color_discrete_map={
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#10b981",
                },
            )
            fig_sev.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#94a3b8"),
                margin=dict(t=40, b=10, l=10, r=10),
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        # Chronological Progression Timeline
        st.markdown("### ⏱️ Chronological Attack Progression Timeline")
        timeline_data = []
        for a in alerts:
            ts_str = a.get("timestamp")
            try:
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                dt = datetime.now()

            timeline_data.append({
                "Alert ID": f"#{a['id']}",
                "Time": dt,
                "Threat Type": a.get("alert_type"),
                "Source": a.get("source_ip"),
                "Target": a.get("destination_ip"),
                "Severity": a.get("severity", "medium").upper(),
            })

        df_time = pd.DataFrame(timeline_data).sort_values("Time")
        fig_timeline = px.scatter(
            df_time,
            x="Time",
            y="Threat Type",
            color="Severity",
            size=[15] * len(df_time),
            hover_data=["Alert ID", "Source", "Target"],
            title="Attack Lifecycle Progression Over Time",
            color_discrete_map={
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#10b981",
            },
        )
        fig_timeline.update_layout(
            height=340,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(15,23,42,0.6)",
            font=dict(color="#94a3b8"),
            xaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            yaxis=dict(gridcolor="rgba(255,255,255,0.05)"),
            margin=dict(t=40, b=20, l=10, r=10),
        )
        st.plotly_chart(fig_timeline, use_container_width=True)

# -------------------------------------------------------------
# TAB 3: Threat Relationship Graph
# -------------------------------------------------------------
with tab_graph:
    st.markdown("### 🕸️ Multi-Vector Threat Interaction Graph")
    st.caption("Visualizes communication flows and relationships between internal hosts, external attackers, and target destinations.")

    if alerts:
        sources = list({a["source_ip"] for a in alerts})
        dests = list({a["destination_ip"] for a in alerts})
        node_records = {}

        for i, src in enumerate(sources):
            node_records[src] = {
                "x": 0.15,
                "y": (i + 1) / (len(sources) + 1),
                "type": "Source Host / Attacker",
                "label": src,
            }
        for j, dst in enumerate(dests):
            node_records[dst] = {
                "x": 0.85,
                "y": (j + 1) / (len(dests) + 1),
                "type": "Target Destination / C2",
                "label": dst,
            }

        fig_graph = go.Figure()

        # Draw Edges
        for a in alerts:
            s = node_records.get(a["source_ip"])
            d = node_records.get(a["destination_ip"])
            if s and d:
                fig_graph.add_trace(go.Scatter(
                    x=[s["x"], d["x"], None],
                    y=[s["y"], d["y"], None],
                    mode="lines",
                    line=dict(
                        width=2,
                        color="#ef4444" if a.get("severity") in ["high", "critical"] else "#f59e0b",
                    ),
                    hoverinfo="text",
                    text=f"{a['alert_type']} ({a['rule_id']})",
                    showlegend=False,
                ))

        # Draw Nodes
        for name, data in node_records.items():
            color = "#ef4444" if data["type"] == "Source Host / Attacker" else "#3b82f6"
            fig_graph.add_trace(go.Scatter(
                x=[data["x"]],
                y=[data["y"]],
                mode="markers+text",
                marker=dict(size=26, color=color, line=dict(width=2, color="#ffffff")),
                text=[name],
                textposition="top center",
                name=data["type"],
                hoverinfo="text",
                hovertext=f"Node: {name}<br>Type: {data['type']}",
                showlegend=False,
            ))

        fig_graph.update_layout(
            title="Adversary Lateral Movement & Outbound C2 Communication Paths",
            height=490,
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            margin=dict(l=30, r=30, t=50, b=30),
            plot_bgcolor="rgba(15,23,42,0.85)",
            paper_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#94a3b8"),
        )
        st.plotly_chart(fig_graph, use_container_width=True)

# -------------------------------------------------------------
# TAB 4: Zeek Telemetry & Pipeline Inspector
# -------------------------------------------------------------
with tab_raw:
    st.markdown("### 📄 Normalized Zeek Network Telemetry")
    csv_path = "data/processed/connections.csv"
    if os.path.exists(csv_path):
        try:
            df_conn = pd.read_csv(csv_path)
            st.markdown(f"**Loaded `{len(df_conn)}` normalized connection events from `{csv_path}`:**")
            st.dataframe(df_conn, use_container_width=True, height=360)
        except Exception as e:
            st.error(f"Error reading CSV: {e}")
    else:
        st.info("No connections.csv file found. Trigger the pipeline to generate telemetry.")

    st.markdown("### ⚙️ System Runtime Architecture")
    st.code(f"""
API Host: {API_URL}
Database: data/alerts.db
ML Model: Unsupervised Isolation Forest (Dual Scikit-Learn / Pure-NumPy Engine)
OpenAI Model: {model_name}
Threat Intel Engine: RFC 1918 Private Safeguard + AbuseIPDB/Tor/C2 Reputation DB
    """, language="yaml")

