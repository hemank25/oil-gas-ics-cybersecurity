"""
audit_log.py
============
Searchable Industrial Security Event History & Audit Repository.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: Compliance Officer & Lead Systems Architect (Student 2)

Features:
- Centralized event aggregator: Simulation runs, AI detections, security alerts, mitigation actions, retests
- Multi-dimensional filtering by Event Type, Target Asset, Severity, and Text Search
- Immutable record preservation with detailed technical proof inspection
"""

from typing import Dict, Any, List
import json
from pathlib import Path
from datetime import datetime
import pandas as pd
import streamlit as st

from process_simulator import ProcessTelemetrySimulator

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = WORKSPACE_ROOT / "results"
SECURITY_ALERTS_PATH = RESULTS_DIR / "security_alerts.csv"

def load_security_alerts() -> pd.DataFrame:
    """Load persistent security alerts CSV from disk."""
    if SECURITY_ALERTS_PATH.exists():
        try:
            return pd.read_csv(SECURITY_ALERTS_PATH)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()

def render_audit_log_page(simulator: ProcessTelemetrySimulator):
    """Render the full Searchable Event History & Audit Log page."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>📜 Event History &amp; Central Industrial Audit Repository</h2>
            <p>Comprehensive, immutable audit trail of simulation executions, AI detector predictions, process trips, and security mitigation actions.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Ingest simulation audit log
    sim_runs = simulator.get_audit_history()
    alerts_df = load_security_alerts()

    # Aggregate unified records
    unified_records = []

    # 1. Add simulation runs
    for run in sim_runs:
        unified_records.append({
            "Record ID": run.get("run_id", "N/A"),
            "Timestamp": run.get("start_time", "").replace("T", " ")[:19],
            "Event Type": "SIMULATION_RUN",
            "Target Asset": run.get("target_asset", "N/A"),
            "Severity": run.get("ai_severity", "INFORMATIONAL"),
            "Summary": f"[{run.get('scenario_id')}] {run.get('scenario_name')}",
            "Details": run
        })

    # 2. Add saved security alerts
    if not alerts_df.empty:
        for idx, row in alerts_df.head(50).iterrows():
            unified_records.append({
                "Record ID": str(row.get("alert_id", f"ALT-HIST-{idx}")),
                "Timestamp": str(row.get("timestamp", "N/A")),
                "Event Type": "SECURITY_ALERT",
                "Target Asset": str(row.get("subsystems", "Field Subsystem")).split(":")[0],
                "Severity": str(row.get("severity", "MEDIUM")),
                "Summary": f"AI Flag on {row.get('primary_sensor', 'Sensor Tag')} (Score: {row.get('anomaly_score', 'N/A')})",
                "Details": row.to_dict()
            })

    # Fallback default records if empty
    if not unified_records:
        unified_records.append({
            "Record ID": "AUDIT-INIT-001",
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Event Type": "SYSTEM_INITIALIZATION",
            "Target Asset": "C-01",
            "Severity": "INFORMATIONAL",
            "Summary": "MUJ Demo Refinery Supervisory SCADA System Initialized Nominal",
            "Details": {"status": "Nominal", "facility": "MUJ Demo Refinery"}
        })

    df_unified = pd.DataFrame(unified_records)

    # Top Filters
    f_col1, f_col2, f_col3, f_col4 = st.columns([1.5, 1.2, 1.2, 1.5])

    with f_col1:
        event_types = ["ALL"] + sorted(list(df_unified["Event Type"].unique()))
        sel_type = st.selectbox("Filter Event Type:", event_types, key="audit_type_filter")

    with f_col2:
        assets = ["ALL"] + sorted(list(df_unified["Target Asset"].unique()))
        sel_asset = st.selectbox("Filter Target Asset:", assets, key="audit_asset_filter")

    with f_col3:
        severities = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "INFORMATIONAL"]
        sel_sev = st.selectbox("Filter Severity:", severities, key="audit_sev_filter")

    with f_col4:
        search_query = st.text_input("Search Description / ID:", "", key="audit_search")

    # Apply filters
    filtered_df = df_unified.copy()
    if sel_type != "ALL":
        filtered_df = filtered_df[filtered_df["Event Type"] == sel_type]
    if sel_asset != "ALL":
        filtered_df = filtered_df[filtered_df["Target Asset"] == sel_asset]
    if sel_sev != "ALL":
        filtered_df = filtered_df[filtered_df["Severity"] == sel_sev]
    if search_query:
        q = search_query.lower()
        filtered_df = filtered_df[
            filtered_df["Summary"].str.lower().str.contains(q) |
            filtered_df["Record ID"].str.lower().str.contains(q)
        ]

    st.markdown(f"**Showing {len(filtered_df)} of {len(df_unified)} Audit Records:**")

    # Display Table
    cols_to_show = ["Record ID", "Timestamp", "Event Type", "Target Asset", "Severity", "Summary"]
    st.dataframe(filtered_df[cols_to_show], use_container_width=True, hide_index=True)

    # Detail Record Inspector
    if not filtered_df.empty:
        st.markdown("#### 🔍 Record Detail Inspector")
        sel_id = st.selectbox(
            "Select Record ID to Inspect Full Payload:",
            filtered_df["Record ID"].tolist(),
            key="audit_record_select"
        )
        selected_record = filtered_df[filtered_df["Record ID"] == sel_id].iloc[0]
        st.json(selected_record["Details"])
