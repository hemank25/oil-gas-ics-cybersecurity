"""
incident_workspace.py
=====================
Industrial Cyber Security Incident Management & Investigation Dossier.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: Group Leader & Incident Response Analyst (Student 2)

Workflow & State Machine:
  New -> Investigating -> Mitigation Planned -> Mitigated -> Retested -> Closed

Key Capabilities:
1. End-to-end event correlation: Connects Attack Simulation Run ID, AI Anomaly Flags, and Threat Vectors.
2. Step-by-step chronological incident timeline reconstruction.
3. Interactive analyst triage, state transition management, and persistent investigation notes.
4. Filterable SOC alert log viewer.
"""

from typing import Dict, Any, List, Optional
import json
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = WORKSPACE_ROOT / "results"
INCIDENT_SUMMARY_PATH = RESULTS_DIR / "incident_summary.json"
SECURITY_ALERTS_PATH = RESULTS_DIR / "security_alerts.csv"

# Pre-curated incident dataset representing historical operational events
DEFAULT_INCIDENTS = [
    {
        "incident_id": "INC-001",
        "title": "Unauthenticated Modbus Valve Override & Boiler Overpressure",
        "detection_source": "Dual-Paradigm Engine (Isolation Forest + Random Forest)",
        "first_seen": "2026-10-19 10:14:01",
        "last_seen": "2026-10-19 10:24:24",
        "duration_seconds": 623,
        "peak_severity": "CRITICAL",
        "peak_anomaly_score": -0.0198,
        "alert_threshold": 0.0132,
        "peak_supervised_prob": 99.8,
        "affected_assets": ["U-01", "U-02"],
        "target_controllers": ["PLC-01-A (192.168.10.10)", "PLC-01 (192.168.10.11)"],
        "flagged_sensors": ["P1_PCV01D", "P1_PCV01Z", "P1_PIT01", "P1_TIT01"],
        "correlated_vapt_findings": ["VAPT-2026-001"],
        "associated_run_id": "RUN-20261019-101400-SCEN-A",
        "evidence_references": [
            "Nmap modbus-discover script confirmed unauthenticated register 40001 write access on 192.168.10.11:502",
            "P1_PCV01D valve demand forced to 88.5% (+5.8 sigma deviation)",
            "P1_PIT01 column pressure surged to 2.85 kPa (Alarm limit: 2.50 kPa)"
        ],
        "assigned_status": "Investigating",
        "analyst_notes": "2026-10-19 10:16: Triage initiated by Shift Cyber Analyst. Verified rogue IP 192.168.10.99. Preparing OT firewall conduit isolation.",
        "mitigation_recommendation": "1. Deploy OT firewall DPI rule blocking Modbus Function 06 from non-engineering subnets. 2. Verify physical steam valve manual bypass. 3. Do not execute automated plant trip.",
        "retest_outcome": "PENDING_RETEST",
        "timeline": [
            {"time": "10:14:01", "stage": "Network Ingress", "event": "Rogue host 192.168.10.99 initiates TCP handshake on Port 502."},
            {"time": "10:14:02", "stage": "Exploit Injection", "event": "Modbus Function 06 written to Register 40001 (Valve Setpoint forced to 88.5%)."},
            {"time": "10:14:04", "stage": "Physical Deviation", "event": "P1_PCV01D and P1_PIT01 diverge past nominal operating bands."},
            {"time": "10:14:05", "stage": "AI Detection", "event": "Isolation Forest flags anomaly score (-0.0198) and Random Forest confirms attack signature (99.8%)."},
            {"time": "10:14:06", "stage": "SOC Alert", "event": "Dispatched CRITICAL alarm to Operator HMI and opened Incident INC-001."},
            {"time": "10:18:20", "stage": "Mitigation Enforced", "event": "Analyst applied Industrial Firewall DPI drop rule."}
        ]
    },
    {
        "incident_id": "INC-002",
        "title": "Compromised EWS Remote Management & Stuxnet Turbine Overspeed Probe",
        "detection_source": "Supervised Random Forest Classifier + Statistical Physics Limit",
        "first_seen": "2026-10-19 11:05:14",
        "last_seen": "2026-10-19 11:08:30",
        "duration_seconds": 196,
        "peak_severity": "HIGH",
        "peak_anomaly_score": -0.0412,
        "alert_threshold": 0.0132,
        "peak_supervised_prob": 92.4,
        "affected_assets": ["U-04", "E-01"],
        "target_controllers": ["PLC-04 (192.168.10.14)", "EWS-01 (192.168.10.20)"],
        "flagged_sensors": ["P4_ST_GOV", "P4_ST_TT01"],
        "correlated_vapt_findings": ["VAPT-2026-003"],
        "associated_run_id": "RUN-20261019-110500-SCEN-F",
        "evidence_references": [
            "Unauthenticated SMBv2 session opened on EWS-01 (192.168.10.20:445)",
            "Turbine governor speed P4_ST_GOV surged to 28,500 RPM (High trip: 22,000 RPM)"
        ],
        "assigned_status": "Mitigation Planned",
        "analyst_notes": "2026-10-19 11:10: Lateral movement suspected via removable media policy bypass on EWS-01. Windows GPO staged.",
        "mitigation_recommendation": "1. Isolate EWS-01 onto dedicated maintenance VLAN. 2. Enforce SMB message signing. 3. Verify turbine vibration telemetry.",
        "retest_outcome": "PENDING_RETEST",
        "timeline": [
            {"time": "11:05:14", "stage": "Lateral Ingress", "event": "Unauthorized SMB session opened on EWS-01 without valid Kerberos ticket."},
            {"time": "11:05:16", "stage": "S7comm Injection", "event": "S7comm block download sent from EWS-01 to PLC-04."},
            {"time": "11:05:18", "stage": "Physical Overspeed", "event": "Turbine rotor governor speed accelerates from 18,135 RPM to 28,500 RPM."},
            {"time": "11:05:20", "stage": "AI Detection", "event": "Dual-paradigm engine flags HIGH hazard on Process Unit 4."}
        ]
    }
]

def initialize_incident_state(simulator_history: List[Dict[str, Any]]):
    """Sync incidents from static history and active simulation runs into session state."""
    if "incident_records" not in st.session_state:
        st.session_state.incident_records = list(DEFAULT_INCIDENTS)

    # Ingest any new simulation runs as dynamically generated incidents
    existing_run_ids = {inc.get("associated_run_id") for inc in st.session_state.incident_records}
    for run in simulator_history:
        if run["threat_classification"] != "BENIGN_EQUILIBRIUM" and run["run_id"] not in existing_run_ids:
            new_inc_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{len(st.session_state.incident_records) + 1:03d}"
            new_inc = {
                "incident_id": new_inc_id,
                "title": f"{run['scenario_name']} (Injected Threat Event)",
                "detection_source": "CyberPhysicalCorrelator & AI Pipeline",
                "first_seen": run["start_time"].replace("T", " ")[:19],
                "last_seen": run["end_time"].replace("T", " ")[:19],
                "duration_seconds": 15,
                "peak_severity": run["ai_severity"],
                "peak_anomaly_score": run["anomaly_score"],
                "alert_threshold": run["alert_threshold"],
                "peak_supervised_prob": 98.5,
                "affected_assets": [run["target_asset"]],
                "target_controllers": [f"{run['target_controller']}"],
                "flagged_sensors": [d["tag"] for d in run.get("top_deviations", [])],
                "correlated_vapt_findings": [v["finding_id"] for v in run.get("correlated_vulnerabilities", [])],
                "associated_run_id": run["run_id"],
                "evidence_references": [
                    f"Simulated Injected Network Event: {run['network_event'].get('description', 'N/A')}",
                    f"Physical Anomaly Score: {run['anomaly_score']:+.4f} (Threshold: {run['alert_threshold']:+.4f})"
                ],
                "assigned_status": "New",
                "analyst_notes": f"{datetime.now().strftime('%H:%M:%S')}: Incident automatically aggregated from simulation run {run['run_id']}.",
                "mitigation_recommendation": "Inspect target controller conduit, verify physical sensor bounds, and enforce firewall access rule.",
                "retest_outcome": "PENDING_RETEST",
                "timeline": [
                    {"time": run["start_time"].split("T")[1][:8], "stage": "Attack Execution", "event": f"Scenario {run['scenario_id']} triggered against {run['target_asset']}."},
                    {"time": run["start_time"].split("T")[1][:8], "stage": "AI Flagged", "event": f"Detection: {run['ai_prediction']} ({run['threat_classification']})."},
                    {"time": run["end_time"].split("T")[1][:8], "stage": "Incident Logged", "event": f"Opened {new_inc_id}."}
                ]
            }
            st.session_state.incident_records.insert(0, new_inc)
            existing_run_ids.add(run["run_id"])


def render_incident_management_page(simulator_history: List[Dict[str, Any]]):
    """Render the full Incident Management and Investigation Dossier Workstation."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>📋 Security Incident Management &amp; SOC Investigation Dossier</h2>
            <p>End-to-end incident lifecycle: Aggregation, timeline reconstruction, root-cause correlation, and analyst triage.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    initialize_incident_state(simulator_history)
    incidents = st.session_state.incident_records

    # Overview KPI Cards
    k1, k2, k3, k4, k5 = st.columns(5)
    total_cnt = len(incidents)
    new_cnt = sum(1 for i in incidents if i["assigned_status"] == "New")
    investigating_cnt = sum(1 for i in incidents if i["assigned_status"] == "Investigating")
    mitigated_cnt = sum(1 for i in incidents if i["assigned_status"] in ("Mitigated", "Retested", "Closed"))
    crit_cnt = sum(1 for i in incidents if i["peak_severity"] == "CRITICAL")

    k1.metric("Total Incidents", f"{total_cnt} Active")
    k2.metric("New / Unacknowledged", new_cnt, delta="Requires Triage" if new_cnt > 0 else None, delta_color="inverse")
    k3.metric("Under Investigation", investigating_cnt)
    k4.metric("Mitigated / Closed", mitigated_cnt)
    k5.metric("Critical Severity", crit_cnt)

    st.markdown("---")

    # Layout: Master List (Left) and Deep Investigation Dossier (Right)
    col_list, col_dossier = st.columns([1.2, 1.8])

    with col_list:
        st.markdown("### 📋 Active Incident Queue")
        
        # Filter controls
        status_filter = st.selectbox(
            "Filter by Lifecycle Status:",
            ["ALL", "New", "Investigating", "Mitigation Planned", "Mitigated", "Retested", "Closed"],
            key="inc_status_filter"
        )

        filtered_incidents = incidents
        if status_filter != "ALL":
            filtered_incidents = [i for i in filtered_incidents if i["assigned_status"] == status_filter]

        if not filtered_incidents:
            st.info("No incidents matching selected filter.")
            selected_inc_id = incidents[0]["incident_id"] if incidents else None
        else:
            inc_options = [i["incident_id"] for i in filtered_incidents]
            selected_inc_id = st.radio(
                "Select Incident to Investigate:",
                inc_options,
                format_func=lambda x: f"[{x}] {next(i['title'] for i in incidents if i['incident_id'] == x)}",
                label_visibility="collapsed",
                key="inc_radio_select"
            )

        # Quick summary table
        st.markdown("#### Queue Summary:")
        q_rows = []
        for inc in filtered_incidents:
            q_rows.append({
                "ID": inc["incident_id"],
                "Severity": inc["peak_severity"],
                "Status": inc["assigned_status"],
                "Assets": ", ".join(inc["affected_assets"]),
                "Opened": inc["first_seen"].split(" ")[1]
            })
        st.dataframe(pd.DataFrame(q_rows), use_container_width=True, hide_index=True)

    with col_dossier:
        if not selected_inc_id:
            st.info("Select an incident to view investigation dossier.")
            return

        curr_inc = next((i for i in incidents if i["incident_id"] == selected_inc_id), incidents[0])

        # Header Badge Bar
        sev_color = "#dc2626" if curr_inc["peak_severity"] == "CRITICAL" else ("#d97706" if curr_inc["peak_severity"] == "HIGH" else "#0284c7")
        st.markdown(
            f"""
            <div style="background:#ffffff; border:1px solid #cbd5e1; border-left:4px solid {sev_color}; border-radius:4px; padding:12px; margin-bottom:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:12px; font-weight:700; color:#64748b; font-family:monospace;">{curr_inc['incident_id']}</span>
                    <span class="status-badge" style="background:{sev_color}; color:#ffffff;">● {curr_inc['peak_severity']} SEVERITY</span>
                </div>
                <div style="font-size:16px; font-weight:800; color:#0f172a; margin:4px 0;">{curr_inc['title']}</div>
                <div style="font-size:11px; color:#475569;">
                    <b>Timespan:</b> {curr_inc['first_seen']} → {curr_inc['last_seen']} ({curr_inc['duration_seconds']}s) | <b>Source:</b> {curr_inc['detection_source']}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Lifecycle State Transition Form
        with st.container():
            st.markdown("#### 🔄 Incident State Transition & Triage Actions")
            s_col1, s_col2 = st.columns([1.5, 1])

            with s_col1:
                state_options = ["New", "Investigating", "Mitigation Planned", "Mitigated", "Retested", "Closed"]
                cur_idx = state_options.index(curr_inc["assigned_status"]) if curr_inc["assigned_status"] in state_options else 0
                new_status = st.selectbox(
                    "Update Assigned Status:",
                    state_options,
                    index=cur_idx,
                    key=f"status_select_{curr_inc['incident_id']}"
                )
                if new_status != curr_inc["assigned_status"]:
                    curr_inc["assigned_status"] = new_status
                    st.success(f"Status updated to: {new_status}")

            with s_col2:
                retest_opts = ["PENDING_RETEST", "VERIFIED_BLOCKED", "THREAT_PERSISTENT"]
                rt_idx = retest_opts.index(curr_inc["retest_outcome"]) if curr_inc["retest_outcome"] in retest_opts else 0
                new_retest = st.selectbox(
                    "Retest Validation Outcome:",
                    retest_opts,
                    index=rt_idx,
                    key=f"retest_select_{curr_inc['incident_id']}"
                )
                if new_retest != curr_inc["retest_outcome"]:
                    curr_inc["retest_outcome"] = new_retest

        # Correlated Cyber-Physical Traceability Card
        st.markdown("#### 🔗 Cross-Domain Cyber-Physical Traceability")
        t_col1, t_col2 = st.columns(2)
        with t_col1:
            st.markdown(f"- **Originating Simulation Run ID**: `{curr_inc.get('associated_run_id', 'N/A')}`")
            st.markdown(f"- **Target Assets**: `{', '.join(curr_inc['affected_assets'])}`")
            st.markdown(f"- **Target Controllers**: `{', '.join(curr_inc['target_controllers'])}`")
            st.markdown(f"- **Deviating Physical Sensors**: `{', '.join(curr_inc['flagged_sensors'])}`")
        with t_col2:
            st.markdown(f"- **Isolation Forest Anomaly Score**: `{curr_inc['peak_anomaly_score']:+.4f}` (Thresh: `+{curr_inc['alert_threshold']:.4f}`)")
            st.markdown(f"- **Supervised Attack Probability**: `{curr_inc['peak_supervised_prob']:.1f}%`")
            st.markdown(f"- **Verification Posture**: `{curr_inc.get('retest_outcome', 'PENDING_RETEST')}`")
            st.markdown(f"- **Operational Impact**: Primary loop setpoints deviated from nominal ISA bounds")

        # Timeline Reconstruction
        st.markdown("#### ⏱️ Step-by-Step Chronological Timeline")
        timeline = curr_inc.get("timeline", [])
        if timeline:
            for item in timeline:
                st.markdown(
                    f"""
                    <div style="border-left: 2px solid #2563eb; padding-left: 10px; margin-left: 4px; margin-bottom: 6px; font-size: 11px;">
                        <span style="font-weight:700; color:#2563eb; font-family:monospace;">[{item['time']}]</span>
                        <span style="background:#e0f2fe; color:#0369a1; padding:1px 5px; border-radius:3px; font-weight:600; font-size:10px;">{item['stage']}</span>
                        <span style="color:#1f2937; margin-left:4px;">{item['event']}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

        # Evidence References
        st.markdown("#### 🔬 Technical Proof-of-Concept & Telemetry Evidence")
        for ev in curr_inc.get("evidence_references", []):
            st.markdown(f"- `{ev}`")

        # Actionable Remediation Checklist
        st.markdown("#### 🛠️ Operator Actionable Mitigation Checklist")
        st.info(curr_inc["mitigation_recommendation"])

        # Analyst Investigation Notes
        st.markdown("#### 📝 Analyst Investigation Log & Notes")
        note_text = st.text_area(
            "Add Analyst Investigation Note:",
            value=curr_inc.get("analyst_notes", ""),
            height=90,
            key=f"notes_{curr_inc['incident_id']}"
        )
        if st.button("Save Analyst Note", key=f"btn_note_{curr_inc['incident_id']}"):
            curr_inc["analyst_notes"] = note_text
            st.success("Analyst note saved successfully.")

    # =========================================================================
    # TABULAR SECURITY ALERT LOG VIEWER (BELOW)
    # =========================================================================
    st.markdown("---")
    st.markdown("### 🗄️ Dispatched Security Alerts Log (1.0 Hz SCADA Stream)")
    st.caption("Immutable chronological alert records generated by the real-time inference engine and persisted to disk:")

    if SECURITY_ALERTS_PATH.exists():
        alerts_df = pd.read_csv(SECURITY_ALERTS_PATH)
        if not alerts_df.empty:
            st.dataframe(alerts_df.head(50), use_container_width=True)
            st.caption(f"Showing latest 50 of {len(alerts_df)} persistent alert records from `results/security_alerts.csv`.")
        else:
            st.info("No security alerts logged yet.")
    else:
        st.info("No `security_alerts.csv` file found.")
