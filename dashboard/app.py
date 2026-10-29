"""
app.py
======
MUJ Demo Refinery — Operations & AI Cybersecurity Control Center.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Center for a Simulated Oil & Gas Refinery
- Role: Senior Industrial SCADA/HMI Interface Designer, Machine Learning Engineer & ICS Architect

Architecture:
- 14 Modular Sections across Operations, Network, AI Detection, Attack Lab, Mitigation & Research
- Full compliance with ISA-101 / ISA-18.2 SCADA HMI guidelines
- Transparent Provenance: Distinct simulation telemetry, proxy replay, and synthetic attack events
- Defense-in-Depth: Multi-tier detection (Physics bounds, Isolation Forest, Random Forest)
- Safety Interlock: Zero automated physical actuation (Human-in-the-loop validation)
"""

import os
import sys
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional

import numpy as np
import pandas as pd
import streamlit as st

# Setup paths relative to workspace root
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
INFERENCE_DIR = WORKSPACE_ROOT / "ai detection" / "inference"
MODELS_DIR = WORKSPACE_ROOT / "ai detection" / "models"
PROCESSED_DIR = WORKSPACE_ROOT / "ai detection" / "dataset" / "processed"
RESULTS_DIR = WORKSPACE_ROOT / "results"
SIMULATION_DIR = WORKSPACE_ROOT / "simulation"
DASHBOARD_DIR = WORKSPACE_ROOT / "dashboard"

for p in [str(INFERENCE_DIR), str(SIMULATION_DIR), str(DASHBOARD_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

# Import local modules
from assets_config import (
    ASSET_REGISTRY,
    FACILITY_NAME,
    FACILITY_LOCATION,
    STATUS_COLORS,
    SECURITY_COLORS,
    get_all_assets,
    get_asset,
    filter_assets,
    get_facility_summary,
    reset_asset_registry
)
from facility_map import render_facility_map_page
from live_operations import render_live_operations_page
from network_topology import render_network_topology_page
from attack_workbench import render_attack_simulation_page
from ai_analysis import render_ai_detection_page
from attack_playback import render_attack_playback_page
from incident_workspace import render_incident_management_page
from mitigation_workspace import render_mitigation_page
from model_eval_workspace import render_model_performance_page
from manual_tester import render_manual_tester_page
from comparison_workspace import render_comparison_workspace_page
from demonstration_mode import render_demonstration_page
from audit_log import render_audit_log_page

from process_simulator import ProcessTelemetrySimulator
from predict import IndustrialPredictor
from alert_system import SecurityAlertSystem
from integration_adapter import CyberPhysicalCorrelator

# Configure Streamlit page
st.set_page_config(
    page_title="MUJ Demo Refinery — Control Center",
    page_icon="🏭",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load custom industrial CSS
css_path = DASHBOARD_DIR / "style.css"
if css_path.exists():
    with open(css_path, "r", encoding="utf-8") as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# -----------------------------------------------------------------------------
# CACHED LOADERS FOR MODELS AND ARTIFACTS
# -----------------------------------------------------------------------------
@st.cache_resource
def load_predictor():
    """Load the trained dual-paradigm model suite."""
    return IndustrialPredictor(models_dir=MODELS_DIR)

@st.cache_resource
def load_correlator():
    """Load the cross-domain cyber-physical correlator."""
    return CyberPhysicalCorrelator(predictor=load_predictor())

@st.cache_resource
def load_simulator():
    """Load the deterministic attack and process simulator."""
    return ProcessTelemetrySimulator(seed=42)

@st.cache_data
def load_evaluation_metrics():
    path = RESULTS_DIR / "evaluation_metrics.json"
    if path.exists():
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

@st.cache_data
def load_security_alerts():
    path = RESULTS_DIR / "security_alerts.csv"
    if path.exists():
        try:
            return pd.read_csv(path)
        except Exception:
            return pd.DataFrame()
    return pd.DataFrame()

@st.cache_data
def load_incident_summary():
    path = RESULTS_DIR / "incident_summary.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []

# Initialize resources
predictor = load_predictor()
correlator = load_correlator()
simulator = load_simulator()

# -----------------------------------------------------------------------------
# SIDEBAR NAVIGATION & SYSTEM HEALTH RAIL
# -----------------------------------------------------------------------------
with st.sidebar:
    st.markdown(
        f"""
        <div style="padding: 4px 0 8px 0; border-bottom: 2px solid #cbd5e1;">
            <div style="font-size: 11px; font-weight: 700; color: #64748b; letter-spacing: 0.5px;">REFINERY OPERATIONS &amp; SOC</div>
            <div style="font-size: 16px; font-weight: 800; color: #0f172a;">{FACILITY_NAME}</div>
            <div style="font-size: 10px; color: #475569;">Manipal University Jaipur | Sem 5 Capstone</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
    st.markdown("**Navigation Console**")

    # Final 14 Industrial Navigation Sections
    nav_options = [
        "1. Plant Overview",
        "2. Refinery Map",
        "3. Live Operations",
        "4. Network Topology",
        "5. Attack Simulation",
        "6. AI Detection",
        "7. Attack Playback",
        "8. Incident Investigation",
        "9. Mitigation & Recovery",
        "10. ML Model Laboratory",
        "11. Manual Telemetry Tester",
        "12. Normal vs Attack Comparison",
        "13. Demonstration Mode",
        "14. Event History & Audit Log"
    ]

    selected_nav = st.radio(
        "Navigation Sections",
        nav_options,
        index=0,
        label_visibility="collapsed"
    )

    st.divider()

    # Supervisory System Health Panel
    st.markdown("**Supervisory System Health**")
    facility_stats = get_facility_summary()

    # Operational status indicator
    if facility_stats["alarm_count"] > 0:
        st.error(f"🔴 PLANT STATE: ALARM ({facility_stats['alarm_count']} Active)")
    elif facility_stats["warning_count"] > 0:
        st.warning(f"🟡 PLANT STATE: WARNING ({facility_stats['warning_count']} Advisory)")
    else:
        st.success(f"🟢 PLANT STATE: NOMINAL ({facility_stats['online_count']}/{facility_stats['total_assets']} Online)")

    st.markdown(
        f"""
        <div style="font-size: 11px; color: #334155; line-height: 1.6; background: #ffffff; padding: 8px; border-radius: 4px; border: 1px solid #cbd5e1;">
            <div><b>AI Engine:</b> <span style="color:#16a34a; font-weight:700;">● Dual-Paradigm Active</span></div>
            <div><b>Models:</b> Isolation Forest + RF</div>
            <div><b>Trained Threshold:</b> <code>+0.0132</code></div>
            <div><b>Scan Frequency:</b> 1.0 Hz (1 sample/sec)</div>
            <div><b>Active Assets:</b> 9 Simulated Nodes</div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.divider()
    st.markdown(
        """
        <div style="font-size: 10px; color: #dc2626; background: #fef2f2; padding: 6px; border-radius: 4px; border: 1px solid #fecaca; font-weight: 600;">
            ⚠️ SAFETY INTERLOCK MANDATE:<br>
            Automated plant actuation strictly INHIBITED. Operator validation required.
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
    st.caption("MUJ Capstone: AI-Assisted Cybersecurity Control Center")


# -----------------------------------------------------------------------------
# HELPER: DATA ORIGIN BANNER
# -----------------------------------------------------------------------------
def render_data_origin_banner(source_type: str = "LIVE_SIMULATION", details: str = ""):
    """Render a visible indicator for data origin to prevent confusing proxy/replay with live plant data."""
    badges = {
        "LIVE_SIMULATION": ("origin-live", "DATA SOURCE: DETERMINISTIC TELEMETRY SIMULATION", "Generated by physical process simulation for fictional units U-01 to U-05."),
        "HAI_REPLAY": ("origin-replay", "DATA SOURCE: HAI 23.05 ICS PROXY REPLAY", "Replayed from public research testbed dataset (86 physical tags, 284,400 test observations)."),
        "SYNTHETIC_SCENARIO": ("origin-synthetic", "DATA SOURCE: SYNTHETIC ATTACK INJECTION", "Controlled cyber-physical exploit event generated in isolated laboratory testbed."),
        "SAVED_HISTORICAL": ("origin-saved", "DATA SOURCE: SAVED AUDIT LOGS", "Locally persisted evaluation and alert records from prior simulation runs.")
    }
    badge_cls, label, default_desc = badges.get(source_type, badges["LIVE_SIMULATION"])
    desc = details or default_desc

    st.markdown(
        f"""
        <div class="scada-top-bar">
            <div style="display: flex; align-items: center; gap: 8px;">
                <span class="scada-top-pill {badge_cls}">● {label}</span>
                <span style="color: #64748b;">{desc}</span>
            </div>
            <div style="font-family: monospace; color: #94a3b8;">
                SYS REF: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} UTC
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )


# =============================================================================
# PAGE 1: PLANT OVERVIEW
# =============================================================================
if selected_nav == "1. Plant Overview":
    st.markdown(
        f"""
        <div class="industrial-header">
            <h2>🏭 Plant Operational Overview — {FACILITY_NAME}</h2>
            <p>Supervisory telemetry summary, unit health status, active process alarms, and AI detection readiness.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    render_data_origin_banner("LIVE_SIMULATION", "Real-time aggregated health metrics from 9 fictional refinery assets.")

    stats = get_facility_summary()
    incidents = load_incident_summary()
    alerts_df = load_security_alerts()

    # KPI Metric Cards Row 1
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Facility Status</div>
                <div class="kpi-value" style="color: #16a34a;">ONLINE</div>
                <div class="kpi-sub">{stats['online_count']} of {stats['total_assets']} Assets Nominal</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col2:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Process Units</div>
                <div class="kpi-value">{stats['process_units']} Units</div>
                <div class="kpi-sub">U-01 through U-05</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col3:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Active Alarms</div>
                <div class="kpi-value" style="color: {'#dc2626' if stats['alarm_count'] > 0 else '#16a34a'};">{stats['alarm_count']}</div>
                <div class="kpi-sub">Process Safety Trip Limits</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col4:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Security Incidents</div>
                <div class="kpi-value" style="color: {'#d97706' if len(incidents) > 0 else '#16a34a'};">{len(incidents)} Open</div>
                <div class="kpi-sub">Correlated SOC Alerts</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with col5:
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Facility Health</div>
                <div class="kpi-value" style="color: #16a34a;">{stats['facility_health_pct']}%</div>
                <div class="kpi-sub">Overall Plant Availability</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Two column overview: Refinery Subsystem Grid and Real-Time Event Summary
    col_units, col_events = st.columns([1.6, 1.4])

    with col_units:
        st.markdown("### 🎛️ Refinery Process Units & Cyber Assets")
        assets = get_all_assets()
        unit_rows = []
        for aid, a in assets.items():
            op = a["operational_status"]
            sec = a["security_status"]
            tags_cnt = len(a.get("tags", []))
            unit_rows.append({
                "Asset ID": aid,
                "Name / Description": a["short_name"],
                "Purdue Level": a["purdue_level"].split(":")[0],
                "IP Address": a["ip_address"].split(" ")[0],
                "Operational": f"● {op}",
                "Security Posture": f"🛡️ {sec}",
                "Monitored Tags": f"{tags_cnt} Tags" if tags_cnt > 0 else "Host Node"
            })
        st.dataframe(pd.DataFrame(unit_rows), use_container_width=True, hide_index=True)

        st.caption(
            "Note: Assets U-01 to U-05 represent physical refining trains. "
            "C-01, H-01, E-01, and N-01 represent supervisory SCADA and network perimeter nodes."
        )

    with col_events:
        st.markdown("### 🚨 Recent Supervisory Alerts & Audit Log")
        recent_runs = simulator.get_audit_history()
        if recent_runs:
            last_run = recent_runs[0]
            is_mal = (last_run["threat_classification"] != "BENIGN_EQUILIBRIUM")
            box_bg = "#fef2f2" if is_mal else "#ecfdf5"
            border_c = "#fca5a5" if is_mal else "#86efac"
            txt_c = "#991b1b" if is_mal else "#166534"
            st.markdown(
                f"""
                <div style="background:{box_bg}; border:1px solid {border_c}; border-radius:4px; padding:8px 10px; margin-bottom:10px;">
                    <div style="font-size:10px; font-weight:700; color:#64748b;">MOST RECENT SIMULATION AUDIT EVENT</div>
                    <div style="font-size:12px; font-weight:800; color:#0f172a;">{last_run['run_id']}</div>
                    <div style="font-size:11px; color:#334155;">Scenario: <b>[{last_run['scenario_id']}] {last_run['scenario_name']}</b></div>
                    <div style="font-size:11px; color:{txt_c}; font-weight:700; margin-top:2px;">
                        ● {last_run['threat_classification']} | Score: {last_run['anomaly_score']:+.4f} (Thresh: {last_run['alert_threshold']:+.4f})
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        if not alerts_df.empty:
            cols_to_show = [c for c in ["timestamp", "subsystems", "primary_sensor", "severity", "anomaly_score"] if c in alerts_df.columns]
            recent_alerts = alerts_df.head(5)[cols_to_show]
            st.dataframe(recent_alerts, use_container_width=True, hide_index=True)
            st.markdown(f"**Total Persistent Alerts Logged**: `{len(alerts_df)} records`")
        else:
            st.info("No persistent security alerts logged. Run an Attack Scenario to generate audit records.")

        st.markdown("#### 🔬 AI Inference Pipeline Health")
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.markdown(f"- **Detector**: Isolation Forest")
            st.markdown(f"- **Trained Threshold**: `+0.0132`")
            st.markdown(f"- **Supervised Classifier**: Random Forest")
        with col_m2:
            st.markdown(f"- **Input Schema**: 86 Physical Continuous Tags")
            st.markdown(f"- **Proxy Dataset**: HAI 23.05 Testbed")
            st.markdown(f"- **Inference Latency**: `13.85 ms / 1k`")


# =============================================================================
# PAGE 2: REFINERY MAP
# =============================================================================
elif selected_nav == "2. Refinery Map":
    render_facility_map_page()


# =============================================================================
# PAGE 3: LIVE OPERATIONS
# =============================================================================
elif selected_nav == "3. Live Operations":
    render_live_operations_page(simulator)


# =============================================================================
# PAGE 4: NETWORK TOPOLOGY
# =============================================================================
elif selected_nav == "4. Network Topology":
    render_network_topology_page()


# =============================================================================
# PAGE 5: ATTACK SIMULATION
# =============================================================================
elif selected_nav == "5. Attack Simulation":
    render_attack_simulation_page(simulator, correlator)


# =============================================================================
# PAGE 6: AI DETECTION
# =============================================================================
elif selected_nav == "6. AI Detection":
    render_ai_detection_page(predictor)


# =============================================================================
# PAGE 7: ATTACK PLAYBACK
# =============================================================================
elif selected_nav == "7. Attack Playback":
    render_attack_playback_page(simulator, correlator)


# =============================================================================
# PAGE 8: INCIDENT INVESTIGATION
# =============================================================================
elif selected_nav == "8. Incident Investigation":
    render_incident_management_page(simulator.get_audit_history())


# =============================================================================
# PAGE 9: MITIGATION & RECOVERY
# =============================================================================
elif selected_nav == "9. Mitigation & Recovery":
    render_mitigation_page(simulator, correlator)


# =============================================================================
# PAGE 10: ML MODEL LABORATORY
# =============================================================================
elif selected_nav == "10. ML Model Laboratory":
    render_model_performance_page()


# =============================================================================
# PAGE 11: MANUAL TELEMETRY TESTER
# =============================================================================
elif selected_nav == "11. Manual Telemetry Tester":
    render_manual_tester_page(predictor)


# =============================================================================
# PAGE 12: NORMAL VS ATTACK COMPARISON
# =============================================================================
elif selected_nav == "12. Normal vs Attack Comparison":
    render_comparison_workspace_page(simulator, correlator)


# =============================================================================
# PAGE 13: DEMONSTRATION MODE
# =============================================================================
elif selected_nav == "13. Demonstration Mode":
    render_demonstration_page(simulator, correlator)


# =============================================================================
# PAGE 14: EVENT HISTORY & AUDIT LOG
# =============================================================================
elif selected_nav == "14. Event History & Audit Log":
    render_audit_log_page(simulator)
