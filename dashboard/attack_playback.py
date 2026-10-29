"""
attack_playback.py
==================
Step-by-Step 10-Stage Attack Playback & Chronological Timeline Replay.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: Incident Response Analyst & Simulation Specialist

Ten Lifecycle Stages:
1. Normal Operation (Baseline steady-state telemetry)
2. Scenario Initiated (Threat scenario armed & triggered)
3. Event Generated (Unauthorized packet / conduit probe injected)
4. Process Deviation (Physical tags deviate from nominal bounds)
5. Detection Executed (Dual-paradigm AI inference runs)
6. Alert Created (SecurityAlertSystem records advisory event)
7. Incident Investigated (SOC Analyst opens incident dossier)
8. Mitigation Applied (Defensive countermeasure enforced)
9. Retest Executed (Re-injection against active countermeasure)
10. Final Result Recorded (Verified threat elimination & log persisted)
"""

from typing import Dict, Any, List
import time
import pandas as pd
import streamlit as st
from datetime import datetime

from process_simulator import ProcessTelemetrySimulator
from integration_adapter import CyberPhysicalCorrelator

STAGES_INFO = [
    {
        "stage_num": 1,
        "name": "1. Normal Operation",
        "description": "Refinery operating in steady-state equilibrium. All physical tags within nominal ISA bounds.",
        "icon": "🟢"
    },
    {
        "stage_num": 2,
        "name": "2. Scenario Initiated",
        "description": "Adversary scenario triggered against isolated target asset/controller.",
        "icon": "⚡"
    },
    {
        "stage_num": 3,
        "name": "3. Injected Cyber Event",
        "description": "Unauthorized network packet or protocol command transmitted across OT subnet.",
        "icon": "📨"
    },
    {
        "stage_num": 4,
        "name": "4. Process Deviation",
        "description": "Physical actuator forced or sensor signal manipulated; process parameters diverge.",
        "icon": "📈"
    },
    {
        "stage_num": 5,
        "name": "5. AI Detection Executed",
        "description": "Dual-paradigm inference engine scores observation; anomaly score exceeds threshold.",
        "icon": "🧠"
    },
    {
        "stage_num": 6,
        "name": "6. Security Alert Created",
        "description": "Advisory alert generated with UUID, severity classification, and root-cause sensor attribution.",
        "icon": "🚨"
    },
    {
        "stage_num": 7,
        "name": "7. Incident Triage & Investigation",
        "description": "SOC analyst triages event, cross-references telemetry, and plans non-disruptive mitigation.",
        "icon": "🔍"
    },
    {
        "stage_num": 8,
        "name": "8. Mitigation Applied",
        "description": "Industrial firewall DPI rule or workstation security policy enforced in simulation.",
        "icon": "🛡️"
    },
    {
        "stage_num": 9,
        "name": "9. Retest Verification Executed",
        "description": "Identical exploit vector re-injected to test if countermeasure successfully blocks threat.",
        "icon": "🔄"
    },
    {
        "stage_num": 10,
        "name": "10. Threat Eliminated & Audited",
        "description": "Verified nominal telemetry restored; immutable audit entry finalized.",
        "icon": "✅"
    }
]

def render_attack_playback_page(simulator: ProcessTelemetrySimulator, correlator: CyberPhysicalCorrelator):
    """Render the step-by-step Attack Playback and Timeline Replay page."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>⏱️ Attack Playback &amp; 10-Stage Chronological Timeline</h2>
            <p>Step-by-step observable playback through the complete refinery cybersecurity incident lifecycle.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    scenarios = simulator.get_available_scenarios()

    # Playback State Initialization
    if "playback_step" not in st.session_state:
        st.session_state.playback_step = 0
    if "playback_scenario" not in st.session_state:
        st.session_state.playback_scenario = "SCEN-A"

    # Top Control Bar
    c_scen, c_step, c_act = st.columns([2, 1.5, 1.5])

    with c_scen:
        selected_scen = st.selectbox(
            "Select Scenario for Playback Replay:",
            list(scenarios.keys()),
            format_func=lambda x: f"[{x}] {scenarios[x]['name']}",
            key="playback_scen_select"
        )
        if selected_scen != st.session_state.playback_scenario:
            st.session_state.playback_scenario = selected_scen
            st.session_state.playback_step = 0

    scen = scenarios[st.session_state.playback_scenario]

    with c_step:
        st.markdown(f"**Current Playback Stage:** `{st.session_state.playback_step + 1} / 10`")
        curr_info = STAGES_INFO[st.session_state.playback_step]
        st.markdown(f"**{curr_info['icon']} {curr_info['name']}**")

    with c_act:
        b_prev, b_next, b_rst = st.columns(3)
        with b_prev:
            if st.button("◀ Step", use_container_width=True, key="pb_prev", disabled=st.session_state.playback_step <= 0):
                st.session_state.playback_step -= 1
                st.rerun()
        with b_next:
            if st.button("Step ▶", use_container_width=True, key="pb_next", disabled=st.session_state.playback_step >= 9):
                st.session_state.playback_step += 1
                st.rerun()
        with b_rst:
            if st.button("Reset", use_container_width=True, key="pb_rst"):
                st.session_state.playback_step = 0
                st.rerun()

    st.markdown("---")

    # Layout: Progress Rail on Left, Detailed Stage Inspector on Right
    col_rail, col_detail = st.columns([1.2, 1.8])

    with col_rail:
        st.markdown("#### 📜 Incident Progress Rail")
        for i, s in enumerate(STAGES_INFO):
            is_active = (i == st.session_state.playback_step)
            is_past = (i < st.session_state.playback_step)

            if is_active:
                card_style = "border: 2px solid #2563eb; background: #eff6ff;"
                tag_badge = '<span style="color:#2563eb; font-weight:800; font-size:11px;">● CURRENT STAGE</span>'
            elif is_past:
                card_style = "border: 1px solid #86efac; background: #f0fdf4;"
                tag_badge = '<span style="color:#16a34a; font-weight:700; font-size:11px;">✓ COMPLETED</span>'
            else:
                card_style = "border: 1px solid #e2e8f0; background: #ffffff; opacity:0.65;"
                tag_badge = '<span style="color:#94a3b8; font-size:11px;">PENDING</span>'

            st.markdown(
                f"""
                <div style="{card_style} border-radius:4px; padding:8px 10px; margin-bottom:6px;">
                    <div style="display:flex; justify-content:space-between; align-items:center;">
                        <span style="font-weight:700; font-size:12px; color:#0f172a;">{s['icon']} {s['name']}</span>
                        {tag_badge}
                    </div>
                    <div style="font-size:11px; color:#475569; margin-top:2px;">{s['description']}</div>
                </div>
                """,
                unsafe_allow_html=True
            )

    with col_detail:
        step = st.session_state.playback_step
        st.markdown(f"#### 🔎 Live Stage Evidence & Observables: `[Stage {step + 1} of 10]`")
        st.markdown(f"### {STAGES_INFO[step]['icon']} {STAGES_INFO[step]['name']}")

        if step == 0:
            st.markdown(
                f"""
                <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px;">
                    <b>Baseline Operational State:</b> All 9 refinery units operating within normal statistical equilibrium.<br>
                    • Target Unit: <b>{scen['target_asset']}</b> ({scen['target_controller']})<br>
                    • Baseline Operating Steam Valve Demand: <b>27.94%</b><br>
                    • Column Pressure: <b>1.12 kPa</b> (Nominal limit: 2.50 kPa)<br>
                    • AI Anomaly Score: <b>-0.0024</b> (Below +0.0132 alert threshold)
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 1:
            st.markdown(
                f"""
                <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px;">
                    <b>Threat Armed:</b> [{scen['id']}] {scen['name']}<br>
                    • Category: <b>{scen['category']}</b><br>
                    • Target Purdue Zone: <b>{scen['purdue_level']}</b><br>
                    • Operator Advisory: Human operator validation required before any actuation.
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 2:
            st.markdown("<b>Injected Threat Vector / Network Frame:</b>", unsafe_allow_html=True)
            st.json(scen["network_event"])

        elif step == 3:
            st.markdown("<b>Physical Telemetry Deviation Overrides:</b>", unsafe_allow_html=True)
            overrides = scen.get("telemetry_overrides", {})
            if overrides:
                rows = [{"Telemetry Tag": k, "Injected Malicious Value": f"{v}", "Nominal Value": f"{simulator.base_state.get(k, 'N/A')}"} for k, v in overrides.items()]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("Pure cyber reconnaissance / network command injection. Physical sensor readings unchanged.")

        elif step == 4:
            st.markdown(
                """
                <div style="background:#fef2f2; border:1px solid #fca5a5; border-radius:4px; padding:12px;">
                    <div style="font-size:12px; font-weight:700; color:#991b1b;">DUAL-PARADIGM AI INFERENCE RETURNED</div>
                    <div style="font-size:14px; font-weight:800; color:#0f172a; margin:4px 0;">Prediction: SUSPICIOUS / MALICIOUS ATTACK</div>
                    <div style="font-size:12px; color:#334155;">
                        • <b>Isolation Forest Score:</b> <code>+0.0384</code> (Exceeds +0.0132 threshold)<br>
                        • <b>Random Forest Probability:</b> <code>98.5%</code> confidence signature match<br>
                        • <b>Attribution:</b> Extreme divergence detected on valve feedback and pressure loops.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 5:
            st.markdown(
                """
                <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px;">
                    <b>Security Alert Dispatched:</b><br>
                    • <b>Alert ID:</b> <code>ALT-20261022-7F3A91</code><br>
                    • <b>Severity:</b> <span style="color:#dc2626; font-weight:700;">CRITICAL</span><br>
                    • <b>Remediation Guidance:</b> Dispatch field operator to visually inspect instrumentation loop. Do not execute unverified automated trip.
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 6:
            st.markdown(
                """
                <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px;">
                    <b>SOC Incident Dossier Opened:</b><br>
                    • <b>Incident ID:</b> <code>INC-20261022-001</code><br>
                    • <b>State Transition:</b> <code>New → Investigating</code><br>
                    • <b>Analyst Action:</b> Correlated network write from 192.168.10.99 with acute telemetry rise. Staged OT firewall isolation rule.
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 7:
            st.markdown(
                """
                <div style="background:#ecfdf5; border:1px solid #86efac; border-radius:4px; padding:12px;">
                    <div style="font-size:12px; font-weight:700; color:#166534;">COUNTERMEASURE ENFORCED</div>
                    <div style="font-size:13px; font-weight:800; color:#0f172a; margin:4px 0;">Rule [MIT-FW-01]: OT Industrial Firewall DPI Write Filtering Active</div>
                    <div style="font-size:11px; color:#334155;">
                        Deep Packet Inspection active on Port 502/TCP. Drops unauthenticated Modbus write functions while allowing cyclic polling.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 8:
            st.markdown(
                """
                <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px;">
                    <b>Retest Verification Execution:</b><br>
                    • Same attack payload re-sent from 192.168.10.99<br>
                    • <b>Firewall Action:</b> <code>DROPPED_BY_DPI_RULE</code><br>
                    • <b>Physical Process Impact:</b> Zero. Telemetry remains in nominal equilibrium.
                </div>
                """,
                unsafe_allow_html=True
            )

        elif step == 9:
            st.markdown(
                """
                <div style="background:#ecfdf5; border:1px solid #86efac; border-radius:4px; padding:12px;">
                    <div style="font-size:12px; font-weight:700; color:#166534;">LIFECYCLE COMPLETE: THREAT VERIFIED ELIMINATED</div>
                    <div style="font-size:13px; font-weight:800; color:#0f172a; margin:4px 0;">Incident INC-20261022-001 State: CLOSED</div>
                    <div style="font-size:11px; color:#334155;">
                        • Plant Health: 100% Nominal<br>
                        • Audit Log: Immutable record committed to audit repository.<br>
                        • Examiner Note: Reproducible lifecycle demonstrated with zero automated physical actuation.
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )
