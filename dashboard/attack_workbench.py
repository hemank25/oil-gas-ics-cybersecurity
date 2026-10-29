"""
attack_workbench.py
===================
Controlled ICS Attack Simulation Suite & Audit Workbench.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: Attack Simulation Specialist & AI Integration (Student 3 & Student 2)

Features:
- Deterministic execution of predefined scenarios A through F
- Live integration with CyberPhysicalCorrelator and IndustrialPredictor
- Traceable run records with Scenario ID, Run ID, timestamps, target asset, observables, and detector outputs
- Safety-first execution within isolated memory space (No real field traffic)
"""

from typing import Dict, Any, List
import pandas as pd
import streamlit as st
from datetime import datetime

from process_simulator import ProcessTelemetrySimulator
from integration_adapter import CyberPhysicalCorrelator
from assets_config import update_asset_status, reset_asset_registry

def render_attack_simulation_page(simulator: ProcessTelemetrySimulator, correlator: CyberPhysicalCorrelator):
    """Render the full Attack Simulation Workbench."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>⚔️ Controlled ICS Attack Simulation Suite</h2>
            <p>Safe, deterministic cyber-physical threat execution targeting isolated refinery units and controllers.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        > **SAFETY COMPLIANCE MANDATE**: All scenarios execute strictly within memory models and local proxy testbeds.
        > Zero physical valve registers or real industrial controllers are ever probed or altered.
        """
    )

    scenarios = simulator.get_available_scenarios()

    # Scenario Selection Box
    scen_col1, scen_col2 = st.columns([1.8, 1.2])

    with scen_col1:
        scenario_keys = list(scenarios.keys())
        selected_scen_id = st.selectbox(
            "Select Attack Scenario to Arm:",
            scenario_keys,
            format_func=lambda x: f"[{x}] {scenarios[x]['name']}",
            key="attack_scen_select"
        )
        scen = scenarios[selected_scen_id]

    with scen_col2:
        st.markdown(
            f"""
            <div style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:4px; padding:10px 14px;">
                <div style="font-size:11px; font-weight:700; color:#64748b;">TARGET ASSET PROFILE</div>
                <div style="font-size:14px; font-weight:800; color:#0f172a;">{scen['target_asset']} — {scen['target_controller']}</div>
                <div style="font-size:11px; color:#475569;">Purdue: {scen['purdue_level']}</div>
                <div style="font-size:11px; color:#0284c7; font-weight:600;">Category: {scen['category']}</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    # Scenario Details & Expected Observables
    with st.container():
        st.markdown(f"#### 📝 Scenario Specification: `[{scen['id']}]`")
        st.markdown(f"**Description**: {scen['description']}")

        obs_col1, obs_col2 = st.columns([1.5, 1])
        with obs_col1:
            st.markdown("**Expected Physical & Cyber Observables:**")
            for obs in scen["expected_observables"]:
                st.markdown(f"- {obs}")

        with obs_col2:
            st.markdown("**Injected Threat Vector / Network Packet:**")
            st.json(scen["network_event"])

    st.markdown("---")

    # Simulation Controls Row
    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1.5, 1, 1.5])

    with ctrl_col1:
        run_btn = st.button("🚀 Execute Armed Scenario", type="primary", use_container_width=True, key="run_attack_btn")

    with ctrl_col2:
        reset_btn = st.button("🔄 Reset Baseline", use_container_width=True, key="reset_attack_btn")

    with ctrl_col3:
        st.caption("Execution generates an immutable audit record and triggers the real AI detection pipeline.")

    if reset_btn:
        simulator.clear_overrides()
        reset_asset_registry()
        st.success("✅ Plant state restored to nominal equilibrium. Asset statuses nominal.")

    # Execution Logic
    if run_btn:
        with st.spinner(f"Executing {scen['id']} through isolated simulation and AI detection pipeline..."):
            audit_record = simulator.execute_scenario(selected_scen_id, correlator)
            st.session_state["last_run_record"] = audit_record
            
            # Update target asset status dynamically
            is_attack = (audit_record["threat_classification"] != "BENIGN_EQUILIBRIUM")
            if is_attack:
                update_asset_status(scen["target_asset"], operational_status="ALARM", security_status="SUSPECTED_ATTACK")
            else:
                update_asset_status(scen["target_asset"], operational_status="ONLINE", security_status="SECURE")

        st.success(f"✅ Run Completed! Traceable Run ID: `{audit_record['run_id']}`")

    # Display Last Run Results
    if "last_run_record" in st.session_state:
        last = st.session_state["last_run_record"]
        st.markdown(f"### 📡 Execution Output & AI Diagnostic: `{last['run_id']}`")

        r1, r2, r3, r4 = st.columns(4)
        is_attack = (last["threat_classification"] != "BENIGN_EQUILIBRIUM")
        r1.metric("Threat Classification", last["threat_classification"], delta="Flagged" if is_attack else "Nominal", delta_color="inverse" if is_attack else "normal")
        r2.metric("AI Anomaly Prediction", last["ai_prediction"])
        r3.metric("Anomaly Score", f"{last['anomaly_score']:+.4f}", f"Threshold: {last['alert_threshold']:+.4f}")
        r4.metric("Severity Level", last["ai_severity"])

        # Target Impact Details
        st.markdown(
            f"""
            <div style="background:{'#fef2f2' if is_attack else '#ecfdf5'}; border:1px solid {'#fca5a5' if is_attack else '#86efac'}; border-radius:4px; padding:10px 14px; margin: 8px 0;">
                <b>Target Asset Impact:</b> Asset <code>{last['target_asset']}</code> ({last['target_controller']}) state transitioned to 
                <span style="font-weight:700; color:{'#991b1b' if is_attack else '#166534'};">
                    ● {'ALARM / SUSPECTED ATTACK' if is_attack else 'ONLINE / NOMINAL'}
                </span>.
            </div>
            """,
            unsafe_allow_html=True
        )

        # Deviating Sensors Table
        devs = last.get("top_deviations", [])
        if devs:
            st.markdown("#### 🔍 Root-Cause Sensor Attribution (Standard Deviations σ from Normal):")
            st.dataframe(pd.DataFrame(devs), use_container_width=True)

    st.markdown("---")

    # =========================================================================
    # TRACEABLE AUDIT RUN HISTORY
    # =========================================================================
    st.markdown("### 🗄️ Traceable Simulation Run History (Immutable Audit Log)")
    history = simulator.get_audit_history()

    if history:
        summary_rows = []
        for h in history:
            summary_rows.append({
                "Run ID": h["run_id"],
                "Scenario": f"[{h['scenario_id']}] {h['scenario_name']}",
                "Target Asset": h["target_asset"],
                "Threat Assessment": h["threat_classification"],
                "AI Prediction": h["ai_prediction"],
                "Anomaly Score": f"{h['anomaly_score']:+.4f}",
                "Timestamp": h["start_time"].split("T")[1][:8]
            })
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)
    else:
        st.info("No attack simulation runs recorded in current session. Execute a scenario above to generate auditable events.")
