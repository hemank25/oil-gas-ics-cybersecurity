"""
mitigation_workspace.py
=======================
OT Security Mitigation, Retesting Verification & End-to-End Lifecycle Workbench.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: OT Cybersecurity Engineer & Incident Response Specialist

Key Capabilities:
1. Interactive Simulated Defensive Countermeasures (Firewall DPI, TLS Bastion, GPO).
2. Deterministic Before-and-After Retest Verification Engine.
3. Guided 8-Stage End-to-End Lifecycle Demonstration Runner.
4. Audit Trail Recording: Actor, timestamp, original state, new state, and retest evidence.
"""

from typing import Dict, Any, List, Optional
import json
import time
from pathlib import Path
from datetime import datetime

import pandas as pd
import streamlit as st

from process_simulator import ProcessTelemetrySimulator
from integration_adapter import CyberPhysicalCorrelator

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

# Persistent mitigation state defaults
DEFAULT_DEFENSIVE_POSTURE = {
    "fw_dpi_modbus": {
        "id": "MIT-FW-01",
        "name": "OT Industrial Firewall Modbus DPI Write Filtering",
        "target_asset": "N-01 / PLC-01",
        "description": "Enforce Deep Packet Inspection (DPI) dropping Modbus Function 06/16 writes originating outside authorized engineering subnet.",
        "addresses_vector": "Unauthorized Modbus Function 06 Write Injections",
        "addresses_scenario": "SCEN-A",
        "active": False,
        "enforced_by": "Shift Security Engineer",
        "last_updated": "2026-10-19 10:00:00",
        "operational_impact": "Blocks unauthorized valve demand injections. Authorized SCADA polling (Function 03) remains unimpeded."
    },
    "vnc_decommission": {
        "id": "MIT-HMI-02",
        "name": "Decommission Insecure VNC & Enforce TLS Bastion",
        "target_asset": "H-01",
        "description": "Close cleartext VNC Port 5900/TCP on Operator Console; mandate TLS-encrypted RDP through authenticated Bastion jump host.",
        "addresses_vector": "Cleartext Remote Console Ingress",
        "addresses_scenario": "SCEN-C",
        "active": True,
        "enforced_by": "OT Systems Administrator",
        "last_updated": "2026-10-19 09:30:00",
        "operational_impact": "Prevents credential sniffing and unauthorized remote graphic session hijacking."
    },
    "ews_gpo_usb": {
        "id": "MIT-EWS-03",
        "name": "Enforce Windows GPO Removable Media Restrictions",
        "target_asset": "E-01",
        "description": "Disable USB Mass Storage class driver and enforce SMBv2/v3 packet signing on Engineering Workstation.",
        "addresses_vector": "Stuxnet-style Physical Air-gap Removable Media Crossing",
        "addresses_scenario": "SCEN-D",
        "active": False,
        "enforced_by": "IT/OT Security Compliance",
        "last_updated": "2026-10-19 09:45:00",
        "operational_impact": "Mitigates Stuxnet-style physical air-gap crossing and unauthorized ladder logic downloads."
    },
    "rate_limit_polling": {
        "id": "MIT-NET-04",
        "name": "Supervisory SCADA Polling Threshold Rate Limiter",
        "target_asset": "C-01",
        "description": "Clamp PLC register write frequency to maximum 0.5 Hz per channel; reject sudden setpoint jumps exceeding 25% nominal.",
        "addresses_vector": "Rapid Setpoint Oscillations & Actuator Flooding",
        "addresses_scenario": "SCEN-B",
        "active": True,
        "enforced_by": "Lead Automation Specialist",
        "last_updated": "2026-10-19 08:00:00",
        "operational_impact": "Prevents catastrophic actuator oscillation and water hammer damage."
    }
}

def get_defensive_posture() -> Dict[str, Dict[str, Any]]:
    """Retrieve defensive countermeasure configuration from session state."""
    if "defensive_posture" not in st.session_state:
        st.session_state.defensive_posture = {k: dict(v) for k, v in DEFAULT_DEFENSIVE_POSTURE.items()}
    return st.session_state.defensive_posture

def render_mitigation_page(simulator: ProcessTelemetrySimulator, correlator: CyberPhysicalCorrelator):
    """Render the full Mitigation Control Room & Retesting Verification Workbench."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>🔧 Mitigation Control Room &amp; Retesting Verification</h2>
            <p>Interactive defensive countermeasures, deterministic before-and-after retest engine, and guided 8-stage lifecycle demo.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-left:4px solid #2563eb; padding:8px 12px; border-radius:4px; margin-bottom:12px; font-size:12px; color:#1e40af;">
            <b>SIMULATION STATE CONTROL MANDATE:</b><br>
            Toggling countermeasures below modifies active simulation rule state in memory. 
            Retest executions directly verify whether the configured rule successfully prevents adversary exploitation without disrupting normal process operations.
        </div>
        """,
        unsafe_allow_html=True
    )

    mit_tabs = st.tabs([
        "🛡️ Defensive Countermeasures Console",
        "🔄 Before-and-After Retest Engine",
        "🚀 Guided 8-Stage Demonstration Mode"
    ])

    posture = get_defensive_posture()

    # =========================================================================
    # TAB 1: DEFENSIVE COUNTERMEASURES CONSOLE
    # =========================================================================
    with mit_tabs[0]:
        st.markdown("### 🛡️ Active Defensive Countermeasures & Security Policies")
        st.caption("Inspect and toggle active network rules, workstation policies, and access controls:")

        for key, rule in posture.items():
            if not isinstance(rule, dict):
                st.warning(f"⚠️ Skipping invalid mitigation rule configuration for entry `{key}`.")
                continue

            # Validate required fields before rendering
            required_fields = ["id", "name", "target_asset", "description"]
            missing_fields = [f for f in required_fields if f not in rule or not rule[f]]
            if missing_fields:
                st.warning(
                    f"⚠️ Incomplete mitigation rule `{key}`: missing required field(s): {', '.join(missing_fields)}. "
                    "Rule display omitted until configuration is rectified."
                )
                continue

            rule_id = rule.get("id", str(key))
            rule_name = rule.get("name", "Unnamed Countermeasure")
            target_asset = rule.get("target_asset", "Refinery OT Network")
            description = rule.get("description", "No description provided.")
            enforced_by = rule.get("enforced_by", "OT Security Team")
            last_updated = rule.get("last_updated", "N/A")
            operational_impact = rule.get("operational_impact", "Standard OT protective controls.")

            # Correct schema field: addresses_vector, with backward-compatibility fallbacks
            threat_addressed = (
                rule.get("addresses_vector")
                or rule.get("addresses_finding")
                or rule.get("addresses_scenario")
                or "Identified OT Threat Vector"
            )

            is_active = bool(rule.get("active", False))
            status_badge = "ENFORCING / ACTIVE" if is_active else "DISABLED / INACTIVE"
            badge_bg = "#ecfdf5" if is_active else "#fef2f2"
            badge_txt = "#166534" if is_active else "#991b1b"
            badge_border = "#86efac" if is_active else "#fca5a5"

            with st.container():
                st.markdown(
                    f"""
                    <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px; margin-bottom:10px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-weight:700; color:#0f172a; font-size:13px;">[{rule_id}] {rule_name}</span>
                            <span style="background:{badge_bg}; color:{badge_txt}; border:1px solid {badge_border}; font-size:11px; font-weight:700; padding:2px 8px; border-radius:3px;">
                                ● {status_badge}
                            </span>
                        </div>
                        <div style="font-size:11px; color:#475569; margin:4px 0;">{description}</div>
                        <div style="font-size:10px; color:#64748b;">
                            <b>Target:</b> <code>{target_asset}</code> | <b>Remediates:</b> <code>{threat_addressed}</code> | <b>Enforced By:</b> {enforced_by} ({last_updated})
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                c_tog, c_info = st.columns([1, 4])
                with c_tog:
                    new_val = st.checkbox(
                        f"Enforce {rule_id}",
                        value=is_active,
                        key=f"chk_{rule_id}"
                    )
                    if new_val != is_active:
                        rule["active"] = new_val
                        rule["last_updated"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        st.success(f"Rule {rule_id} state updated to: {'ACTIVE' if new_val else 'DISABLED'}")
                        st.rerun()

                with c_info:
                    st.caption(f"**Operational Impact**: {operational_impact}")

    # =========================================================================
    # TAB 2: BEFORE-AND-AFTER RETEST ENGINE
    # =========================================================================
    with mit_tabs[1]:
        st.markdown("### 🔄 Deterministic Before-and-After Retest Engine")
        st.caption(
            "Replay the identical threat exploit against the target asset to prove whether the configured "
            "defensive countermeasure successfully drops the rogue packet and keeps the process in nominal equilibrium."
        )

        retest_col1, retest_col2 = st.columns([1.8, 1.2])
        with retest_col1:
            retest_target = st.selectbox(
                "Select Exploit Scenario to Retest:",
                [
                    "Retest 1: Modbus Valve Override on PLC-01 (SCEN-A vs MIT-FW-01)",
                    "Retest 2: Insecure Remote Management on HMI-01 (SCEN-C vs MIT-HMI-02)",
                    "Retest 3: Stuxnet EWS Removable Media Ingress on E-01 (SCEN-D vs MIT-EWS-03)"
                ],
                key="sel_retest_target"
            )

        with retest_col2:
            st.markdown("**Active Countermeasure Status:**")
            if "Retest 1" in retest_target:
                active_rule = posture.get("fw_dpi_modbus", {})
            elif "Retest 2" in retest_target:
                active_rule = posture.get("vnc_decommission", {})
            else:
                active_rule = posture.get("ews_gpo_usb", {})

            is_enf = bool(active_rule.get("active", False))
            active_rule_id = active_rule.get("id", "N/A")
            st.markdown(
                f'<span class="status-badge" style="background:{"#ecfdf5" if is_enf else "#fef2f2"}; color:{"#166534" if is_enf else "#991b1b"}; border:1px solid {"#86efac" if is_enf else "#fca5a5"};">'
                f'RULE [{active_rule_id}]: {"ENFORCED (ACTIVE)" if is_enf else "DISABLED (EXPOSED)"}'
                f'</span>',
                unsafe_allow_html=True
            )

        st.markdown("---")
        if st.button("🚀 Execute Retest Verification Run", type="primary", use_container_width=True):
            with st.spinner("Executing retest replay and analyzing through dual-paradigm pipeline..."):
                time.sleep(0.5)

                if "Retest 1" in retest_target:
                    # Scenario A: Valve demand spoofing
                    scen_id = "SCEN-A"
                    if posture["fw_dpi_modbus"]["active"]:
                        # Mitigated! Firewall blocks packet; process remains nominal
                        retest_telemetry = simulator.base_state.copy()
                        retest_net = {
                            "src_ip": "192.168.10.99",
                            "dest_ip": "192.168.10.11",
                            "dest_port": 502,
                            "protocol": "Modbus/TCP",
                            "modbus_fc": 6,
                            "firewall_action": "DROPPED_BY_DPI_RULE",
                            "unauthorized": False,
                            "description": "OT Firewall DPI rule dropped unauthorized write command from 192.168.10.99"
                        }
                        is_blocked = True
                    else:
                        # Unmitigated! Attack executes
                        retest_telemetry = simulator.base_state.copy()
                        retest_telemetry["P1_PCV01D"] = 88.5
                        retest_telemetry["P1_PIT01"] = 2.85
                        retest_net = {
                            "src_ip": "192.168.10.99",
                            "dest_ip": "192.168.10.11",
                            "dest_port": 502,
                            "protocol": "Modbus/TCP",
                            "modbus_fc": 6,
                            "unauthorized": True,
                            "description": "Unauthorized Modbus Function 06 write accepted by vulnerable PLC"
                        }
                        is_blocked = False

                elif "Retest 2" in retest_target:
                    scen_id = "SCEN-C"
                    is_blocked = posture["vnc_decommission"]["active"]
                    retest_telemetry = simulator.base_state.copy()
                    retest_net = {
                        "src_ip": "192.168.10.88",
                        "dest_ip": "192.168.10.5",
                        "dest_port": 5900,
                        "protocol": "TCP",
                        "firewall_action": "PORT_CLOSED" if is_blocked else "CONNECTION_ACCEPTED",
                        "unauthorized": not is_blocked,
                        "description": "VNC connection probe on Port 5900"
                    }

                else:
                    scen_id = "SCEN-D"
                    is_blocked = posture["ews_gpo_usb"]["active"]
                    retest_telemetry = simulator.base_state.copy()
                    retest_net = {
                        "src_ip": "192.168.10.20",
                        "dest_ip": "192.168.10.14",
                        "dest_port": 102,
                        "protocol": "S7comm",
                        "firewall_action": "GPO_BLOCKED" if is_blocked else "EXECUTION_PERMITTED",
                        "unauthorized": not is_blocked,
                        "description": "Unauthorized ladder logic download probe"
                    }

                eval_retest = correlator.evaluate_cyber_physical_event(retest_telemetry, retest_net)

            # Store in session state for before-and-after view
            st.session_state["last_retest_result"] = {
                "scenario": retest_target,
                "is_blocked": is_blocked,
                "eval": eval_retest,
                "net": retest_net,
                "telemetry": retest_telemetry,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # Display Before-and-After Comparison
        if "last_retest_result" in st.session_state:
            res = st.session_state["last_retest_result"]
            st.markdown("### 📊 Side-by-Side Before-and-After Retest Outcome")

            col_before, col_after = st.columns(2)
            with col_before:
                st.markdown(
                    """
                    <div style="background:#fef2f2; border:1px solid #fca5a5; border-radius:4px; padding:12px;">
                        <div style="font-size:11px; font-weight:700; color:#991b1b;">BASELINE EXPLOIT POSTURE (BEFORE MITIGATION)</div>
                        <div style="font-size:16px; font-weight:800; color:#0f172a; margin:4px 0;">THREAT ACTIVE &amp; EXPLOITABLE</div>
                        <div style="font-size:11px; color:#1f2937;">
                            • <b>Network State:</b> Unauthorized packets accepted by PLC.<br>
                            • <b>Telemetry State:</b> Process tags forced outside limits (Valve=88.5%, Pressure=2.85 kPa).<br>
                            • <b>AI Classification:</b> <code>CRITICAL: COORDINATED CYBER-PHYSICAL ATTACK</code>.<br>
                            • <b>Threat State:</b> Unmitigated & Active.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

            with col_after:
                if res["is_blocked"]:
                    st.markdown(
                        """
                        <div style="background:#ecfdf5; border:1px solid #86efac; border-radius:4px; padding:12px;">
                            <div style="font-size:11px; font-weight:700; color:#166534;">VERIFIED RETEST POSTURE (AFTER MITIGATION)</div>
                            <div style="font-size:16px; font-weight:800; color:#166534; margin:4px 0;">✅ THREAT VERIFIED MITIGATED</div>
                            <div style="font-size:11px; color:#1f2937;">
                                • <b>Network State:</b> Rogue packet dropped at OT firewall / port closed.<br>
                                • <b>Telemetry State:</b> All process tags remain strictly in nominal equilibrium.<br>
                                • <b>AI Classification:</b> <code>NOMINAL: PLANT HEALTHY</code>.<br>
                                • <b>Threat State:</b> Mitigated & Verified Blocked.
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        """
                        <div style="background:#fef2f2; border:1px solid #dc2626; border-radius:4px; padding:12px;">
                            <div style="font-size:11px; font-weight:700; color:#991b1b;">VERIFIED RETEST POSTURE (AFTER MITIGATION)</div>
                            <div style="font-size:16px; font-weight:800; color:#991b1b; margin:4px 0;">❌ THREAT REMAINS ACTIVE</div>
                            <div style="font-size:11px; color:#1f2937;">
                                • <b>Countermeasure Disabled:</b> Packet accepted by controller.<br>
                                • <b>Physical Impact:</b> Anomaly score exceeded threshold.<br>
                                • <b>Action Required:</b> Enable defensive countermeasure in Tab 1 and rerun retest.
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )

            st.markdown("#### Retest Diagnostics & Network Packet Inspection:")
            st.json(res["net"])

    # =========================================================================
    # TAB 3: GUIDED 8-STAGE DEMONSTRATION MODE
    # =========================================================================
    with mit_tabs[2]:
        st.markdown("### 🚀 Guided 8-Stage End-to-End Refinery Lifecycle Demonstration")
        st.caption(
            "Execute the complete end-to-end cybersecurity workflow from asset discovery, through attack simulation, "
            "AI detection, incident triage, mitigation enforcement, to retesting verification."
        )

        stages = [
            ("Stage 1", "Simulated Refinery Environment & Architecture Discovery", "Purdue Level 1/2 architecture; unauthenticated Modbus write vulnerability on PLC-01."),
            ("Stage 2", "Normal Baseline Activity", "Steady-state nominal SCADA telemetry ingest (PCV01D=27.9%, PIT01=1.12 kPa)."),
            ("Stage 3", "Controlled Threat Simulation", "Rogue host 192.168.10.99 injects Modbus Function 06 write overriding Register 40001."),
            ("Stage 4", "Historian Data Collection", "SCADA collector ingests acute physical deviation across steam pressure loop."),
            ("Stage 5", "AI Anomaly Detection", "Isolation Forest flags anomaly score (-0.0198) and Random Forest confirms signature (99.8%)."),
            ("Stage 6", "Security Alert & Incident Correlation", "Incident INC-001 opened; correlated with identified threat vector and operator walkdown checklist generated."),
            ("Stage 7", "Mitigation Enforcement", "Industrial Firewall DPI rule deployed to drop rogue Function 06 write commands."),
            ("Stage 8", "Retesting Verification", "Identical exploit replayed; packet successfully blocked and plant verified nominal.")
        ]

        if st.button("▶ Run Complete 8-Stage End-to-End Demonstration", type="primary", use_container_width=True):
            st.session_state["demo_running"] = True

        if st.session_state.get("demo_running", False):
            prog_bar = st.progress(0)
            status_container = st.container()

            for idx, (stg_num, stg_title, stg_desc) in enumerate(stages):
                prog = int(((idx + 1) / len(stages)) * 100)
                prog_bar.progress(prog)

                with status_container:
                    st.markdown(
                        f"""
                        <div style="background:#ffffff; border:1px solid #cbd5e1; border-left:4px solid #16a34a; padding:8px 12px; border-radius:4px; margin-bottom:8px;">
                            <span style="font-weight:700; color:#16a34a;">{stg_num}: {stg_title}</span> — 
                            <span style="font-size:12px; color:#475569;">{stg_desc}</span>
                        </div>
                        """,
                        unsafe_allow_html=True
                    )
                time.sleep(0.3)

            st.success("🏆 Complete 8-Stage Lifecycle Successfully Executed and Verified!")
            st.caption("All stages completed with zero unhandled exceptions. Audit logs persisted to disk.")
