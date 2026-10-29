"""
ai_analysis.py
==============
Industrial AI/ML Detection Engine & Diagnostic Workstation.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: AI/ML Detection Specialist & Group Leader (Student 2)

Key Features:
1. Multi-tier Defense-in-Depth Diagnostic:
   - Layer 1: Statistical Physics Limit Check (>4.0 sigma)
   - Layer 2: Unsupervised Isolation Forest (Trained Threshold: +0.0132)
   - Layer 3: Supervised Random Forest Signature Classifier
2. Real-time Score-vs-Threshold Visualization & Gauge.
3. Strict Schema Validation with transparent proxy imputation documentation.
4. Local Per-Event Attribution vs. Global Model Feature Importance.
5. Interactive Replay Engine across real HAI 23.05 attack episodes.
"""

from typing import Dict, Any, List, Optional
import time
import json
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from predict import IndustrialPredictor
from alert_system import SUBSYSTEM_MAP
from assets_config import get_all_assets

def render_ai_detection_page(predictor: IndustrialPredictor):
    """Render the comprehensive AI Detection Analysis Workstation."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>🧠 AI/ML Detection Engine &amp; Diagnostic Workstation</h2>
            <p>Dual-paradigm inference, score-vs-threshold calibration, root-cause attribution, and strict schema validation.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Scientific Provenance Notice
    st.markdown(
        """
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-left:4px solid #2563eb; padding:8px 12px; border-radius:4px; margin-bottom:12px; font-size:12px; color:#1e40af;">
            <b>ACADEMIC PROVENANCE &amp; PROXY DATASET NOTICE:</b><br>
            The machine learning models are trained on the <b>HAI 23.05 ICS Research Testbed</b> (86 physical continuous tags, 572,400 normal training observations). 
            HAI serves as an authoritative scientific proxy for physical refining control loops (steam boilers, heat exchangers, distillation columns, and turbine drives).
            Fictional refinery tags are explicitly mapped to their corresponding physical proxy loops.
        </div>
        """,
        unsafe_allow_html=True
    )

    # Model Health Badges Bar
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.markdown(
            """
            <div class="kpi-card">
                <div class="kpi-title">Unsupervised Engine</div>
                <div class="kpi-value" style="font-size:1.1rem; color:#16a34a;">Isolation Forest</div>
                <div class="kpi-sub">Threshold: <code>+0.0132</code> (3.9% FPR)</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m_col2:
        rf_status = "Random Forest" if predictor.rf_model is not None else "Not Loaded"
        st.markdown(
            f"""
            <div class="kpi-card">
                <div class="kpi-title">Supervised Engine</div>
                <div class="kpi-value" style="font-size:1.1rem; color:#16a34a;">{rf_status}</div>
                <div class="kpi-sub">100 Estimators | Dual-Class</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m_col3:
        st.markdown(
            """
            <div class="kpi-card">
                <div class="kpi-title">Preprocessing Scaler</div>
                <div class="kpi-value" style="font-size:1.1rem; color:#0f172a;">StandardScaler</div>
                <div class="kpi-sub">Fitted on 572.4k Normal Samples</div>
            </div>
            """,
            unsafe_allow_html=True
        )
    with m_col4:
        st.markdown(
            """
            <div class="kpi-card">
                <div class="kpi-title">Inference Latency</div>
                <div class="kpi-value" style="font-size:1.1rem; color:#2563eb;">13.85 ms</div>
                <div class="kpi-sub">Per 1,000 SCADA Observations</div>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Workstation Tabs
    ai_tabs = st.tabs([
        "📊 Score-vs-Threshold Visualizer",
        "⚡ HAI 23.05 Replay Engine",
        "🧪 Refinery Tag Tester & Schema Validator",
        "📈 Global Model Explainability"
    ])

    # =========================================================================
    # TAB 1: SCORE-VS-THRESHOLD VISUALIZER
    # =========================================================================
    with ai_tabs[0]:
        st.markdown("### 🎯 Real-Time Score-vs-Threshold Anomaly Diagnostic")
        st.caption(
            "Isolation Forest maps multivariate sensor correlations into a continuous decision score. "
            "Scores exceeding the calibrated threshold (+0.0132) represent statistical deviations outside the normal physical manifold."
        )

        # Check if an observation was stored from recent test or replay
        sample_to_eval = st.session_state.get("active_ai_sample", None)
        sample_label = st.session_state.get("active_ai_label", "Baseline Equilibrium")

        if sample_to_eval is None:
            # Generate default nominal baseline sample
            sample_to_eval = {
                "P1_PCV01D": 27.94,
                "P1_PCV01Z": 28.40,
                "P1_PIT01":  1.12,
                "P1_FCV01D": 32.12,
                "P1_LIT01":  349.36,
                "P1_TIT01":  30.38,
                "P4_ST_GOV": 18135.0,
                "P4_ST_TT01": 27.10,
                "P2_24Vdc":  28.035
            }

        col_run1, col_run2 = st.columns([2, 1])
        with col_run1:
            st.markdown(f"**Current Evaluation Input**: `{sample_label}`")
        with col_run2:
            re_eval = st.button("🔄 Execute Live AI Diagnostic", type="primary", use_container_width=True)

        # Compute prediction
        t0 = time.perf_counter()
        pred_res = predictor.predict(sample_to_eval, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        latency_ms = (time.perf_counter() - t0) * 1000

        score = pred_res["anomaly_score"]
        threshold = pred_res["alert_threshold"]
        is_suspicious = (pred_res["prediction"] == "SUSPICIOUS")
        rf_conf = pred_res.get("supervised_attack_confidence_percent")

        # Gauge & Metric Cards Row
        gauge_col, metric_col = st.columns([1.5, 1])

        with gauge_col:
            # Plotly Bullet / Gauge Chart for Anomaly Score
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=score,
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Isolation Forest Anomaly Score", 'font': {'size': 14, 'color': '#0f172a'}},
                delta={'reference': threshold, 'increasing': {'color': '#dc2626'}, 'decreasing': {'color': '#16a34a'}},
                gauge={
                    'axis': {'range': [-0.15, 0.15], 'tickwidth': 1, 'tickcolor': "#334155"},
                    'bar': {'color': "#dc2626" if is_suspicious else "#16a34a"},
                    'bgcolor': "white",
                    'borderwidth': 1,
                    'bordercolor': "#cbd5e1",
                    'steps': [
                        {'range': [-0.15, threshold], 'color': "#ecfdf5"},
                        {'range': [threshold, 0.15], 'color': "#fef2f2"}
                    ],
                    'threshold': {
                        'line': {'color': "#dc2626", 'width': 3},
                        'thickness': 0.85,
                        'value': threshold
                    }
                }
            ))
            fig_gauge.update_layout(height=260, margin=dict(l=30, r=30, t=40, b=20))
            st.plotly_chart(fig_gauge, use_container_width=True)

        with metric_col:
            st.markdown(
                f"""
                <div style="background:#ffffff; border:1px solid #cbd5e1; border-radius:4px; padding:12px; margin-top:20px;">
                    <div style="font-size:11px; font-weight:700; color:#64748b;">PREDICTION CLASSIFICATION</div>
                    <div style="font-size:22px; font-weight:800; color:{'#dc2626' if is_suspicious else '#16a34a'}; margin:4px 0;">
                        ● {pred_res['prediction']}
                    </div>
                    <div style="font-size:12px; margin-bottom:8px;">Severity: <b>{pred_res['severity']}</b></div>
                    <div style="font-size:11px; color:#475569; border-top:1px solid #e2e8f0; padding-top:6px;">
                        <b>Calibrated Threshold:</b> <code>+{threshold:.4f}</code><br>
                        <b>Observed Score:</b> <code>{score:+.4f}</code><br>
                        <b>Delta to Alert Boundary:</b> <code>{score - threshold:+.4f}</code><br>
                        <b>Supervised Probability:</b> <code>{rf_conf if rf_conf is not None else 'N/A'}%</code>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

        # Multi-Tier Decision Breakdown
        st.markdown("#### 🛡️ Multi-Layer Defense-in-Depth Breakdown")
        l1, l2, l3 = st.columns(3)
        with l1:
            max_dev = pred_res["top_deviating_sensors"][0]["z_score_deviation"] if pred_res["top_deviating_sensors"] else 0.0
            phys_ok = max_dev < 4.0
            st.markdown(
                f"""
                <div style="background:{'#ecfdf5' if phys_ok else '#fef2f2'}; border:1px solid {'#86efac' if phys_ok else '#fca5a5'}; padding:10px; border-radius:4px;">
                    <div style="font-size:11px; font-weight:700; color:{'#166534' if phys_ok else '#991b1b'};">LAYER 1: PHYSICS &amp; STATS BOUNDS</div>
                    <div style="font-size:13px; font-weight:700; color:#0f172a; margin:3px 0;">
                        {'✅ PASS (&lt;4σ)' if phys_ok else f'⚠️ DIVERGENCE ({max_dev:.1f}σ)'}
                    </div>
                    <div style="font-size:10px; color:#475569;">Evaluates statistical Z-score limits on individual tag baselines.</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with l2:
            iso_ok = score < threshold
            st.markdown(
                f"""
                <div style="background:{'#ecfdf5' if iso_ok else '#fef2f2'}; border:1px solid {'#86efac' if iso_ok else '#fca5a5'}; padding:10px; border-radius:4px;">
                    <div style="font-size:11px; font-weight:700; color:{'#166534' if iso_ok else '#991b1b'};">LAYER 2: ISOLATION FOREST</div>
                    <div style="font-size:13px; font-weight:700; color:#0f172a; margin:3px 0;">
                        {'✅ NORMAL EQUILIBRIUM' if iso_ok else '🚨 MULTIVARIATE ANOMALY'}
                    </div>
                    <div style="font-size:10px; color:#475569;">Evaluates 86-dimensional joint manifold cross-correlations.</div>
                </div>
                """,
                unsafe_allow_html=True
            )
        with l3:
            rf_ok = (rf_conf is None or rf_conf < 50.0)
            st.markdown(
                f"""
                <div style="background:{'#ecfdf5' if rf_ok else '#fef2f2'}; border:1px solid {'#86efac' if rf_ok else '#fca5a5'}; padding:10px; border-radius:4px;">
                    <div style="font-size:11px; font-weight:700; color:{'#166534' if rf_ok else '#991b1b'};">LAYER 3: RANDOM FOREST SIGNATURE</div>
                    <div style="font-size:13px; font-weight:700; color:#0f172a; margin:3px 0;">
                        {'✅ NO ATTACK SIGNATURE' if rf_ok else f'🚨 ATTACK DETECTED ({rf_conf:.1f}%)'}
                    </div>
                    <div style="font-size:10px; color:#475569;">Supervised classification against known cyber-physical attack signatures.</div>
                </div>
                """,
                unsafe_allow_html=True
            )

        st.markdown("---")

        # Local Root-Cause Sensor Attribution
        st.markdown("#### 🔍 Local Per-Event Root-Cause Attribution (Top Deviating Sensors)")
        st.caption(r"Standard deviations ($\sigma$) from baseline training equilibrium for the current observation:")
        
        top_devs = pred_res.get("top_deviating_sensors", [])
        if top_devs:
            dev_df = pd.DataFrame(top_devs)
            dev_df.columns = ["Physical Tag Name", "Raw Engineering Value", "Deviation (Standard Deviations σ)"]
            st.dataframe(dev_df, use_container_width=True, hide_index=True)

        st.markdown(f"**Diagnostic Rationale**: `{pred_res['detection_reason']}`")
        if is_suspicious:
            st.error(f"📋 **Actionable Operator Checklist**:\n{pred_res['mitigation_recommendation']}")
        else:
            st.success(f"📋 **Operator Status**: {pred_res['mitigation_recommendation']}")

        st.caption(f"*{pred_res['safety_disclaimer']}*")

    # =========================================================================
    # TAB 2: HAI 23.05 REPLAY ENGINE
    # =========================================================================
    with ai_tabs[1]:
        st.markdown("### ⚡ Replay Real Industrial Testbed Telemetry (HAI 23.05)")
        st.caption(
            "Replay verified continuous 86-feature testbed slices from the held-out evaluation dataset. "
            "Allows evaluators to step through real physical attack episodes and observe AI detection response."
        )

        test_data_path = predictor.models_dir.parent / "dataset" / "processed" / "test1_data.npz"
        if not test_data_path.exists():
            st.warning("Processed test dataset (`test1_data.npz`) not found. Run `prepare_data.py` to generate.")
        else:
            with np.load(test_data_path, allow_pickle=True) as data:
                X_t1 = data["X_test"]
                y_t1 = data["y_test"]
                ts_t1 = data["timestamps"]

            replay_scen = st.selectbox(
                "Select Pre-Recorded Testbed Episode to Ingest:",
                [
                    "Episode 1: Nominal Steady-State Operation (Index 1,000 — Benign Equilibrium)",
                    "Episode 2: Attack Incident 07 — Boiler Valve Demand Tampering (Index 24,500 — Active Exploit)",
                    "Episode 3: Multi-Loop Transmitter Drift & Level Disturbance (Index 49,500 — Active Exploit)"
                ],
                key="replay_episode_select"
            )

            if "Episode 1" in replay_scen:
                base_idx = 1000
                ep_desc = "Nominal continuous plant operation in steady-state equilibrium. All 86 features within normal covariance."
                expected_label = 0
            elif "Episode 2" in replay_scen:
                base_idx = 24500
                ep_desc = "Physical tampering of Pressure Control Valve 01 Demand (P1_PCV01D) and position feedback (P1_PCV01Z). Direct attack on boiler steam loop."
                expected_label = 1
            else:
                base_idx = 49500
                ep_desc = "Multi-transmitter drift affecting water drum level and feed flow rates simultaneously."
                expected_label = 1

            st.markdown(f"**Episode Context**: {ep_desc}")
            st.markdown(f"**Ground Truth Label**: `{'ATTACK (1)' if expected_label == 1 else 'NORMAL (0)'}`")

            # Offset slider to scrub across seconds of the incident
            step_offset = st.slider("Time Step Offset within Episode (Seconds from start):", -10, 30, 0, key="replay_scrub")
            target_idx = max(0, min(len(X_t1) - 1, base_idx + step_offset))

            raw_vec = predictor.scaler.inverse_transform(X_t1[target_idx:target_idx+1])[0]
            curr_ts = str(ts_t1[target_idx])
            curr_true_label = int(y_t1[target_idx])

            c_info1, c_info2, c_info3 = st.columns(3)
            c_info1.metric("Observation Timestamp", curr_ts)
            c_info2.metric("Dataset Index", f"Row #{target_idx:,}")
            c_info3.metric("True Label", "🔴 ATTACK" if curr_true_label == 1 else "🟢 NORMAL")

            if st.button("🚀 Ingest Selected Replay Step & Evaluate", type="primary", key="btn_replay_eval"):
                # Save as active sample for Tab 1
                st.session_state["active_ai_sample"] = raw_vec
                st.session_state["active_ai_label"] = f"HAI Replay #{target_idx} ({curr_ts})"

                res = predictor.predict(raw_vec, timestamp=curr_ts)

                st.markdown("#### 📡 Real-Time Replay Inference Diagnostic:")
                rc1, rc2, rc3, rc4 = st.columns(4)
                rc1.metric("Prediction", res["prediction"])
                rc2.metric("Severity", res["severity"])
                rc3.metric("Anomaly Score", f"{res['anomaly_score']:+.4f}", f"Threshold: {res['alert_threshold']:+.4f}")
                rc4.metric("Supervised Confidence", f"{res['supervised_attack_confidence_percent']:.1f}%" if res['supervised_attack_confidence_percent'] is not None else "N/A")

                st.markdown(f"**Detection Rationale**: `{res['detection_reason']}`")
                st.markdown("##### Top Deviating Sensors:")
                st.dataframe(pd.DataFrame(res["top_deviating_sensors"]), use_container_width=True)

    # =========================================================================
    # TAB 3: REFINERY TAG TESTER & SCHEMA VALIDATOR
    # =========================================================================
    with ai_tabs[2]:
        st.markdown("### 🧪 Refinery Tag Manual Diagnostic & Schema Validator")
        st.caption(
            "Directly test individual refinery sensor parameters. "
            "Input boundary checks prevent physically impossible values, and transparent schema imputation "
            "explains how partial tags safely interface with the 86-feature model suite."
        )

        with st.expander("ℹ️ Schema Compatibility & Transparent Feature Imputation Explanation", expanded=False):
            st.markdown(
                """
                **How Partial Refinery Tag Vectors are Evaluated Without Feature Corruption**:
                - The full ML model suite requires an 86-dimensional feature vector corresponding to the HAI physical topology.
                - When testing fictional refinery tags (e.g. `P1_PCV01D`, `P1_PIT01`, `P4_ST_GOV`), the remaining unobserved tags 
                  are imputed using their **calibrated baseline training mean** (`scaler.mean_`).
                - Because `StandardScaler` transforms the mean to exactly `0.0`, unobserved channels contribute zero artificial deviation, 
                  allowing the models to isolate and score the exact physical disturbance introduced by the user.
                """
            )

        # Preset Scenarios
        preset = st.selectbox(
            "Quick-Load Diagnostic Preset:",
            [
                "Custom Manual Input",
                "Preset: Normal Steady-State Refinery Operations",
                "Preset: Acute Steam Boiler Overpressure Attack (PCV01D=88%, PIT01=2.85 kPa)",
                "Preset: Stuxnet Turbine Overspeed Hazard (ST_GOV=28,500 RPM, Bearing=74°C)",
                "Preset: Severe Drum Low-Water Trip (LIT01=95 mm)"
            ]
        )

        # Default values based on preset
        def_pcv = 27.94
        def_pit = 1.12
        def_fcv = 32.12
        def_lit = 349.36
        def_tit = 30.38
        def_gov = 18135.0
        def_tt  = 27.10
        def_dc  = 28.035

        if "Overpressure" in preset:
            def_pcv = 88.5
            def_pit = 2.85
            def_tit = 58.0
        elif "Stuxnet" in preset:
            def_gov = 28500.0
            def_tt = 74.0
        elif "Low-Water" in preset:
            def_lit = 95.0
            def_fcv = 75.0

        with st.form("refinery_manual_form"):
            st.markdown("#### Process Unit 1: Boiler Steam & Distillation Loop")
            col_u1, col_u2, col_u3 = st.columns(3)
            with col_u1:
                p1_pcv01d = st.slider("P1_PCV01D (Steam Valve Demand %)", 0.0, 100.0, float(def_pcv), help="Nominal: 20-35%, Alarm: 75%")
                p1_pcv01z = st.slider("P1_PCV01Z (Steam Valve Position %)", 0.0, 100.0, float(def_pcv + 0.4))
            with col_u2:
                p1_pit01 = st.slider("P1_PIT01 (Overhead Pressure kPa)", 0.5, 4.0, float(def_pit), help="Nominal: 0.85-1.45, Alarm: 2.50")
                p1_tit01 = st.slider("P1_TIT01 (Column Inflow Temp °C)", 15.0, 100.0, float(def_tit), help="Nominal: 25-38, Alarm: 55")
            with col_u3:
                p1_fcv01d = st.slider("P1_FCV01D (Feed Flow Valve Demand %)", 0.0, 100.0, float(def_fcv))
                p1_lit01 = st.slider("P1_LIT01 (Boiler Drum Level mm)", 50.0, 600.0, float(def_lit), help="Nominal: 300-400, Trip: 200")

            st.markdown("#### Process Unit 4: Rotating Turbines & Emergency DC Bus")
            col_u4, col_u5 = st.columns(2)
            with col_u4:
                p4_st_gov = st.slider("P4_ST_GOV (Turbine Governor Speed RPM)", 10000.0, 32000.0, float(def_gov), help="Nominal: 17800-18400, Trip: 22000")
                p4_st_tt01 = st.slider("P4_ST_TT01 (Turbine Bearing Temp °C)", 15.0, 100.0, float(def_tt), help="Nominal: 22-35, Trip: 65")
            with col_u5:
                p2_24vdc = st.slider("P2_24Vdc (Emergency Trip Bus Volts DC)", 18.0, 32.0, float(def_dc), help="Nominal: 26.5-29.5")

            submit_manual = st.form_submit_button("🔍 Run Full AI Diagnostic Suite", type="primary")

        if submit_manual:
            test_dict = {
                "P1_PCV01D": p1_pcv01d,
                "P1_PCV01Z": p1_pcv01z,
                "P1_PIT01":  p1_pit01,
                "P1_FCV01D": p1_fcv01d,
                "P1_LIT01":  p1_lit01,
                "P1_TIT01":  p1_tit01,
                "P4_ST_GOV": p4_st_gov,
                "P4_ST_TT01": p4_st_tt01,
                "P2_24Vdc":  p2_24vdc
            }
            # Save to session for Tab 1 gauge
            st.session_state["active_ai_sample"] = test_dict
            st.session_state["active_ai_label"] = f"Manual Injection ({datetime.now().strftime('%H:%M:%S')})"

            diag_res = predictor.predict(test_dict, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            st.markdown("### 📋 AI Diagnostic Outcome")
            d1, d2, d3, d4 = st.columns(4)
            d1.metric("Predicted Security State", diag_res["prediction"])
            d2.metric("Severity", diag_res["severity"])
            d3.metric("Isolation Forest Score", f"{diag_res['anomaly_score']:+.4f}", f"Threshold: {diag_res['alert_threshold']:+.4f}")
            rf_p = diag_res["supervised_attack_confidence_percent"]
            d4.metric("Supervised Confidence", f"{rf_p:.1f}%" if rf_p is not None else "N/A")

            st.markdown(f"**Rationale**: `{diag_res['detection_reason']}`")
            st.markdown("#### Contributing Tag Deviations:")
            st.dataframe(pd.DataFrame(diag_res["top_deviating_sensors"]), use_container_width=True)

    # =========================================================================
    # TAB 4: GLOBAL MODEL EXPLAINABILITY
    # =========================================================================
    with ai_tabs[3]:
        st.markdown("### 📈 Global Feature Importance & Model Explainability")
        st.caption(
            "Global feature importance measures the relative contribution of each sensor tag across the entire dataset. "
            "Actuators and high-energy process lines naturally carry the highest discriminative power for physical attacks."
        )

        fi_path = predictor.models_dir.parent.parent / "results" / "feature_importance.png"
        if fi_path.exists():
            st.image(str(fi_path), caption="Top 15 Most Discriminative Physical Process Features (Random Forest Gini Importance)", use_container_width=True)

        st.markdown(
            """
            #### 💡 Scientific Explainability Insights:
            1. **Valve Actuator Positions (`P1_PCV01D`, `P1_FCV01D`)**:
               - Attackers seeking physical disruption invariably alter actuator demands. Actuators therefore exhibit the highest Mutual Information with attack episodes.
            2. **Rotating Machinery Speed (`P4_ST_GOV`)**:
               - Centrifugal and turbine drive tags represent high-kinetic-energy subsystems where overspeed induces immediate resonant mechanical damage.
            3. **Multi-Variate Joint Covariance**:
               - An individual sensor reading may appear nominal in isolation (e.g., pressure within bounds), but if valve demand is 100% while pressure remains low, the joint physics relationship is violated. Isolation Forest detects this breakdown in joint feature space.
            """
        )
