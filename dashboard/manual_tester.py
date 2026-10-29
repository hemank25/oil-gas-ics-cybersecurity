"""
manual_tester.py
================
Manual Telemetry Tester & Physics Validation Interface.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: SCADA Test Engineer & Machine Learning Specialist

Features:
- Custom sensor/actuator measurement input with rigorous engineering bounds
- Transparent dual-paradigm inference execution
- Explicit explanation of proxy imputation and statistical physics limit checking
- Input validation preventing non-physical or out-of-range parameters
"""

from typing import Dict, Any, List
import pandas as pd
import streamlit as st
from datetime import datetime

from assets_config import get_all_assets, get_asset
from predict import IndustrialPredictor

def render_manual_tester_page(predictor: IndustrialPredictor):
    """Render the Manual Telemetry Tester page."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>🧪 Manual Telemetry Tester &amp; Physics Validation</h2>
            <p>Interactive telemetry injection interface with schema validation, operating limits, and live dual-paradigm inference.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div style="background:#eff6ff; border:1px solid #bfdbfe; border-left:4px solid #2563eb; padding:8px 12px; border-radius:4px; margin-bottom:12px; font-size:12px; color:#1e40af;">
            <b>TRANSPARENT INFERENCE ARCHITECTURE NOTICE:</b><br>
            The machine learning models operate on an 86-dimensional continuous sensor manifold.
            When you enter specific refinery measurements below, missing continuous tags are imputed at their <b>standardized baseline means (0.0 z-score)</b>.
            This ensures zero data leakage, preserves physical manifold correlation, and tests model sensitivity directly on the chosen parameters.
        </div>
        """,
        unsafe_allow_html=True
    )

    assets = get_all_assets()
    process_unit_ids = [k for k in assets if k.startswith("U-")]

    # Asset selector
    selected_unit_id = st.selectbox(
        "Select Target Process Unit to Test:",
        process_unit_ids,
        format_func=lambda x: f"[{x}] {assets[x]['name']}",
        key="manual_test_unit_select"
    )

    unit = assets[selected_unit_id]
    tags = unit.get("tags", [])

    if not tags:
        st.info("No field transmitters configured for manual testing on this asset.")
        return

    st.markdown(f"#### ⚙️ Configure Telemetry Tags for `{unit['id']}` ({unit['short_name']})")
    st.caption("Adjust values below. Values beyond alarm limits will trigger physics rule checks and anomaly scores:")

    # Form inputs
    user_inputs = {}
    cols = st.columns(min(len(tags), 3))

    for idx, t in enumerate(tags):
        col = cols[idx % len(cols)]
        with col:
            val = st.number_input(
                f"{t['tag']} — {t['name']} ({t['unit']})",
                min_value=float(min(0.0, t['alarm_low'] - 10.0)),
                max_value=float(t['alarm_high'] * 1.5),
                value=float(t['nominal_val']),
                step=0.1 if t['nominal_val'] < 100 else 1.0,
                key=f"input_{t['tag']}"
            )
            user_inputs[t["tag"]] = val
            st.caption(f"Nominal: `{t['nominal_val']} {t['unit']}` | Alarm Limits: `[{t['alarm_low']} - {t['alarm_high']}]`")

    st.markdown("---")

    col_btn, col_info = st.columns([1, 2])
    with col_btn:
        submit = st.button("🔬 Submit Telemetry for Analysis", type="primary", use_container_width=True, key="submit_manual_test")

    with col_info:
        st.caption("Submitting executes scaling, Isolation Forest score evaluation, and Random Forest signature verification.")

    if submit:
        # Validate against safe operating limits
        out_of_bounds = []
        for t in tags:
            tag_name = t["tag"]
            val = user_inputs[tag_name]
            if val < t["alarm_low"] or val > t["alarm_high"]:
                out_of_bounds.append((t, val))

        with st.spinner("Executing inference pipeline across 86-dimensional manifold..."):
            result = predictor.predict(user_inputs, timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

        st.markdown("### 📡 Inference Diagnostic Results")

        res_col1, res_col2, res_col3, res_col4 = st.columns(4)
        is_anom = (result["prediction"] == "SUSPICIOUS")
        res_col1.metric("Detection Verdict", result["prediction"], delta="Anomalous" if is_anom else "Nominal", delta_color="inverse" if is_anom else "normal")
        res_col2.metric("Severity", result["severity"])
        res_col3.metric("Anomaly Score", f"{result['anomaly_score']:+.4f}", f"Threshold: {result['alert_threshold']:+.4f}")
        res_col4.metric("Supervised Confidence", f"{result.get('supervised_attack_confidence_percent', 0.0):.1f}%")

        if is_anom:
            st.error(f"🚨 **Detection Rationale**: {result['detection_reason']}")
        else:
            st.success(f"✅ **Detection Rationale**: {result['detection_reason']}")

        # Physics Limit Cross-Check
        if out_of_bounds:
            st.warning("⚠️ **Statistical & Physics Threshold Violations Detected:**")
            for t, val in out_of_bounds:
                st.markdown(f"- **{t['tag']}** ({t['name']}): Value `{val} {t['unit']}` breached limit (Range: `{t['alarm_low']} - {t['alarm_high']}`)")

        # Deviating Sensors Table
        st.markdown("#### 🔍 Root-Cause Attribution (Top Divergent Telemetry Tags)")
        devs = result.get("top_deviating_sensors", [])
        if devs:
            st.dataframe(pd.DataFrame(devs), use_container_width=True)

        st.markdown(f"> **Remediation Recommendation**: {result['mitigation_recommendation']}")
