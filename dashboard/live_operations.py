"""
live_operations.py
==================
Industrial Live Operations & Telemetry Trend Station for MUJ Demo Refinery.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: SCADA/HMI Interface Designer & OT Operations Engineer

Features:
- Multi-pen strip chart trend plots with engineering units (Plotly)
- Normal operating bands and trip limits (ISA-18.2 Alarm standards)
- Interactive simulation playback controls (Step, Pause, Reset)
- Controller watchdog & sensor loop diagnostics
"""

from typing import Dict, Any, List
import pandas as pd
import numpy as np
import plotly.graph_objects as go
import streamlit as st

from assets_config import ASSET_REGISTRY, get_asset, get_all_assets
from process_simulator import ProcessTelemetrySimulator

def render_live_operations_page(simulator: ProcessTelemetrySimulator):
    """Render the full Live Operations and Process Telemetry page."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>⚡ Live Operations &amp; SCADA Process Monitoring</h2>
            <p>Real-time physical process telemetry, multi-pen trend analysis, nominal operating bands, and sensor loop diagnostics.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Simulation control state initialization
    if "sim_running" not in st.session_state:
        st.session_state.sim_running = True
    if "sim_window_seconds" not in st.session_state:
        st.session_state.sim_window_seconds = 60
    if "sim_time_series" not in st.session_state:
        st.session_state.sim_time_series = simulator.generate_time_series(duration_steps=60)

    # Top Control Bar
    ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns([1.5, 1.5, 1.5, 1.5])
    
    with ctrl_col1:
        # Asset selector
        assets = get_all_assets()
        process_unit_ids = [k for k in assets if k.startswith("U-")]
        selected_unit_id = st.selectbox(
            "Monitored Process Unit:",
            process_unit_ids,
            format_func=lambda x: f"[{x}] {assets[x]['short_name']}",
            key="ops_unit_select"
        )
        unit = assets[selected_unit_id]

    with ctrl_col2:
        # Time Window selector
        time_window = st.selectbox(
            "Historical Time Window:",
            [30, 60, 120, 300],
            index=1,
            format_func=lambda x: f"{x} Seconds Strip-Chart",
            key="ops_time_window"
        )
        if time_window != st.session_state.sim_window_seconds:
            st.session_state.sim_window_seconds = time_window
            st.session_state.sim_time_series = simulator.generate_time_series(duration_steps=time_window)

    with ctrl_col3:
        st.markdown("**Simulation Control**")
        b1, b2 = st.columns(2)
        with b1:
            if st.button("▶ Step +1s", use_container_width=True, key="step_sim"):
                # Append one step and maintain window size
                new_step = simulator.generate_single_step()
                new_step["timestamp"] = pd.Timestamp.now().strftime("%H:%M:%S")
                df = st.session_state.sim_time_series
                df = pd.concat([df, pd.DataFrame([new_step])], ignore_index=True)
                if len(df) > st.session_state.sim_window_seconds:
                    df = df.iloc[-st.session_state.sim_window_seconds:]
                st.session_state.sim_time_series = df
                st.rerun()
        with b2:
            if st.button("🔄 Reset", use_container_width=True, key="reset_sim"):
                simulator.clear_overrides()
                st.session_state.sim_time_series = simulator.generate_time_series(duration_steps=st.session_state.sim_window_seconds)
                st.success("Nominal baseline restored.")
                st.rerun()

    with ctrl_col4:
        st.markdown("**Controller Status**")
        ctrl_id = unit["controller_id"]
        status = simulator.controller_comms_status.get(ctrl_id, "HEALTHY")
        if status == "HEALTHY":
            st.markdown(
                f'<div style="background:#ecfdf5; color:#166534; padding:6px 10px; border-radius:4px; border:1px solid #86efac; font-weight:700; font-size:12px;">'
                f'● {ctrl_id}: COMMS NORMAL'
                f'</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f'<div style="background:#fef2f2; color:#991b1b; padding:6px 10px; border-radius:4px; border:1px solid #fca5a5; font-weight:700; font-size:12px;">'
                f'■ {ctrl_id}: {status}'
                f'</div>',
                unsafe_allow_html=True
            )

    st.markdown("---")

    # =========================================================================
    # MULTI-PEN TREND CHART WITH NOMINAL OPERATING BANDS
    # =========================================================================
    tags = unit.get("tags", [])
    if not tags:
        st.info("No field tags configured on this supervisory asset.")
        return

    # Tag selector for plotting
    tag_options = {t["tag"]: f"{t['tag']} - {t['name']} ({t['unit']})" for t in tags}
    selected_tags = st.multiselect(
        "Select Process Variables to Trend (Multi-Pen Overlay):",
        options=list(tag_options.keys()),
        default=[tags[0]["tag"]] if len(tags) > 0 else [],
        format_func=lambda x: tag_options.get(x, x),
        key="ops_tag_select"
    )

    if selected_tags:
        df = st.session_state.sim_time_series
        fig = go.Figure()

        colors = ["#0284c7", "#d97706", "#16a34a", "#8b5cf6", "#ec4899"]

        for i, tag_name in enumerate(selected_tags):
            tag_info = next((t for t in tags if t["tag"] == tag_name), None)
            if not tag_info or tag_name not in df.columns:
                continue

            pen_color = colors[i % len(colors)]
            y_vals = df[tag_name]
            x_vals = df["timestamp"]

            # Main Telemetry Trace
            fig.add_trace(go.Scatter(
                x=x_vals,
                y=y_vals,
                mode="lines+markers",
                name=f"{tag_name} ({tag_info['unit']})",
                line=dict(color=pen_color, width=2.5),
                marker=dict(size=4)
            ))

            # If only 1 or 2 tags selected, show safe operating band and trip limits
            if len(selected_tags) <= 2:
                # High Trip Limit Line
                fig.add_hline(
                    y=tag_info["alarm_high"],
                    line_dash="dash",
                    line_color="#dc2626",
                    line_width=1.5,
                    annotation_text=f"{tag_name} High Trip: {tag_info['alarm_high']} {tag_info['unit']}",
                    annotation_position="top left",
                    annotation_font_color="#dc2626",
                    annotation_font_size=9
                )

                # Low Trip Limit Line
                fig.add_hline(
                    y=tag_info["alarm_low"],
                    line_dash="dash",
                    line_color="#dc2626",
                    line_width=1.5,
                    annotation_text=f"{tag_name} Low Trip: {tag_info['alarm_low']} {tag_info['unit']}",
                    annotation_position="bottom left",
                    annotation_font_color="#dc2626",
                    annotation_font_size=9
                )

                # Shaded Nominal Operating Band
                fig.add_hrect(
                    y0=tag_info["min_nominal"],
                    y1=tag_info["max_nominal"],
                    fillcolor="#ecfdf5",
                    opacity=0.4,
                    line_width=1,
                    line_color="#86efac",
                    annotation_text=f"Nominal Band: [{tag_info['min_nominal']} - {tag_info['max_nominal']}]",
                    annotation_position="top right",
                    annotation_font_color="#065f46",
                    annotation_font_size=9
                )

        fig.update_layout(
            title=f"Industrial Strip-Chart — {unit['name']}",
            title_font_size=13,
            title_font_color="#0f172a",
            xaxis_title="Simulation Time (Wall-Clock Elapsed)",
            yaxis_title="Measured Engineering Value",
            template="plotly_white",
            height=380,
            margin=dict(l=40, r=40, t=40, b=40),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=1.02,
                xanchor="right",
                x=1,
                bgcolor="rgba(255,255,255,0.8)"
            ),
            hovermode="x unified"
        )
        st.plotly_chart(fig, use_container_width=True)

    st.markdown("---")

    # =========================================================================
    # CURRENT PHYSICAL VALUE GAUGES & METRIC CARDS
    # =========================================================================
    st.markdown("#### 📊 Current Transmitter Values & Loop Health")
    current_vals = st.session_state.sim_time_series.iloc[-1]
    
    val_cols = st.columns(len(tags))
    for i, t in enumerate(tags):
        tag_key = t["tag"]
        curr_val = current_vals.get(tag_key, t["nominal_val"])
        is_alarm = (curr_val >= t["alarm_high"] or curr_val <= t["alarm_low"])
        is_warn = (curr_val > t["max_nominal"] or curr_val < t["min_nominal"]) and not is_alarm

        with val_cols[i]:
            card_border = "#dc2626" if is_alarm else ("#d97706" if is_warn else "#e2e8f0")
            status_text = "ALARM TRIP" if is_alarm else ("WARNING" if is_warn else "NORMAL")
            status_color = "#dc2626" if is_alarm else ("#d97706" if is_warn else "#16a34a")

            st.markdown(
                f"""
                <div style="background:#ffffff; border:1px solid {card_border}; border-top:3px solid {card_border}; border-radius:4px; padding:10px 12px; margin-bottom:8px;">
                    <div style="font-size:11px; font-weight:700; color:#64748b; font-family:monospace;">{tag_key}</div>
                    <div style="font-size:18px; font-weight:800; color:#0f172a; font-family:monospace; margin:4px 0;">{curr_val} <span style="font-size:12px; color:#64748b;">{t['unit']}</span></div>
                    <div style="display:flex; justify-content:space-between; align-items:center; font-size:10px;">
                        <span style="color:#64748b;">Band: {t['min_nominal']}-{t['max_nominal']}</span>
                        <span style="color:{status_color}; font-weight:700;">● {status_text}</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True
            )

    # Monitored Tag Technical Specification Table
    with st.expander(f"📋 Technical Data Sheet & Alarm Setpoints for {unit['short_name']}"):
        spec_df = pd.DataFrame([
            {
                "Tag": t["tag"],
                "Description": t["name"],
                "Operating Equilibrium": f"{t['nominal_val']} {t['unit']}",
                "Safe Band [Min-Max]": f"[{t['min_nominal']} to {t['max_nominal']}] {t['unit']}",
                "Low Trip Limit": f"{t['alarm_low']} {t['unit']}",
                "High Trip Limit": f"{t['alarm_high']} {t['unit']}",
                "Principle": t["description"]
            }
            for t in tags
        ])
        st.dataframe(spec_df, use_container_width=True, hide_index=True)
