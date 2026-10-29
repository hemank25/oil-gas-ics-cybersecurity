"""
facility_map.py
===============
Interactive 2D Industrial Facility Map & Asset Detail Inspector for MUJ Demo Refinery.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: SCADA/HMI Interface Designer & OT Cybersecurity Specialist

This component renders an authentic, industrial-grade 2D schematic of the fictional refinery,
displaying:
- Purdue Model network zones (Level 0/1 Field, Level 2 Supervisory, Level 3.5 DMZ)
- Process flow piping (steam, crude, transfer manifold)
- Industrial communications conduits (Modbus/TCP, S7comm, DNP3, OPC UA)
- Real-time asset status lamps (green/amber/red/grey)
- Interactive asset highlighting and operational detail inspector
"""

from typing import Dict, Any, Optional
import streamlit as st
from assets_config import (
    ASSET_REGISTRY,
    STATUS_COLORS,
    SECURITY_COLORS,
    get_all_assets,
    get_asset,
    filter_assets
)

def generate_refinery_svg(selected_asset_id: Optional[str] = None, filter_mode: str = "ALL") -> str:
    """
    Generate crisp, industrial-grade 2D SVG schematic of the MUJ Demo Refinery.
    Highlights the selected asset and reflects real-time operational and security status.
    """
    assets = get_all_assets()
    filtered = filter_assets(filter_mode)

    # Canvas dimensions
    width = 720
    height = 450

    svg_parts = []
    svg_parts.append(f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="auto" style="background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
    <defs>
        <!-- Marker for flow arrows -->
        <marker id="pipe-arrow-oil" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#b45309" />
        </marker>
        <marker id="pipe-arrow-steam" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#0284c7" />
        </marker>
        <marker id="cyber-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#64748b" />
        </marker>
        <!-- Grid pattern -->
        <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
            <path d="M 20 0 L 0 0 0 20" fill="none" stroke="#f1f5f9" stroke-width="1"/>
        </pattern>
    </defs>

    <!-- Background Grid -->
    <rect width="{width}" height="{height}" fill="url(#grid)" />

    <!-- ======================================================================= -->
    <!-- PURDUE MODEL ZONE BACKGROUNDS & LABELS                                 -->
    <!-- ======================================================================= -->
    <!-- Zone 3.5: DMZ & Boundary (Top) -->
    <rect x="15" y="10" width="690" height="90" rx="4" fill="#f1f5f9" stroke="#cbd5e1" stroke-dasharray="4,4" stroke-width="1.2"/>
    <text x="25" y="26" font-size="10" font-weight="700" fill="#475569" letter-spacing="0.5">PURDUE LEVEL 3.5 : IT/OT DEMILITARIZED ZONE (DMZ) &amp; PERIMETER</text>

    <!-- Zone 2: Supervisory & Engineering (Middle) -->
    <rect x="15" y="115" width="690" height="125" rx="4" fill="#f8fafc" stroke="#cbd5e1" stroke-dasharray="4,4" stroke-width="1.2"/>
    <text x="25" y="131" font-size="10" font-weight="700" fill="#475569" letter-spacing="0.5">PURDUE LEVEL 2 : OT SUPERVISORY CONTROL &amp; ENGINEERING SUBNET (192.168.10.0/24)</text>

    <!-- Zone 0/1: Field Process & SIS (Bottom) -->
    <rect x="15" y="255" width="690" height="180" rx="4" fill="#f1f5f9" stroke="#cbd5e1" stroke-dasharray="4,4" stroke-width="1.2"/>
    <text x="25" y="271" font-size="10" font-weight="700" fill="#475569" letter-spacing="0.5">PURDUE LEVEL 0/1 : PHYSICAL REFINERY PROCESS UNITS, PLCS &amp; SIS (FIELD ZONE)</text>

    <!-- ======================================================================= -->
    <!-- PROCESS FLOW PIPING (PHYSICAL BUS)                                      -->
    <!-- ======================================================================= -->
    <!-- Steam Line: U-02 (Steam Boiler) to U-01 (Distillation) -->
    <path d="M 135 345 L 160 345" stroke="#0284c7" stroke-width="3" fill="none" marker-end="url(#pipe-arrow-steam)"/>
    <text x="138" y="338" font-size="8" fill="#0369a1" font-weight="600">STEAM</text>

    <!-- Crude Feed Line: U-03 (Storage) to U-04 (Pumps) -->
    <path d="M 405 345 L 430 345" stroke="#b45309" stroke-width="3" fill="none" marker-end="url(#pipe-arrow-oil)"/>
    
    <!-- Crude Line: U-04 (Pumps) to U-01 (Distillation) via lower pipe run -->
    <path d="M 485 410 L 485 425 L 215 425 L 215 410" stroke="#b45309" stroke-width="3" fill="none" marker-end="url(#pipe-arrow-oil)"/>
    <text x="310" y="421" font-size="8" fill="#92400e" font-weight="600">CRUDE FEED DISCHARGE</text>

    <!-- Distillate Run-Down Line: U-01 to U-03 Storage Tanks -->
    <path d="M 270 345 L 295 345" stroke="#d97706" stroke-width="2.5" stroke-dasharray="4,2" fill="none" marker-end="url(#pipe-arrow-oil)"/>
    <text x="272" y="338" font-size="8" fill="#b45309" font-weight="600">PRODUCTS</text>

    <!-- Safety Interlock Bus: U-05 (SIS) hardwired interlocks to U-01, U-02, U-03, U-04 -->
    <path d="M 620 410 L 620 435 L 85 435 L 85 410" stroke="#dc2626" stroke-width="1.8" stroke-dasharray="3,3" fill="none"/>
    <text x="350" y="443" font-size="8" fill="#b91c1c" font-weight="700">SIL-3 EMERGENCY SHUTDOWN (SIS) HARDWIRED INTERLOCK BUS</text>

    <!-- ======================================================================= -->
    <!-- CYBER COMMUNICATION CONDUITS (OT ETHERNET & FIELDBUS)                   -->
    <!-- ======================================================================= -->
    <!-- Firewall N-01 <-> SCADA C-01 -->
    <line x1="300" y1="90" x2="300" y2="140" stroke="#64748b" stroke-width="2" stroke-dasharray="3,2" marker-end="url(#cyber-arrow)"/>
    <text x="306" y="112" font-size="8" fill="#475569" font-family="monospace">DMZ TRUNK</text>

    <!-- HMI H-01 <-> SCADA C-01 -->
    <line x1="170" y1="182" x2="240" y2="182" stroke="#2563eb" stroke-width="2" marker-end="url(#cyber-arrow)"/>
    <text x="180" y="176" font-size="8" fill="#1d4ed8" font-family="monospace">OPC-UA/TCP</text>

    <!-- Engineering E-01 <-> SCADA C-01 -->
    <line x1="430" y1="182" x2="360" y2="182" stroke="#475569" stroke-width="1.8" stroke-dasharray="4,2" marker-end="url(#cyber-arrow)"/>
    <text x="375" y="176" font-size="8" fill="#334155" font-family="monospace">SMB/RDP</text>

    <!-- SCADA C-01 down to Field Units Trunk -->
    <line x1="300" y1="225" x2="300" y2="250" stroke="#16a34a" stroke-width="2.5"/>
    <line x1="85" y1="250" x2="620" y2="250" stroke="#16a34a" stroke-width="2.5"/>
    <text x="310" y="247" font-size="8" fill="#15803d" font-weight="700">OT SCADA INDUSTRIAL ETHERNET TRUNK (MODBUS/TCP, S7COMM, DNP3)</text>

    <!-- Drops from SCADA Trunk to Field Controllers -->
    <line x1="85" y1="250" x2="85" y2="280" stroke="#16a34a" stroke-width="1.8" marker-end="url(#cyber-arrow)"/>
    <line x1="215" y1="250" x2="215" y2="280" stroke="#16a34a" stroke-width="1.8" marker-end="url(#cyber-arrow)"/>
    <line x1="350" y1="250" x2="350" y2="280" stroke="#16a34a" stroke-width="1.8" marker-end="url(#cyber-arrow)"/>
    <line x1="485" y1="250" x2="485" y2="280" stroke="#16a34a" stroke-width="1.8" marker-end="url(#cyber-arrow)"/>
    <line x1="620" y1="250" x2="620" y2="280" stroke="#64748b" stroke-width="1.5" stroke-dasharray="3,2" marker-end="url(#cyber-arrow)"/>
''')

    # =======================================================================
    # ASSET RECTANGLES & STATUS OVERLAYS
    # =======================================================================
    for asset_id, asset in assets.items():
        pos = asset["svg_pos"]
        x, y, w, h = pos["x"], pos["y"], pos["width"], pos["height"]
        is_selected = (asset_id == selected_asset_id)
        is_filtered_in = (asset_id in filtered)

        # Operational status color
        op_status = asset.get("operational_status", "ONLINE")
        sec_status = asset.get("security_status", "SECURE")

        # Status lamp color
        if sec_status in ("SUSPECTED_ATTACK", "COMPROMISED") or op_status == "ALARM":
            lamp_color = "#dc2626"  # Red
            pulse_effect = 'animation: pulse 1.5s infinite;'
        elif sec_status in ("VULNERABLE", "ANOMALY_DETECTED") or op_status == "WARNING":
            lamp_color = "#d97706"  # Amber
            pulse_effect = ''
        elif op_status == "OFFLINE":
            lamp_color = "#64748b"  # Grey
            pulse_effect = ''
        else:
            lamp_color = "#16a34a"  # Green
            pulse_effect = ''

        # Box border & fill
        box_opacity = "1.0" if is_filtered_in else "0.35"
        if is_selected:
            box_stroke = "#2563eb"
            box_stroke_width = "3"
            box_fill = "#eff6ff"
            shadow = 'filter="drop-shadow(0px 2px 6px rgba(37,99,235,0.3))"'
        else:
            box_stroke = "#cbd5e1"
            box_stroke_width = "1.5"
            box_fill = "#ffffff"
            shadow = 'filter="drop-shadow(0px 1px 3px rgba(0,0,0,0.06))"'

        # Asset Title & Type
        svg_parts.append(f'''
    <!-- Asset Node: {asset_id} -->
    <g id="node-{asset_id}" opacity="{box_opacity}">
        <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="5" fill="{box_fill}" stroke="{box_stroke}" stroke-width="{box_stroke_width}" {shadow}/>
        
        <!-- Header Bar -->
        <rect x="{x}" y="{y}" width="{w}" height="20" rx="4" fill="#f8fafc" stroke="{box_stroke}" stroke-width="0.8"/>
        
        <!-- Status Lamp -->
        <circle cx="{x + 12}" cy="{y + 10}" r="4" fill="{lamp_color}" stroke="#ffffff" stroke-width="1"/>
        
        <!-- Tag Label -->
        <text x="{x + 22}" y="{y + 14}" font-size="10" font-weight="700" fill="#1e293b" font-family="monospace">{asset_id}</text>
        
        <!-- IP or Role Subtitle -->
        <text x="{x + w - 8}" y="{y + 14}" font-size="8" font-family="monospace" fill="#64748b" text-anchor="end">{asset.get('ip_address', '').split(' ')[0]}</text>
        
        <!-- Name -->
        <text x="{x + 8}" y="{y + 34}" font-size="9" font-weight="600" fill="#0f172a">{asset['short_name']}</text>
        
        <!-- Detail Lines -->
        <text x="{x + 8}" y="{y + 48}" font-size="7.5" fill="#475569">{asset['asset_type']}</text>
        <text x="{x + 8}" y="{y + 60}" font-size="7.5" font-family="monospace" fill="#64748b">Ctrl: {asset['controller_id']}</text>
        ''')

        # Additional unit-specific indicators for process units
        if asset_id.startswith("U-"):
            tags = asset.get("tags", [])
            tag_summary = f"{len(tags)} Tags Monitored"
            svg_parts.append(f'''
        <rect x="{x + 6}" y="{y + 66}" width="{w - 12}" height="14" rx="2" fill="#f1f5f9"/>
        <text x="{x + 10}" y="{y + 76}" font-size="7.5" font-family="monospace" fill="#334155">{tag_summary}</text>
        ''')
        # Status Badge at bottom of box
            sec_badge_bg = "#ecfdf5" if sec_status == "SECURE" else ("#fee2e2" if "ATTACK" in sec_status else "#fef3c7")
            sec_badge_txt = "#15803d" if sec_status == "SECURE" else ("#b91c1c" if "ATTACK" in sec_status else "#b45309")
            svg_parts.append(f'''
        <rect x="{x + 6}" y="{y + 85}" width="{w - 12}" height="14" rx="2" fill="{sec_badge_bg}"/>
        <text x="{x + 10}" y="{y + 95}" font-size="7.5" font-weight="600" fill="{sec_badge_txt}">{sec_status}</text>
        ''')
        else:
            # Supervisory boxes
            sec_badge_bg = "#ecfdf5" if sec_status == "SECURE" else "#fef3c7"
            sec_badge_txt = "#15803d" if sec_status == "SECURE" else "#b45309"
            svg_parts.append(f'''
        <rect x="{x + 6}" y="{y + 66}" width="{w - 12}" height="13" rx="2" fill="{sec_badge_bg}"/>
        <text x="{x + 10}" y="{y + 75}" font-size="7" font-weight="600" fill="{sec_badge_txt}">{sec_status}</text>
        ''')

        svg_parts.append('</g>')

    # Legend at bottom right of schematic
    svg_parts.append(f'''
    <!-- Industrial Legend -->
    <g id="legend" transform="translate(480, 18)">
        <rect width="220" height="74" rx="4" fill="#ffffff" stroke="#cbd5e1" stroke-width="1" opacity="0.95"/>
        <text x="8" y="13" font-size="8.5" font-weight="700" fill="#1e293b">SCHEMATIC LEGEND</text>
        
        <circle cx="14" cy="26" r="3.5" fill="#16a34a"/>
        <text x="24" y="29" font-size="7.5" fill="#334155">Operational Nominal / Secure</text>
        
        <circle cx="14" cy="40" r="3.5" fill="#d97706"/>
        <text x="24" y="43" font-size="7.5" fill="#334155">Process Advisory / Anomaly</text>
        
        <circle cx="14" cy="54" r="3.5" fill="#dc2626"/>
        <text x="24" y="57" font-size="7.5" fill="#334155">Trip Alarm / Attack Event</text>

        <line x1="140" y1="26" x2="165" y2="26" stroke="#0284c7" stroke-width="2"/>
        <text x="170" y="29" font-size="7.5" fill="#0284c7">Steam</text>

        <line x1="140" y1="40" x2="165" y2="40" stroke="#b45309" stroke-width="2"/>
        <text x="170" y="43" font-size="7.5" fill="#b45309">Crude</text>

        <line x1="140" y1="54" x2="165" y2="54" stroke="#16a34a" stroke-width="2"/>
        <text x="170" y="57" font-size="7.5" fill="#16a34a">SCADA</text>

        <line x1="140" y1="67" x2="165" y2="67" stroke="#dc2626" stroke-width="1.5" stroke-dasharray="3,2"/>
        <text x="170" y="70" font-size="7.5" fill="#dc2626">SIS Interlock</text>
    </g>
</svg>''')

    return "".join(svg_parts)


def render_facility_map_page():
    """Render the full Facility Map page with interactive filters and asset detail pane."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>🗺️ MUJ Demo Refinery — 2D Industrial Facility Map</h2>
            <p>Top-down physical process schematic and OT supervisory communication topology. Select any asset to inspect Purdue classification, field sensor tags, and operational health.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    all_assets = get_all_assets()
    asset_ids = list(all_assets.keys())

    # Ensure valid selected asset in session state
    if "selected_asset_id" not in st.session_state or st.session_state.selected_asset_id not in all_assets:
        st.session_state.selected_asset_id = asset_ids[0] if asset_ids else "U-01"

    # Callback when quick jump button is clicked
    def _select_asset_callback(aid: str):
        st.session_state.selected_asset_id = aid
        st.session_state["asset_selector_dropdown"] = aid

    # Callback when dropdown selection changes
    def _dropdown_callback():
        if "asset_selector_dropdown" in st.session_state:
            st.session_state.selected_asset_id = st.session_state["asset_selector_dropdown"]

    # Filter controls
    col_filter, col_select, col_mode = st.columns([1.5, 1.5, 1])
    with col_filter:
        filter_mode = st.selectbox(
            "Filter Assets on Schematic:",
            ["ALL", "ABNORMAL", "ALARMS", "FIELD_UNITS", "SUPERVISORY"],
            format_func=lambda x: {
                "ALL": "Display All 9 Refinery Assets",
                "ABNORMAL": "Abnormal / Alarming Assets Only",
                "ALARMS": "Active Trip Alarms & Threats",
                "FIELD_UNITS": "Field Process Units Only (U-01 to U-05)",
                "SUPERVISORY": "Supervisory & Boundary Nodes (C-01, H-01, E-01, N-01)"
            }.get(x, x),
            key="map_filter_mode"
        )

    filtered_dict = filter_assets(filter_mode)
    options = list(filtered_dict.keys()) if filtered_dict else asset_ids

    # If current asset is excluded by active filter, update to first available option
    if st.session_state.selected_asset_id not in options:
        st.session_state.selected_asset_id = options[0]

    # Pre-sync dropdown session state with single source of truth before widget renders
    st.session_state["asset_selector_dropdown"] = st.session_state.selected_asset_id

    with col_select:
        idx = options.index(st.session_state.selected_asset_id) if st.session_state.selected_asset_id in options else 0
        st.selectbox(
            "Select Asset to Inspect:",
            options=options,
            index=idx,
            format_func=lambda x: f"[{x}] {all_assets[x]['name']}",
            key="asset_selector_dropdown",
            on_change=_dropdown_callback
        )

    with col_mode:
        st.markdown("**Schematic Data Mode**")
        st.markdown(
            '<span style="background:#e0f2fe; color:#0369a1; padding:3px 8px; border-radius:4px; font-size:12px; font-weight:600; border:1px solid #bae6fd;">● SIMULATED OT TOPOLOGY</span>',
            unsafe_allow_html=True
        )

    # Render interactive SVG with currently selected asset highlighted
    svg_html = generate_refinery_svg(
        selected_asset_id=st.session_state.selected_asset_id,
        filter_mode=filter_mode
    )
    st.components.v1.html(svg_html, height=470, scrolling=False)

    # Quick Jump Buttons row: every asset button selects its corresponding asset with active visual state
    st.markdown("**Quick Asset Select:**")
    btn_cols = st.columns(len(all_assets))
    for i, (aid, ainfo) in enumerate(all_assets.items()):
        with btn_cols[i]:
            is_active = (aid == st.session_state.selected_asset_id)
            btn_type = "primary" if is_active else "secondary"
            st.button(
                aid,
                key=f"btn_asset_{aid}",
                type=btn_type,
                use_container_width=True,
                on_click=_select_asset_callback,
                args=(aid,)
            )

    st.markdown("---")

    # =========================================================================
    # DETAILED OPERATIONAL ASSET INSPECTION PANEL (Guaranteed Fallback & Fresh Data)
    # =========================================================================
    curr_asset = get_asset(st.session_state.selected_asset_id)
    if not curr_asset and all_assets:
        # Sensible fallback if requested asset is missing
        fallback_id = asset_ids[0]
        st.session_state.selected_asset_id = fallback_id
        st.session_state["asset_selector_dropdown"] = fallback_id
        curr_asset = get_asset(fallback_id)

    if curr_asset:
        render_asset_detail_panel(curr_asset)
    else:
        st.warning("⚠️ Selected asset is not available in the refinery asset registry. Please select a valid unit above.")


def render_asset_detail_panel(asset: Dict[str, Any]):
    """Render comprehensive engineering and operational details for the selected asset."""
    asset_id = asset["id"]
    name = asset["name"]
    op_status = asset["operational_status"]
    sec_status = asset["security_status"]

    op_cfg = STATUS_COLORS.get(op_status, STATUS_COLORS["ONLINE"])
    sec_cfg = SECURITY_COLORS.get(sec_status, SECURITY_COLORS["SECURE"])

    header_col1, header_col2 = st.columns([3, 1])
    with header_col1:
        st.markdown(f"### 🔍 Asset Detail: `[{asset_id}]` {name}")
        st.caption(f"**Purdue Classification**: {asset['purdue_level']} | **Physical Zone**: {asset['zone']}")
    with header_col2:
        st.markdown(
            f'<div style="text-align:right;">'
            f'<span style="background:{op_cfg["bg"]}; color:{op_cfg["text"]}; border:1px solid {op_cfg["border"]}; padding:4px 8px; border-radius:4px; font-weight:700; font-size:12px; margin-right:4px;">● {op_cfg["label"]}</span>'
            f'<span style="background:{sec_cfg["bg"]}; color:{sec_cfg["text"]}; border:1px solid {sec_cfg["border"]}; padding:4px 8px; border-radius:4px; font-weight:700; font-size:12px;">🛡️ {sec_cfg["label"]}</span>'
            f'</div>',
            unsafe_allow_html=True
        )

    # Asset Specs & Network Architecture
    col_net, col_conn, col_diag = st.columns([1.2, 1.2, 1.2])
    with col_net:
        st.markdown("#### 🌐 Network & Controller Identity")
        st.markdown(f"- **Controller ID**: `{asset['controller_id']}`")
        st.markdown(f"- **Simulated IP**: `{asset['ip_address']}`")
        st.markdown(f"- **MAC Address**: `{asset['mac_address']}`")
        st.markdown(f"- **Telemetry Health**: `{asset.get('telemetry_health_pct', 100.0)}% Nominal`")

    with col_conn:
        st.markdown("#### 🔌 Communications & Services")
        services = asset.get("services", [])
        if services:
            for s in services:
                st.markdown(f"- **{s['service']}** (Port `{s['port']}/{s['protocol']}`) - Status: `{s['status']}`")
        else:
            st.markdown("- *Isolated Hardwired Bus (No routable IP ports)*")
        
        connected = asset.get("connected_assets", [])
        st.markdown(f"- **Connected Nodes**: `{', '.join(connected)}`")

    with col_diag:
        st.markdown("#### ⚙️ Operational Status & Telemetry Bounds")
        st.markdown(f"- **Operational Mode**: `● {op_status}`")
        st.markdown(f"- **Security Posture**: `🛡️ {sec_status}`")
        st.markdown(f"- **Supervisory Polling**: `1.0 Hz Cyclic`")
        if sec_status == "SECURE":
            st.success("✅ Asset correlates within nominal physical boundaries.")
        elif "ATTACK" in sec_status:
            st.error("🚨 Critical security perturbation flagged on asset channel.")
        else:
            st.warning("⚠️ Telemetry deviation under advisory investigation.")

    # Process Inputs and Outputs
    p_in = asset.get("process_inputs", [])
    p_out = asset.get("process_outputs", [])
    if p_in or p_out:
        st.markdown("#### 🔄 Process Materials & Energy Flow")
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Inflows / Feeds:**")
            for item in p_in:
                st.markdown(f"- {item}")
        with c2:
            st.markdown("**Outflows / Products:**")
            for item in p_out:
                st.markdown(f"- {item}")

    # Monitored Tags Table
    tags = asset.get("tags", [])
    if tags:
        st.markdown(f"#### 📊 Monitored Field Instrumentation & Actuators ({len(tags)} Tags)")
        tag_records = []
        for t in tags:
            tag_records.append({
                "Physical Tag": t["tag"],
                "Instrument Name": t["name"],
                "Nominal Value": f"{t['nominal_val']} {t['unit']}",
                "Safe Operating Range": f"[{t['min_nominal']} - {t['max_nominal']}] {t['unit']}",
                "Low Alarm Limit": f"{t['alarm_low']} {t['unit']}",
                "High Trip Limit": f"{t['alarm_high']} {t['unit']}",
                "Sensor Principle / Role": t["description"]
            })
        st.dataframe(tag_records, use_container_width=True, hide_index=True)
    else:
        st.info("This supervisory node aggregates field telemetry from connected process units rather than housing direct field transmitters.")

