"""
network_topology.py
===================
Interactive IT/OT Network Topology & Industrial Conduit Inspector.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: OT Systems Architecture & Network Security Specialist

Architecture:
- Purdue Enterprise Reference Architecture (PERA / ISA-95):
  * Level 3.5: IT/OT Demilitarized Zone (Industrial Perimeter Firewall N-01)
  * Level 2: Supervisory OT Subnet (SCADA Host C-01, Operator HMI H-01, Engineering Station E-01)
  * Level 1: Basic Process Control & SIS (PLCs 01-A, 01, 02, 04, and TMR-SIS-01)
  * Level 0: Physical Field Sensors & Actuators
"""

from typing import Dict, Any, List, Optional
import streamlit as st
import pandas as pd
from assets_config import get_all_assets, get_asset

# Conduits mapping
CONDUITS: List[Dict[str, Any]] = [
    {
        "conduit_id": "CND-01",
        "name": "Supervisory OPC-UA Trunk",
        "source": "H-01 (Operator HMI)",
        "destination": "C-01 (SCADA Host)",
        "protocol": "OPC UA / TCP",
        "port": 4840,
        "zone": "Level 2 Supervisory Subnet",
        "status": "NORMAL",
        "bandwidth": "100 Mbps (Full Duplex)",
        "encryption": "TLS 1.3 / Basic256Sha256",
        "security_policy": "Authenticated & Integrity Monitored"
    },
    {
        "conduit_id": "CND-02",
        "name": "Engineering Administration & Logic",
        "source": "E-01 (Engineering Station)",
        "destination": "C-01 (SCADA Host)",
        "protocol": "SMBv2 / RDP",
        "port": 445,
        "zone": "Level 2 Privileged Subnet",
        "status": "NORMAL",
        "bandwidth": "1 Gbps",
        "encryption": "Enforced SMB Signing",
        "security_policy": "MOC Authorized Maintenance Windows Only"
    },
    {
        "conduit_id": "CND-03",
        "name": "Perimeter IT/OT Ingress Trunk",
        "source": "N-01 (Perimeter Firewall)",
        "destination": "C-01 (SCADA Host)",
        "protocol": "IPSec VPN / HTTPS",
        "port": 443,
        "zone": "Level 3.5 DMZ",
        "status": "NORMAL",
        "bandwidth": "1 Gbps",
        "encryption": "AES-256-GCM",
        "security_policy": "Strict State-Tracking & DPI Inspection"
    },
    {
        "conduit_id": "CND-04",
        "name": "Crude Fractionation Modbus Trunk",
        "source": "C-01 (SCADA Host)",
        "destination": "U-01 (PLC-01-A)",
        "protocol": "Modbus / TCP",
        "port": 502,
        "zone": "Level 2 to Level 1 Field Conduit",
        "status": "NORMAL",
        "bandwidth": "100 Mbps Industrial Ethernet",
        "encryption": "Cleartext OT Fieldbus (Air-Gapped)",
        "security_policy": "Read Function 03 Permitted; Write Function 06/16 Restricted"
    },
    {
        "conduit_id": "CND-05",
        "name": "Steam Boiler Control Trunk",
        "source": "C-01 (SCADA Host)",
        "destination": "U-02 (PLC-01)",
        "protocol": "Modbus / TCP",
        "port": 502,
        "zone": "Level 2 to Level 1 Field Conduit",
        "status": "NORMAL",
        "bandwidth": "100 Mbps Industrial Ethernet",
        "encryption": "Cleartext OT Fieldbus",
        "security_policy": "Deep Packet Inspection (DPI) Enabled"
    },
    {
        "conduit_id": "CND-06",
        "name": "Storage Tank Farm Telemetry Bus",
        "source": "C-01 (SCADA Host)",
        "destination": "U-03 (PLC-02)",
        "protocol": "DNP3 / IP",
        "port": 20000,
        "zone": "Level 2 to Level 1 Field Conduit",
        "status": "NORMAL",
        "bandwidth": "100 Mbps Industrial Ethernet",
        "encryption": "Secure Authentication DNP3-SAv5",
        "security_policy": "Cyclic Report-by-Exception"
    },
    {
        "conduit_id": "CND-07",
        "name": "Turbine Governor Control Link",
        "source": "E-01 (Engineering Station)",
        "destination": "U-04 (PLC-04)",
        "protocol": "Siemens S7comm",
        "port": 102,
        "zone": "Level 2 to Level 1 Engineering Conduit",
        "status": "NORMAL",
        "bandwidth": "100 Mbps",
        "encryption": "Proprietary Siemens Industrial Protocol",
        "security_policy": "Program Block Uploads Require Key-Switch in RUN-P"
    },
    {
        "conduit_id": "CND-08",
        "name": "Safety SIS Hardwired Interlock Bus",
        "source": "U-05 (TMR-SIS-01)",
        "destination": "U-01, U-02, U-03, U-04",
        "protocol": "SIL-3 Safety Bus / 24Vdc Hardwire",
        "port": 44818,
        "zone": "Level 1 Safety Instrumented System",
        "status": "NORMAL",
        "bandwidth": "Sub-millisecond Copper Interlock",
        "encryption": "Dedicated Physical Conduits (Galvanically Isolated)",
        "security_policy": "Independent Safety Layer (IEC 61511)"
    }
]

def generate_network_topology_svg(selected_asset_id: str = "C-01") -> str:
    """Generate industrial network architecture SVG diagram."""
    width = 740
    height = 420

    assets = get_all_assets()
    sel_asset = assets.get(selected_asset_id, assets.get("C-01"))

    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="100%" height="auto" style="background:#f8fafc; border:1px solid #cbd5e1; border-radius:4px; font-family:-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;">
    <defs>
        <marker id="net-arrow" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#2563eb" />
        </marker>
        <marker id="net-arrow-green" viewBox="0 0 10 10" refX="6" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 1 L 8 5 L 0 9 z" fill="#16a34a" />
        </marker>
    </defs>

    <!-- ZONE 3.5: DMZ -->
    <rect x="20" y="15" width="700" height="75" rx="4" fill="#f1f5f9" stroke="#94a3b8" stroke-dasharray="4,4" stroke-width="1.2"/>
    <text x="32" y="32" font-size="10" font-weight="700" fill="#475569">PURDUE LEVEL 3.5 : INDUSTRIAL DMZ &amp; PERIMETER GATEWAY</text>

    <!-- N-01 Box -->
    <rect x="290" y="40" width="160" height="38" rx="4" fill="{'#eff6ff' if selected_asset_id == 'N-01' else '#ffffff'}" stroke="{'#2563eb' if selected_asset_id == 'N-01' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'N-01' else '1.5'}"/>
    <circle cx="304" cy="59" r="4" fill="#16a34a"/>
    <text x="316" y="55" font-size="9" font-weight="700" fill="#0f172a">N-01: OT Firewall</text>
    <text x="316" y="68" font-size="8" fill="#64748b" font-family="monospace">192.168.10.1 (DMZ)</text>

    <!-- Firewall Trunk Line -->
    <line x1="370" y1="78" x2="370" y2="125" stroke="#64748b" stroke-width="2" stroke-dasharray="3,2" marker-end="url(#net-arrow)"/>

    <!-- ZONE 2: SUPERVISORY SUBNET -->
    <rect x="20" y="105" width="700" height="120" rx="4" fill="#ffffff" stroke="#94a3b8" stroke-dasharray="4,4" stroke-width="1.2"/>
    <text x="32" y="121" font-size="10" font-weight="700" fill="#475569">PURDUE LEVEL 2 : OT SUPERVISORY CONTROL &amp; ENGINEERING (192.168.10.0/24)</text>

    <!-- H-01 Console -->
    <rect x="40" y="140" width="180" height="65" rx="4" fill="{'#eff6ff' if selected_asset_id == 'H-01' else '#f8fafc'}" stroke="{'#2563eb' if selected_asset_id == 'H-01' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'H-01' else '1.2'}"/>
    <circle cx="55" cy="158" r="4" fill="#16a34a"/>
    <text x="66" y="158" font-size="9.5" font-weight="700" fill="#0f172a">H-01: Operator HMI</text>
    <text x="55" y="174" font-size="8" fill="#475569">Graphics &amp; Alarms Console</text>
    <text x="55" y="188" font-size="8" font-family="monospace" fill="#64748b">192.168.10.8 (TCP:8080/5900)</text>

    <!-- SCADA Server C-01 -->
    <rect x="270" y="135" width="200" height="75" rx="4" fill="{'#eff6ff' if selected_asset_id == 'C-01' else '#f8fafc'}" stroke="{'#2563eb' if selected_asset_id == 'C-01' else '#2563eb'}" stroke-width="{'2.5' if selected_asset_id == 'C-01' else '1.8'}"/>
    <circle cx="286" cy="154" r="4" fill="#16a34a"/>
    <text x="298" y="155" font-size="10" font-weight="700" fill="#1d4ed8">C-01: SCADA Host</text>
    <text x="286" y="172" font-size="8" fill="#475569">Central Polling Master &amp; Historian</text>
    <text x="286" y="186" font-size="8" font-family="monospace" fill="#64748b">192.168.10.5 (OPC-UA/Modbus)</text>
    <text x="286" y="198" font-size="8" fill="#16a34a" font-weight="600">Scan Rate: 1.0 Hz Cyclic</text>

    <!-- EWS E-01 -->
    <rect x="520" y="140" width="180" height="65" rx="4" fill="{'#eff6ff' if selected_asset_id == 'E-01' else '#f8fafc'}" stroke="{'#2563eb' if selected_asset_id == 'E-01' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'E-01' else '1.2'}"/>
    <circle cx="535" cy="158" r="4" fill="#16a34a"/>
    <text x="546" y="158" font-size="9.5" font-weight="700" fill="#0f172a">E-01: Engineering WS</text>
    <text x="535" y="174" font-size="8" fill="#475569">Logic Development &amp; Tuning</text>
    <text x="535" y="188" font-size="8" font-family="monospace" fill="#64748b">192.168.10.20 (SMB:445)</text>

    <!-- Conduits inside Level 2 -->
    <line x1="220" y1="172" x2="270" y2="172" stroke="#2563eb" stroke-width="2" marker-end="url(#net-arrow)"/>
    <text x="228" y="166" font-size="7.5" fill="#1d4ed8" font-family="monospace">OPC-UA</text>

    <line x1="520" y1="172" x2="470" y2="172" stroke="#64748b" stroke-width="1.8" stroke-dasharray="3,2" marker-end="url(#net-arrow)"/>
    <text x="480" y="166" font-size="7.5" fill="#475569" font-family="monospace">ADMIN</text>

    <!-- Downlink to Field Switch Trunk -->
    <line x1="370" y1="210" x2="370" y2="240" stroke="#16a34a" stroke-width="2.5"/>
    <line x1="90" y1="240" x2="650" y2="240" stroke="#16a34a" stroke-width="2.5"/>
    <text x="380" y="236" font-size="8" fill="#15803d" font-weight="700">REDUNDANT OT FIELDBUS TRUNK (ETHERNET/IP &amp; MODBUS/TCP)</text>

    <!-- ZONE 1/0: FIELD CONTROLLERS & SENSORS -->
    <rect x="20" y="248" width="700" height="155" rx="4" fill="#f1f5f9" stroke="#94a3b8" stroke-dasharray="4,4" stroke-width="1.2"/>
    <text x="32" y="264" font-size="10" font-weight="700" fill="#475569">PURDUE LEVEL 1/0 : BASIC PROCESS CONTROLLERS (PLCS) &amp; SIS FIELD SYSTEM</text>

    <!-- PLC drops -->
    <!-- U-01 -->
    <line x1="95" y1="240" x2="95" y2="275" stroke="#16a34a" stroke-width="1.8" marker-end="url(#net-arrow-green)"/>
    <rect x="35" y="275" width="120" height="115" rx="4" fill="{'#eff6ff' if selected_asset_id == 'U-01' else '#ffffff'}" stroke="{'#2563eb' if selected_asset_id == 'U-01' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'U-01' else '1.2'}"/>
    <text x="45" y="293" font-size="9" font-weight="700" fill="#0f172a">U-01: Crude Feed</text>
    <text x="45" y="307" font-size="8" fill="#475569">PLC-01-A (p:502)</text>
    <text x="45" y="321" font-size="7.5" font-family="monospace" fill="#64748b">192.168.10.10</text>
    <text x="45" y="337" font-size="7.5" fill="#16a34a">Modbus/TCP Polled</text>

    <!-- U-02 -->
    <line x1="230" y1="240" x2="230" y2="275" stroke="#16a34a" stroke-width="1.8" marker-end="url(#net-arrow-green)"/>
    <rect x="170" y="275" width="120" height="115" rx="4" fill="{'#eff6ff' if selected_asset_id == 'U-02' else '#ffffff'}" stroke="{'#2563eb' if selected_asset_id == 'U-02' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'U-02' else '1.2'}"/>
    <text x="180" y="293" font-size="9" font-weight="700" fill="#0f172a">U-02: Steam Boiler</text>
    <text x="180" y="307" font-size="8" fill="#475569">PLC-01 (p:502)</text>
    <text x="180" y="321" font-size="7.5" font-family="monospace" fill="#64748b">192.168.10.11</text>
    <text x="180" y="337" font-size="7.5" fill="#16a34a">Modbus/TCP Polled</text>

    <!-- U-03 -->
    <line x1="370" y1="240" x2="370" y2="275" stroke="#16a34a" stroke-width="1.8" marker-end="url(#net-arrow-green)"/>
    <rect x="310" y="275" width="120" height="115" rx="4" fill="{'#eff6ff' if selected_asset_id == 'U-03' else '#ffffff'}" stroke="{'#2563eb' if selected_asset_id == 'U-03' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'U-03' else '1.2'}"/>
    <text x="320" y="293" font-size="9" font-weight="700" fill="#0f172a">U-03: Storage Farm</text>
    <text x="320" y="307" font-size="8" fill="#475569">PLC-02 (p:20000)</text>
    <text x="320" y="321" font-size="7.5" font-family="monospace" fill="#64748b">192.168.10.12</text>
    <text x="320" y="337" font-size="7.5" fill="#16a34a">DNP3/IP Polled</text>

    <!-- U-04 -->
    <line x1="510" y1="240" x2="510" y2="275" stroke="#16a34a" stroke-width="1.8" marker-end="url(#net-arrow-green)"/>
    <rect x="450" y="275" width="120" height="115" rx="4" fill="{'#eff6ff' if selected_asset_id == 'U-04' else '#ffffff'}" stroke="{'#2563eb' if selected_asset_id == 'U-04' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'U-04' else '1.2'}"/>
    <text x="460" y="293" font-size="9" font-weight="700" fill="#0f172a">U-04: Turbines</text>
    <text x="460" y="307" font-size="8" fill="#475569">PLC-04 (p:102)</text>
    <text x="460" y="321" font-size="7.5" font-family="monospace" fill="#64748b">192.168.10.14</text>
    <text x="460" y="337" font-size="7.5" fill="#16a34a">Siemens S7comm</text>

    <!-- U-05 SIS -->
    <line x1="640" y1="240" x2="640" y2="275" stroke="#dc2626" stroke-width="1.8" stroke-dasharray="3,2"/>
    <rect x="585" y="275" width="120" height="115" rx="4" fill="{'#eff6ff' if selected_asset_id == 'U-05' else '#ffffff'}" stroke="{'#2563eb' if selected_asset_id == 'U-05' else '#cbd5e1'}" stroke-width="{'2.5' if selected_asset_id == 'U-05' else '1.2'}"/>
    <text x="595" y="293" font-size="9" font-weight="700" fill="#991b1b">U-05: Safety SIS</text>
    <text x="595" y="307" font-size="8" fill="#475569">TMR-SIS-01</text>
    <text x="595" y="321" font-size="7.5" font-family="monospace" fill="#64748b">192.168.10.15</text>
    <text x="595" y="337" font-size="7.5" fill="#dc2626" font-weight="700">SIL-3 Interlocked</text>
</svg>"""

def render_network_topology_page():
    """Render the full interactive Network Topology & Industrial Conduit Inspector."""
    st.markdown(
        """
        <div class="industrial-header">
            <h2>🌐 Industrial Network Topology &amp; Conduit Inspector</h2>
            <p>Purdue Model (Levels 0–3.5) architecture, industrial communication conduits, protocol analysis, and link telemetry.</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    if "selected_net_asset" not in st.session_state:
        st.session_state.selected_net_asset = "C-01"

    assets = get_all_assets()

    # Top selector
    c_sel, c_stat = st.columns([2, 1])
    with c_sel:
        selected = st.selectbox(
            "Highlight Node in Network Topology:",
            options=list(assets.keys()),
            format_func=lambda x: f"[{x}] {assets[x]['name']} ({assets[x]['ip_address']})",
            index=list(assets.keys()).index(st.session_state.selected_net_asset) if st.session_state.selected_net_asset in assets else 0,
            key="net_node_select"
        )
        st.session_state.selected_net_asset = selected

    with c_stat:
        st.markdown("**OT Network Security Posture**")
        st.markdown(
            '<div style="background:#ecfdf5; color:#166534; padding:6px 10px; border-radius:4px; border:1px solid #86efac; font-size:12px; font-weight:700;">'
            '● 8 INDUSTRIAL CONDUITS NOMINAL'
            '</div>',
            unsafe_allow_html=True
        )

    # Render SVG diagram
    svg_html = generate_network_topology_svg(selected_asset_id=st.session_state.selected_net_asset)
    st.components.v1.html(svg_html, height=440, scrolling=False)

    st.markdown("---")

    # Tabs: Conduit Inspector vs Node Details
    net_tabs = st.tabs([
        "🔌 Industrial Conduits & Communication Paths",
        "🖥️ Selected Network Node Details"
    ])

    with net_tabs[0]:
        st.markdown("### 🔌 Active Industrial OT Conduits (ISA/IEC 62443 Zones & Conduits)")
        st.caption("All simulated communications follow strict network zoning with granular protocol permissions:")
        df_conduits = pd.DataFrame(CONDUITS)
        st.dataframe(df_conduits, use_container_width=True, hide_index=True)

    with net_tabs[1]:
        a = assets.get(st.session_state.selected_net_asset, assets["C-01"])
        st.markdown(f"### 🖥️ Node Profile: `[{a['id']}]` {a['name']}")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"- **Purdue Level**: `{a['purdue_level']}`")
            st.markdown(f"- **Physical Zone**: `{a['zone']}`")
            st.markdown(f"- **Asset Type**: `{a['asset_type']}`")
        with col2:
            st.markdown(f"- **Simulated IP**: `{a['ip_address']}`")
            st.markdown(f"- **MAC Address**: `{a['mac_address']}`")
            st.markdown(f"- **Controller ID**: `{a['controller_id']}`")
        with col3:
            st.markdown(f"- **Operational**: `● {a['operational_status']}`")
            st.markdown(f"- **Security**: `🛡️ {a['security_status']}`")
            st.markdown(f"- **Telemetry Health**: `{a.get('telemetry_health_pct', 100.0)}%`")
