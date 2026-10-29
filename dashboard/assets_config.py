"""
assets_config.py
================
Central Asset Registry and Configuration for MUJ Demo Refinery.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: OT Cybersecurity Engineer & SCADA/HMI Interface Designer

This module serves as the single source of truth for the fictional refinery's:
1. Equipment hierarchy (Purdue Model Levels 0-3.5)
2. Process units, controllers, HMIs, engineering workstations, and network boundaries
3. Sensor and actuator tag mappings with nominal engineering bounds
4. Simulated IP addresses, open industrial services, and security posture
5. Physical process flow connections and cyber communication conduits
"""

from typing import Dict, List, Optional, Any
from copy import deepcopy

# Facility Metadata
FACILITY_NAME = "MUJ Demo Refinery"
FACILITY_LOCATION = "Manipal University Jaipur - Industrial IoT Simulation Facility"
SIMULATION_MODE = "HARDWARE-IN-THE-LOOP SIMULATION & PROXY TESTBED"

# Asset Registry Dictionary
ASSET_REGISTRY: Dict[str, Dict[str, Any]] = {
    "U-01": {
        "id": "U-01",
        "name": "Crude Feed & Separation Unit",
        "short_name": "Crude Separation",
        "purdue_level": "Level 1/0: Basic Process Control & Field Sensors",
        "purdue_level_int": 1,
        "zone": "Process Zone A (Fractionation & Desalting)",
        "asset_type": "Process Unit",
        "role": "Atmospheric Crude Distillation Column & Primary Separation Train",
        "controller_id": "PLC-01-A",
        "ip_address": "192.168.10.10",
        "mac_address": "00:1B:1B:10:01:0A",
        "services": [
            {"service": "Modbus TCP", "port": 502, "protocol": "TCP", "status": "OPEN"}
        ],
        "operational_status": "ONLINE",
        "security_status": "SECURE",
        "telemetry_health_pct": 100.0,
        "tags": [
            {
                "tag": "P1_PCV01D",
                "name": "Steam Pressure Control Valve Demand",
                "nominal_val": 27.94,
                "unit": "%",
                "min_nominal": 20.0,
                "max_nominal": 35.0,
                "alarm_high": 75.0,
                "alarm_low": 5.0,
                "description": "Primary steam heating loop actuator"
            },
            {
                "tag": "P1_PCV01Z",
                "name": "Steam Pressure Control Valve Position Feedback",
                "nominal_val": 28.40,
                "unit": "%",
                "min_nominal": 19.5,
                "max_nominal": 35.5,
                "alarm_high": 76.0,
                "alarm_low": 4.5,
                "description": "Pneumatic valve stem LVDT position sensor"
            },
            {
                "tag": "P1_PIT01",
                "name": "Column Overhead Pressure Transmitter",
                "nominal_val": 1.12,
                "unit": "kPa",
                "min_nominal": 0.85,
                "max_nominal": 1.45,
                "alarm_high": 2.50,
                "alarm_low": 0.50,
                "description": "Piezoelectric pressure sensor"
            },
            {
                "tag": "P1_TIT01",
                "name": "Column Tray Inflow Temperature Transmitter",
                "nominal_val": 30.38,
                "unit": "°C",
                "min_nominal": 25.0,
                "max_nominal": 38.0,
                "alarm_high": 55.0,
                "alarm_low": 15.0,
                "description": "RTD temperature element"
            },
            {
                "tag": "P1_FCV01D",
                "name": "Crude Feed Flow Control Valve Demand",
                "nominal_val": 32.12,
                "unit": "%",
                "min_nominal": 25.0,
                "max_nominal": 40.0,
                "alarm_high": 80.0,
                "alarm_low": 10.0,
                "description": "Crude feed intake valve"
            }
        ],
        "connected_assets": ["U-02", "U-03", "C-01"],
        "process_inputs": ["Crude Oil from Storage (U-03)", "High-Pressure Steam (U-02)"],
        "process_outputs": ["Distillate Fractions to Storage (U-03)", "Residue Bottoms"],
        "vapt_findings": [],
        "svg_pos": {"x": 160, "y": 280, "width": 110, "height": 130}
    },
    "U-02": {
        "id": "U-02",
        "name": "Water Treatment & Steam Boiler Loop",
        "short_name": "Steam & Boiler",
        "purdue_level": "Level 1/0: Basic Process Control & Field Sensors",
        "purdue_level_int": 1,
        "zone": "Utility Zone (Boiler Island & Deaerator)",
        "asset_type": "Utility & Steam Generation",
        "role": "High-Pressure Process Steam Generation & Feedwater Pumping Loop",
        "controller_id": "PLC-01",
        "ip_address": "192.168.10.11",
        "mac_address": "00:1B:1B:34:5A:01",
        "services": [
            {"service": "Modbus TCP", "port": 502, "protocol": "TCP", "status": "OPEN", "auth": False}
        ],
        "operational_status": "ONLINE",
        "security_status": "VULNERABLE",
        "telemetry_health_pct": 98.5,
        "tags": [
            {
                "tag": "P1_LIT01",
                "name": "Boiler Drum Water Level Indicator",
                "nominal_val": 349.36,
                "unit": "mm",
                "min_nominal": 300.0,
                "max_nominal": 400.0,
                "alarm_high": 480.0,
                "alarm_low": 200.0,
                "description": "Differential pressure level transmitter"
            },
            {
                "tag": "P1_TIT02",
                "name": "Boiler Superheater Steam Temperature",
                "nominal_val": 42.15,
                "unit": "°C",
                "min_nominal": 35.0,
                "max_nominal": 50.0,
                "alarm_high": 70.0,
                "alarm_low": 25.0,
                "description": "Thermocouple probe at superheater exit"
            },
            {
                "tag": "P1_FCV02D",
                "name": "Boiler Feedwater Makeup Valve Demand",
                "nominal_val": 29.50,
                "unit": "%",
                "min_nominal": 20.0,
                "max_nominal": 45.0,
                "alarm_high": 75.0,
                "alarm_low": 5.0,
                "description": "Pneumatic feedwater injection valve"
            }
        ],
        "connected_assets": ["U-01", "U-04", "C-01"],
        "process_inputs": ["Treated Demineralized Water", "Fuel Gas"],
        "process_outputs": ["Superheated Steam to U-01 & U-04", "Boiler Blowdown"],
        "vapt_findings": ["VAPT-2026-001"],
        "svg_pos": {"x": 30, "y": 280, "width": 105, "height": 130}
    },
    "U-03": {
        "id": "U-03",
        "name": "Storage Tanks & Transfer Manifold",
        "short_name": "Tank Farm & Transfer",
        "purdue_level": "Level 1/0: Basic Process Control & Field Sensors",
        "purdue_level_int": 1,
        "zone": "Offsites & Storage Farm",
        "asset_type": "Tank Farm Storage",
        "role": "Crude Receiving Tanks, Intermediate Run-down Tanks, and Blending Manifold",
        "controller_id": "PLC-02",
        "ip_address": "192.168.10.12",
        "mac_address": "00:1B:1B:55:62:33",
        "services": [
            {"service": "DNP3 over IP", "port": 20000, "protocol": "TCP", "status": "OPEN"},
            {"service": "Modbus TCP", "port": 502, "protocol": "TCP", "status": "OPEN"}
        ],
        "operational_status": "ONLINE",
        "security_status": "SECURE",
        "telemetry_health_pct": 100.0,
        "tags": [
            {
                "tag": "P2_24Vdc",
                "name": "Tank Safety Isolation Bus DC Voltage",
                "nominal_val": 28.035,
                "unit": "V",
                "min_nominal": 26.5,
                "max_nominal": 29.5,
                "alarm_high": 31.0,
                "alarm_low": 22.0,
                "description": "DC power health for emergency shutdown interlocks"
            },
            {
                "tag": "P2_AutoSD",
                "name": "Tank Overfill Automatic Shutdown Status",
                "nominal_val": 0.0,
                "unit": "state",
                "min_nominal": 0.0,
                "max_nominal": 0.0,
                "alarm_high": 1.0,
                "alarm_low": 0.0,
                "description": "0=Normal, 1=Auto-Shutdown Armed"
            },
            {
                "tag": "P2_OnOff",
                "name": "Manifold Transfer Valve State",
                "nominal_val": 1.0,
                "unit": "state",
                "min_nominal": 0.0,
                "max_nominal": 1.0,
                "alarm_high": 1.0,
                "alarm_low": 0.0,
                "description": "1=Open (Transfer Active), 0=Closed"
            }
        ],
        "connected_assets": ["U-01", "U-04", "U-05", "C-01"],
        "process_inputs": ["Pipeline Crude Inflow", "Refinery Products from U-01"],
        "process_outputs": ["Feed to U-01", "Product Dispatch to Pipeline Terminal"],
        "vapt_findings": [],
        "svg_pos": {"x": 295, "y": 280, "width": 110, "height": 130}
    },
    "U-04": {
        "id": "U-04",
        "name": "Pumps, Motors & Rotating Equipment Hall",
        "short_name": "Turbines & Compressors",
        "purdue_level": "Level 1/0: Rotating Machinery & Drives",
        "purdue_level_int": 1,
        "zone": "Machinery Hall & Compressor Station",
        "asset_type": "Rotating Equipment",
        "role": "Centrifugal Crude Feed Pumps, Gas Compressors, and Steam Turbines",
        "controller_id": "PLC-04",
        "ip_address": "192.168.10.14",
        "mac_address": "00:1B:1B:77:88:99",
        "services": [
            {"service": "Siemens S7comm", "port": 102, "protocol": "TCP", "status": "OPEN"}
        ],
        "operational_status": "ONLINE",
        "security_status": "SECURE",
        "telemetry_health_pct": 100.0,
        "tags": [
            {
                "tag": "P4_ST_GOV",
                "name": "Steam Turbine Governor Speed Feedback",
                "nominal_val": 18135.0,
                "unit": "RPM",
                "min_nominal": 17800.0,
                "max_nominal": 18400.0,
                "alarm_high": 22000.0,
                "alarm_low": 15000.0,
                "description": "High-speed optical tachometer on turbine rotor shaft"
            },
            {
                "tag": "P4_ST_TT01",
                "name": "Turbine Thrust Bearing Temperature",
                "nominal_val": 27.10,
                "unit": "°C",
                "min_nominal": 22.0,
                "max_nominal": 35.0,
                "alarm_high": 65.0,
                "alarm_low": 15.0,
                "description": "Bearing lubrication journal RTD"
            },
            {
                "tag": "P4_ST_LD",
                "name": "Turbine Mechanical Load Output",
                "nominal_val": 65.4,
                "unit": "kW",
                "min_nominal": 50.0,
                "max_nominal": 85.0,
                "alarm_high": 95.0,
                "alarm_low": 20.0,
                "description": "Shaft torque & power measurement transducer"
            }
        ],
        "connected_assets": ["U-01", "U-02", "U-03", "C-01"],
        "process_inputs": ["High-Pressure Steam (U-02)", "Liquid Feeds from Tanks (U-03)"],
        "process_outputs": ["High-Pressure Discharge to U-01 Fractionator"],
        "vapt_findings": [],
        "svg_pos": {"x": 430, "y": 280, "width": 110, "height": 130}
    },
    "U-05": {
        "id": "U-05",
        "name": "Emergency Isolation & Safety Monitoring (SIS)",
        "short_name": "Safety System (SIS)",
        "purdue_level": "Level 1/0: Safety Instrumented System (SIL-3)",
        "purdue_level_int": 1,
        "zone": "Safety Equipment Room (SIS Enclosure)",
        "asset_type": "Safety Instrumented System",
        "role": "Triple Modular Redundant (TMR) Safety Interlocks & Emergency Depressuring",
        "controller_id": "TMR-SIS-01",
        "ip_address": "192.168.10.15",
        "mac_address": "00:1B:1B:AA:BB:05",
        "services": [
            {"service": "Safety Peer Bus (Hardwired)", "port": 0, "protocol": "HARDWIRED", "status": "ISOLATED"}
        ],
        "operational_status": "ONLINE",
        "security_status": "SECURE",
        "telemetry_health_pct": 100.0,
        "tags": [
            {
                "tag": "P2_Emerg",
                "name": "Plant-wide Emergency De-Inventory Valve Interlock",
                "nominal_val": 0.0,
                "unit": "state",
                "min_nominal": 0.0,
                "max_nominal": 0.0,
                "alarm_high": 1.0,
                "alarm_low": 0.0,
                "description": "0=Armed Normal, 1=Emergency Blowdown Triggered"
            },
            {
                "tag": "ESD_STATUS",
                "name": "Emergency Shutdown Loop Watchdog",
                "nominal_val": 1.0,
                "unit": "health",
                "min_nominal": 1.0,
                "max_nominal": 1.0,
                "alarm_high": 1.0,
                "alarm_low": 0.0,
                "description": "1=Healthy Heartbeat, 0=Failsafe Trip"
            }
        ],
        "connected_assets": ["U-01", "U-02", "U-03", "U-04", "C-01"],
        "process_inputs": ["Hardwired Fire & Gas Detectors", "High-High Pressure Contacts"],
        "process_outputs": ["Trip Contacts to Emergency Isolation Valves"],
        "vapt_findings": [],
        "svg_pos": {"x": 565, "y": 280, "width": 110, "height": 130}
    },
    "C-01": {
        "id": "C-01",
        "name": "Supervisory Control & SCADA Historian Server",
        "short_name": "SCADA Host",
        "purdue_level": "Level 2: Supervisory Control",
        "purdue_level_int": 2,
        "zone": "OT Central Control Room Rack 1",
        "asset_type": "Supervisory Server",
        "role": "SCADA Server, Alarm Engine, Data Historian Collector & OPC Gateway",
        "controller_id": "SCADA-SRV-01",
        "ip_address": "192.168.10.2",
        "mac_address": "00:1B:1B:CC:01:02",
        "services": [
            {"service": "OPC UA Server", "port": 4840, "protocol": "TCP", "status": "OPEN"},
            {"service": "Historian Data Broker", "port": 5432, "protocol": "TCP", "status": "OPEN"},
            {"service": "SCADA Polling Engine", "port": 502, "protocol": "TCP", "status": "MASTER"}
        ],
        "operational_status": "ONLINE",
        "security_status": "SECURE",
        "telemetry_health_pct": 100.0,
        "tags": [],
        "connected_assets": ["U-01", "U-02", "U-03", "U-04", "U-05", "H-01", "E-01", "N-01"],
        "process_inputs": ["Modbus, DNP3 & S7 Field Telemetry from Units"],
        "process_outputs": ["Aggregated Real-time Process Values to HMI (H-01) & AI Detector"],
        "vapt_findings": [],
        "svg_pos": {"x": 240, "y": 140, "width": 120, "height": 85}
    },
    "H-01": {
        "id": "H-01",
        "name": "Main Operator HMI Console Station",
        "short_name": "Operator HMI",
        "purdue_level": "Level 2: Supervisory Control",
        "purdue_level_int": 2,
        "zone": "Central Control Room Operator Desk",
        "asset_type": "Operator Console",
        "role": "Primary Graphic Display Station for Refinery Control Room Shift Engineers",
        "controller_id": "HMI-WS-01",
        "ip_address": "192.168.10.5",
        "mac_address": "00:1B:1B:42:1C:88",
        "services": [
            {"service": "HMI Graphic Client", "port": 8080, "protocol": "TCP", "status": "OPEN"},
            {"service": "VNC Remote Desktop", "port": 5900, "protocol": "TCP", "status": "OPEN", "auth": "WEAK"}
        ],
        "operational_status": "ONLINE",
        "security_status": "VULNERABLE",
        "telemetry_health_pct": 100.0,
        "tags": [],
        "connected_assets": ["C-01"],
        "process_inputs": ["Real-time HMI Graphics & Alarms from C-01"],
        "process_outputs": ["Operator Setpoint Inputs to C-01"],
        "vapt_findings": ["VAPT-2026-002"],
        "svg_pos": {"x": 50, "y": 140, "width": 120, "height": 85}
    },
    "E-01": {
        "id": "E-01",
        "name": "Engineering Workstation (EWS)",
        "short_name": "Engineering Station",
        "purdue_level": "Level 2: Engineering & Configuration",
        "purdue_level_int": 2,
        "zone": "Engineering Maintenance Office",
        "asset_type": "Engineering Workstation",
        "role": "PLC Logic Programming (TIA Portal/Studio 5000), Firmware Maintenance & Diagnostics",
        "controller_id": "EWS-01",
        "ip_address": "192.168.10.20",
        "mac_address": "00:1B:1B:99:EE:14",
        "services": [
            {"service": "SMBv2 File Sharing", "port": 445, "protocol": "TCP", "status": "OPEN", "auth": "UNENCRYPTED"},
            {"service": "RDP Remote Desktop", "port": 3389, "protocol": "TCP", "status": "OPEN"},
            {"service": "PLC Engineering Toolset", "port": 102, "protocol": "TCP", "status": "CLIENT"}
        ],
        "operational_status": "ONLINE",
        "security_status": "VULNERABLE",
        "telemetry_health_pct": 100.0,
        "tags": [],
        "connected_assets": ["C-01", "U-01", "U-02", "U-04"],
        "process_inputs": ["Diagnostic Uploads from PLCs"],
        "process_outputs": ["Ladder Logic Downloads & Register Configurations"],
        "vapt_findings": ["VAPT-2026-003"],
        "svg_pos": {"x": 430, "y": 140, "width": 120, "height": 85}
    },
    "N-01": {
        "id": "N-01",
        "name": "IT/OT Network Boundary & Industrial Firewall",
        "short_name": "Perimeter Firewall",
        "purdue_level": "Level 3.5: Demilitarized Zone (DMZ)",
        "purdue_level_int": 3,
        "zone": "Perimeter Security Gateway / DMZ",
        "asset_type": "Network Security Gateway",
        "role": "Next-Generation Industrial Firewall, Deep Packet Inspection (DPI) & Jump Host",
        "controller_id": "FW-PERIMETER-01",
        "ip_address": "192.168.10.1 (OT) / 10.0.1.1 (DMZ)",
        "mac_address": "00:1B:1B:00:00:01",
        "services": [
            {"service": "Stateful Firewall", "port": 0, "protocol": "ALL", "status": "ENFORCING"},
            {"service": "Industrial DPI", "port": 0, "protocol": "INSPECTION", "status": "ACTIVE"},
            {"service": "SSH Admin Console", "port": 22, "protocol": "TCP", "status": "FILTERED"}
        ],
        "operational_status": "ONLINE",
        "security_status": "SECURE",
        "telemetry_health_pct": 100.0,
        "tags": [],
        "connected_assets": ["C-01"],
        "process_inputs": ["Enterprise Business Network Queries", "Remote Maintenance VPNs"],
        "process_outputs": ["Filtered Historian Replication to Corporate Enterprise"],
        "vapt_findings": [],
        "svg_pos": {"x": 240, "y": 20, "width": 120, "height": 70}
    }
}

# Status color mappings matching industrial HMI standards (ISA-101 / ISA-18.2)
STATUS_COLORS = {
    "ONLINE": {"bg": "#ecfdf5", "border": "#16a34a", "text": "#16a34a", "label": "ONLINE - NOMINAL"},
    "WARNING": {"bg": "#fffbeb", "border": "#d97706", "text": "#d97706", "label": "WARNING / ADVISORY"},
    "ALARM": {"bg": "#fef2f2", "border": "#dc2626", "text": "#dc2626", "label": "ALARM - TRIPPED"},
    "MAINTENANCE": {"bg": "#f1f5f9", "border": "#64748b", "text": "#475569", "label": "MAINTENANCE MODE"},
    "OFFLINE": {"bg": "#f8fafc", "border": "#94a3b8", "text": "#64748b", "label": "OFFLINE / UNREACHABLE"}
}

SECURITY_COLORS = {
    "SECURE": {"bg": "#ecfdf5", "border": "#16a34a", "text": "#16a34a", "label": "NORMAL / SECURE"},
    "VULNERABLE": {"bg": "#fffbeb", "border": "#d97706", "text": "#d97706", "label": "KNOWN VULNERABILITY"},
    "ANOMALY_DETECTED": {"bg": "#fef3c7", "border": "#b45309", "text": "#b45309", "label": "AI ANOMALY FLAGGED"},
    "SUSPECTED_ATTACK": {"bg": "#fee2e2", "border": "#dc2626", "text": "#dc2626", "label": "ATTACK IN PROGRESS"},
    "COMPROMISED": {"bg": "#450a0a", "border": "#dc2626", "text": "#fca5a5", "label": "COMPROMISED ASSET"}
}

def _get_active_registry() -> Dict[str, Dict[str, Any]]:
    """Internal helper to retrieve dynamic registry from session state if available."""
    try:
        import streamlit as st
        if hasattr(st, "session_state") and "asset_registry" in st.session_state:
            return st.session_state["asset_registry"]
    except Exception:
        pass
    return ASSET_REGISTRY

def get_all_assets() -> Dict[str, Dict[str, Any]]:
    """Return a deep copy of all registered assets (from session state if initialized)."""
    return deepcopy(_get_active_registry())

def get_asset(asset_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve an asset by its unique identifier (e.g., 'U-01', 'C-01')."""
    reg = _get_active_registry()
    if asset_id in reg:
        return deepcopy(reg[asset_id])
    return None

def update_asset_status(asset_id: str, operational_status: Optional[str] = None, security_status: Optional[str] = None):
    """Dynamically update an asset's operational and/or security status in session state."""
    try:
        import streamlit as st
        if "asset_registry" not in st.session_state:
            st.session_state["asset_registry"] = deepcopy(ASSET_REGISTRY)
        if asset_id in st.session_state["asset_registry"]:
            if operational_status:
                st.session_state["asset_registry"][asset_id]["operational_status"] = operational_status
            if security_status:
                st.session_state["asset_registry"][asset_id]["security_status"] = security_status
    except Exception:
        pass

def reset_asset_registry():
    """Reset all assets back to nominal operational and security status in session state."""
    try:
        import streamlit as st
        st.session_state["asset_registry"] = deepcopy(ASSET_REGISTRY)
    except Exception:
        pass

def filter_assets(filter_mode: str = "ALL") -> Dict[str, Dict[str, Any]]:
    """
    Filter assets by operational and security status:
    - 'ALL': Return all assets
    - 'ABNORMAL': Return assets with non-ONLINE operational status or non-SECURE security
    - 'ALARMS': Return assets in ALARM operational status or SUSPECTED_ATTACK security
    - 'FIELD_UNITS': Return only physical process units (U-01 to U-05)
    - 'SUPERVISORY': Return Level 2 & 3 systems (C-01, H-01, E-01, N-01)
    """
    assets = get_all_assets()
    if filter_mode == "ALL":
        return assets
    elif filter_mode == "ABNORMAL":
        return {
            k: v for k, v in assets.items()
            if v["operational_status"] != "ONLINE" or v["security_status"] != "SECURE"
        }
    elif filter_mode == "ALARMS":
        return {
            k: v for k, v in assets.items()
            if v["operational_status"] == "ALARM" or "ATTACK" in v["security_status"] or v["security_status"] == "COMPROMISED"
        }
    elif filter_mode == "FIELD_UNITS":
        return {k: v for k, v in assets.items() if k.startswith("U-")}
    elif filter_mode == "SUPERVISORY":
        return {k: v for k, v in assets.items() if not k.startswith("U-")}
    return assets

def get_facility_summary() -> Dict[str, Any]:
    """Calculate aggregated plant-wide operational and security metrics."""
    assets = get_all_assets()
    total_assets = len(assets)
    process_units = sum(1 for k in assets if k.startswith("U-"))
    online_count = sum(1 for v in assets.values() if v["operational_status"] == "ONLINE")
    warning_count = sum(1 for v in assets.values() if v["operational_status"] == "WARNING")
    alarm_count = sum(1 for v in assets.values() if v["operational_status"] == "ALARM")
    maintenance_count = sum(1 for v in assets.values() if v["operational_status"] == "MAINTENANCE")
    offline_count = sum(1 for v in assets.values() if v["operational_status"] == "OFFLINE")

    secure_assets = sum(1 for v in assets.values() if v["security_status"] == "SECURE")
    attack_assets = sum(1 for v in assets.values() if "ATTACK" in v["security_status"] or v["security_status"] == "COMPROMISED")
    anomaly_assets = sum(1 for v in assets.values() if v["security_status"] == "ANOMALY_DETECTED")

    return {
        "facility_name": FACILITY_NAME,
        "facility_location": FACILITY_LOCATION,
        "total_assets": total_assets,
        "process_units": process_units,
        "online_count": online_count,
        "warning_count": warning_count,
        "alarm_count": alarm_count,
        "maintenance_count": maintenance_count,
        "offline_count": offline_count,
        "secure_assets": secure_assets,
        "attack_assets": attack_assets,
        "anomaly_assets": anomaly_assets,
        "facility_health_pct": round((online_count / total_assets) * 100, 1)
    }
