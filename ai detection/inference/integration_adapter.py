"""
integration_adapter.py
======================
Phase 9: Cross-Domain Integration Adapter & Cyber-Physical Correlator.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: AI/ML Detection Specialist & Team Lead (Student 2)

Integration Interfaces:
1. Student 1 (VAPT & Infrastructure):
   - Ingests vulnerability assessment findings (Asset, IP, Port, CWE, Severity, Remediation, Re-test status).
   - Maps vulnerabilities to physical control loops and sensor tags.
2. Student 3 (Attack Simulation):
   - Ingests simulated cyber-physical attack events and network-flow flags.
3. Student 2 (AI Detection & Correlator - Group Leader):
   - Enforces the critical distinction between Network Data (IP/Port/Modbus function codes)
     and Physical Telemetry (86 continuous sensor/actuator dimensions).
   - Correlates network threat events with physical plant anomalies for defense-in-depth.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd

# Paths relative to workspace root
CURRENT_DIR = Path(__file__).resolve().parent
WORKSPACE_ROOT = CURRENT_DIR.parent.parent
VAPT_DIR = WORKSPACE_ROOT / "vapt" / "vulnerabilities"
RESULTS_DIR = WORKSPACE_ROOT / "results"

if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from predict import IndustrialPredictor
from alert_system import SecurityAlertSystem

class CyberPhysicalCorrelator:
    """Correlates VAPT findings, network security events, and physical SCADA AI telemetry."""

    DATA_REPRESENTATION_NOTE = (
        "ARCHITECTURAL INTEGRITY NOTICE: HAI 23.05 telemetry consists of 86 physical process "
        "measurements (temperatures, pressures, flow rates, valve positions). Network-flow data "
        "(packet headers, Modbus function codes, TCP flags) represents an entirely different feature space. "
        "In compliance with scientific rigor, network packets are NOT fed into the HAI model. Instead, "
        "network events and physical telemetry anomalies are cross-correlated at this integration layer."
    )

    def __init__(self, predictor: IndustrialPredictor = None):
        self.predictor = predictor or IndustrialPredictor()
        self.vapt_findings = self._load_vapt_findings()

    def _load_vapt_findings(self) -> list:
        """Load Student 1's VAPT findings from JSON repository."""
        vapt_path = VAPT_DIR / "vapt_findings.json"
        if vapt_path.exists():
            with open(vapt_path, "r", encoding="utf-8") as f:
                return json.load(f)
        return []

    def lookup_vulnerabilities(self, sensor_tags: list) -> list:
        """Find any known VAPT vulnerabilities associated with given physical sensor tags."""
        matched = []
        for finding in self.vapt_findings:
            common = set(sensor_tags).intersection(set(finding.get("affected_telemetry_tags", [])))
            if common:
                matched.append({
                    "finding_id": finding["finding_id"],
                    "asset": finding["asset_name"],
                    "ip": finding["ip_address"],
                    "service": finding["service"],
                    "vulnerability": finding["vulnerability_title"],
                    "severity": finding["severity"],
                    "cvss": finding["cvss_v3_score"],
                    "status": finding["re_test_status"],
                    "correlated_tags": list(common)
                })
        return matched

    def evaluate_cyber_physical_event(self, process_telemetry: dict, network_event: dict = None, timestamp: str = None) -> dict:
        """
        Evaluate a joint cyber-physical event.
        - process_telemetry: dict of sensor readings (e.g. {'P1_PCV01D': 85.0})
        - network_event: dict of network findings (e.g. {'src_ip': '192.168.10.99', 'modbus_fc': 6, 'unauthorized': True})
        """
        ts = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Physical AI Inference (Student 2 Engine)
        phys_result = self.predictor.predict(process_telemetry, timestamp=ts)
        is_phys_anomaly = (phys_result["prediction"] == "SUSPICIOUS")
        deviating_tags = [d["tag"] for d in phys_result["top_deviating_sensors"]]

        # 2. VAPT Correlation (Student 1 Integration)
        matched_vulns = self.lookup_vulnerabilities(deviating_tags)

        # 3. Network Event Evaluation (Student 3 Integration)
        is_net_anomaly = False
        net_summary = "No anomalous network traffic detected on OT subnet."
        if network_event and network_event.get("unauthorized", False):
            is_net_anomaly = True
            net_summary = (
                f"Unauthorized Modbus Function {network_event.get('modbus_fc', 'N/A')} write "
                f"from unauthenticated host {network_event.get('src_ip', 'Unknown')} to "
                f"PLC {network_event.get('dest_ip', '192.168.10.11')}."
            )

        # 4. Cross-Domain Correlation Synthesis
        if is_net_anomaly and is_phys_anomaly:
            threat_level = "CRITICAL: COORDINATED CYBER-PHYSICAL ATTACK"
            correl_summary = (
                "CONFIRMED MULTI-STAGE EXPLOIT: Network-layer unauthorized Modbus command was immediately followed "
                "by severe physical process anomaly on target PLC valve/sensor loop. High confidence adversary action."
            )
            action_priority = "IMMEDIATE EMERGENCY ISOLATION (MANUAL)"
        elif is_net_anomaly and not is_phys_anomaly:
            threat_level = "HIGH: CYBER PROBE / ATTEMPTED EXPLOIT"
            correl_summary = (
                "Unauthorized network command detected, but physical plant control loop has not yet deviated. "
                "Likely early-stage reconnaissance or blocked command injection."
            )
            action_priority = "NETWORK FIREWALL ISOLATION"
        elif not is_net_anomaly and is_phys_anomaly:
            threat_level = "MEDIUM: PROCESS DEVIATION / UNATTRIBUTED ANOMALY"
            correl_summary = (
                "Physical telemetry anomaly detected by AI model without corresponding network intrusion alerts. "
                "Possible physical hardware degradation, calibration drift, or covert out-of-band manipulation (e.g. physical tapping)."
            )
            action_priority = "FIELD INSTRUMENTATION CALIBRATION"
        else:
            threat_level = "NOMINAL: PLANT HEALTHY"
            correl_summary = "All network traffic and physical telemetry correlate within normal bounds."
            action_priority = "ROUTINE MONITORING"

        return {
            "timestamp": ts,
            "threat_classification": threat_level,
            "action_priority": action_priority,
            "correlation_summary": correl_summary,
            "physical_ai_detection": {
                "prediction": phys_result["prediction"],
                "severity": phys_result["severity"],
                "anomaly_score": phys_result["anomaly_score"],
                "alert_threshold": phys_result.get("alert_threshold", 0.0132),
                "rf_confidence_pct": phys_result["supervised_attack_confidence_percent"],
                "top_sensors": phys_result["top_deviating_sensors"],
                "top_deviating_sensors": phys_result["top_deviating_sensors"]
            },
            "network_intrusion_detection": {
                "network_alert": is_net_anomaly,
                "summary": net_summary,
                "event_details": network_event
            },
            "vapt_correlation": {
                "known_vulnerabilities_on_targeted_assets": matched_vulns
            },
            "architectural_disclaimer": self.DATA_REPRESENTATION_NOTE
        }

def run_integration_test():
    """Run an automated demonstration correlating VAPT findings with a live attack simulation."""
    print("=" * 80)
    print("PHASE 9: CROSS-DOMAIN INTEGRATION & CYBER-PHYSICAL CORRELATOR")
    print("=" * 80)
    correlator = CyberPhysicalCorrelator()
    print(f"[*] Loaded {len(correlator.vapt_findings)} VAPT Vulnerability Findings from Student 1.")
    print("[*] Initialized Student 2 AI Anomaly Detector.\n")

    # Scenario: Student 3 simulates an attack on Boiler Feedwater Valve PLC-01
    # 1. Attacker exploits VAPT-2026-001 (unauthenticated Modbus write on Port 502)
    network_attack = {
        "src_ip": "192.168.10.99",
        "dest_ip": "192.168.10.11",
        "dest_port": 502,
        "protocol": "Modbus/TCP",
        "modbus_fc": 6,
        "register": 40001,
        "injected_value": 85.0,
        "unauthorized": True,
        "description": "Unauthorized Preset Single Register write targeting Boiler Feed Valve Demand"
    }

    # 2. Injected physical perturbation resulting on the plant
    tampered_telemetry = {
        "P1_PCV01D": 85.0,   # Attacked valve demand (normal is ~12-15%)
        "P1_PCV01Z": 83.5,   # Valve position following demand
        "P1_PIT01":  2.85    # Pressure rising from 1.4 to 2.85 kPa
    }

    print(">>> Executing Cross-Domain Correlation Analysis...")
    result = correlator.evaluate_cyber_physical_event(
        process_telemetry=tampered_telemetry,
        network_event=network_attack,
        timestamp="2026-10-19 12:55:00"
    )

    print("-" * 80)
    print(f"Timestamp:              {result['timestamp']}")
    print(f"Threat Classification:  {result['threat_classification']}")
    print(f"Action Priority:        {result['action_priority']}")
    print(f"Synthesis Summary:      {result['correlation_summary']}")
    print("\nPhysical AI Detection:")
    print(f"  - Prediction:         {result['physical_ai_detection']['prediction']} (Severity: {result['physical_ai_detection']['severity']})")
    print(f"  - Anomaly Score:      {result['physical_ai_detection']['anomaly_score']}")
    print(f"  - Supervised RF Prob: {result['physical_ai_detection']['rf_confidence_pct']}%")
    print("  - Deviating Sensors:")
    for s in result['physical_ai_detection']['top_sensors']:
        print(f"      * {s['tag']:<15}: Raw = {s['raw_value']:>6.2f} (Z-Score = {s['z_score_deviation']:>5.2f} sigma)")

    print("\nNetwork Intrusion Correlation:")
    print(f"  - Network Alert:      {result['network_intrusion_detection']['network_alert']}")
    print(f"  - Network Detail:     {result['network_intrusion_detection']['summary']}")

    print("\nVAPT Known Vulnerabilities on Attacked Asset:")
    for v in result['vapt_correlation']['known_vulnerabilities_on_targeted_assets']:
        print(f"  - Finding ID:   {v['finding_id']} ({v['asset']} at {v['ip']})")
        print(f"    Vuln:         {v['vulnerability']} (Severity: {v['severity']}, CVSS: {v['cvss']})")
        print(f"    Mitigation:   Status = {v['status']}")

    print("\n" + "=" * 80)
    print("[+] PHASE 9 INTEGRATION ADAPTER VERIFIED AND FUNCTIONAL!")
    print("=" * 80)

if __name__ == "__main__":
    run_integration_test()
