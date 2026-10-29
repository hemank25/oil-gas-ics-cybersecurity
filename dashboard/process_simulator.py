"""
process_simulator.py
====================
Deterministic Industrial Process Telemetry Simulator & Safe Attack Scenarios.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: Senior OT Cybersecurity Engineer & Simulation Specialist

Key Features:
1. Deterministic & Seeded: Demonstrations are 100% reproducible for academic examiners.
2. Physics-Consistent: Generates realistic fluctuations around nominal equilibrium.
3. Safe Attack Scenarios (A through F): Controlled, isolated cyber-physical manipulations.
4. Traceable Audit History: Every scenario execution produces a verifiable run record.
5. In-Memory Safety: Bounded event queues prevent unbounded memory growth.
"""

import time
import math
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
import numpy as np
import pandas as pd

from assets_config import ASSET_REGISTRY, get_asset, get_all_assets

class ProcessTelemetrySimulator:
    """
    Deterministic telemetry engine generating physically plausible process data
    for fictional refinery units U-01 to U-05.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.rng = np.random.default_rng(seed)
        self.step_count = 0
        self.is_running = True
        self.audit_log: List[Dict[str, Any]] = []
        self.max_audit_records = 200

        # Baseline steady-state values for all physical tags
        self.base_state = {
            # U-01: Crude Feed & Separation
            "P1_PCV01D": 27.94,   # Steam pressure valve demand (%)
            "P1_PCV01Z": 28.40,   # Valve position feedback (%)
            "P1_PIT01":  1.12,    # Column pressure (kPa)
            "P1_TIT01":  30.38,   # Column inflow temperature (°C)
            "P1_FCV01D": 32.12,   # Crude feed flow valve demand (%)

            # U-02: Water Treatment & Boiler
            "P1_LIT01":  349.36,  # Boiler drum level (mm)
            "P1_TIT02":  42.15,   # Superheater steam temp (°C)
            "P1_FCV02D": 29.50,   # Feedwater makeup valve demand (%)

            # U-03: Storage & Transfer
            "P2_24Vdc":  28.035,  # Safety bus DC voltage (V)
            "P2_AutoSD": 0.0,     # Auto shutdown arm (0 or 1)
            "P2_OnOff":  1.0,     # Transfer valve state (1=Open)

            # U-04: Rotating Equipment & Turbines
            "P4_ST_GOV": 18135.0, # Turbine governor speed (RPM)
            "P4_ST_TT01": 27.10,  # Bearing temp (°C)
            "P4_ST_LD":  65.40,   # Turbine load (kW)

            # U-05: Safety System (SIS)
            "P2_Emerg":  0.0,     # Emergency blowdown (0=Normal)
            "ESD_STATUS": 1.0     # Watchdog (1=Healthy)
        }

        # Active anomalies/overrides applied by attack simulations
        self.active_overrides: Dict[str, float] = {}
        self.controller_comms_status: Dict[str, str] = {
            "PLC-01-A": "HEALTHY",
            "PLC-01":   "HEALTHY",
            "PLC-02":   "HEALTHY",
            "PLC-04":   "HEALTHY",
            "TMR-SIS-01": "HEALTHY"
        }

    def generate_single_step(self, step_idx: Optional[int] = None) -> Dict[str, float]:
        """
        Generate a single deterministic time-step sample across all refinery tags.
        Adds subtle sinusoidal process oscillation + low-amplitude Gaussian noise.
        """
        if step_idx is None:
            self.step_count += 1
            idx = self.step_count
        else:
            idx = step_idx

        sample = {}
        for tag, base_val in self.base_state.items():
            # Check if an active attack override is present
            if tag in self.active_overrides:
                sample[tag] = self.active_overrides[tag]
                continue

            # Deterministic pseudo-random fluctuation based on seed + step + tag hash
            tag_seed = (self.seed + idx * 37 + hash(tag) % 1000) % (2**32)
            local_rng = np.random.default_rng(tag_seed)

            # Process oscillation (harmonic thermal/hydraulic cycle)
            cycle_phase = math.sin(idx * 0.08 + hash(tag) % 10)
            noise_amplitude = 0.004 * abs(base_val) if abs(base_val) > 0.1 else 0.001
            noise = local_rng.normal(0, noise_amplitude)

            val = base_val + (noise_amplitude * 1.5 * cycle_phase) + noise

            # Tag specific bounds and formatting
            if tag in ("P2_AutoSD", "P2_OnOff", "P2_Emerg", "ESD_STATUS"):
                sample[tag] = float(base_val)
            elif tag == "P4_ST_GOV":
                sample[tag] = round(val, 1)
            elif tag == "P2_24Vdc":
                sample[tag] = round(val, 3)
            else:
                sample[tag] = round(val, 2)

        return sample

    def generate_time_series(self, duration_steps: int = 60, interval_seconds: int = 1) -> pd.DataFrame:
        """
        Generate a deterministic historical time series dataframe for multi-pen trending.
        """
        now = datetime.now()
        start_time = now - timedelta(seconds=duration_steps * interval_seconds)

        records = []
        for i in range(duration_steps):
            t_stamp = start_time + timedelta(seconds=i * interval_seconds)
            step_data = self.generate_single_step(step_idx=i)
            step_data["timestamp"] = t_stamp.strftime("%H:%M:%S")
            records.append(step_data)

        return pd.DataFrame(records)

    def set_override(self, tag: str, value: float):
        """Set a simulated override value (e.g., from an attack scenario)."""
        self.active_overrides[tag] = value

    def clear_overrides(self):
        """Restore all process parameters to nominal equilibrium."""
        self.active_overrides.clear()
        for k in self.controller_comms_status:
            self.controller_comms_status[k] = "HEALTHY"

    # =========================================================================
    # PREDEFINED SAFE ATTACK SCENARIOS (A THROUGH F)
    # =========================================================================
    def get_available_scenarios(self) -> Dict[str, Dict[str, Any]]:
        """Return metadata for all 6 predefined deterministic attack scenarios."""
        return {
            "SCEN-A": {
                "id": "SCEN-A",
                "name": "Abnormal Process Telemetry: Column Overpressure & Heating",
                "category": "Physical Process Manipulation",
                "target_asset": "U-01",
                "target_controller": "PLC-01-A",
                "purdue_level": "Level 1: Basic Process Control",
                "description": "Simulates a forced override of the primary steam heating valve (P1_PCV01D) to 88.5%, driving column pressure (P1_PIT01) into high alarm (2.85 kPa).",
                "expected_observables": [
                    "P1_PCV01D demand increases from nominal 27.9% to 88.5%",
                    "P1_PIT01 overhead pressure rises from 1.12 kPa to 2.85 kPa (Alarm limit: 2.5 kPa)",
                    "P1_TIT01 temperature climbs from 30.4°C to 58.2°C",
                    "AI Isolation Forest flags multivariate physical correlation anomaly"
                ],
                "network_event": {
                    "src_ip": "192.168.10.99",
                    "dest_ip": "192.168.10.10",
                    "dest_port": 502,
                    "protocol": "Modbus/TCP",
                    "modbus_fc": 6,
                    "register": 40001,
                    "injected_value": 88.5,
                    "unauthorized": True,
                    "description": "Unauthorized Modbus Function 06 Write to steam valve register"
                },
                "telemetry_overrides": {
                    "P1_PCV01D": 88.5,
                    "P1_PCV01Z": 87.1,
                    "P1_PIT01": 2.85,
                    "P1_TIT01": 58.2
                }
            },
            "SCEN-B": {
                "id": "SCEN-B",
                "name": "Simulated Sensor Manipulation: Boiler Drum Level Drift & Freeze",
                "category": "Sensor Signal Tampering / Spoofing",
                "target_asset": "U-02",
                "target_controller": "PLC-01",
                "purdue_level": "Level 1: Basic Process Control",
                "description": "Simulates an adversary spoofing or freezing the differential pressure level transmitter (P1_LIT01) at 120 mm while actual makeup valve continues to feed water.",
                "expected_observables": [
                    "P1_LIT01 reports sudden collapse from 349 mm to 120 mm (Low trip limit: 200 mm)",
                    "Boiler makeup valve P1_FCV02D reacts with extreme compensatory demand (72.0%)",
                    "Physics limit check triggers: Level reading severely deviates from mass flow balance",
                    "High-priority advisory alert logged for Unit U-02"
                ],
                "network_event": {
                    "src_ip": "192.168.10.99",
                    "dest_ip": "192.168.10.11",
                    "dest_port": 502,
                    "protocol": "Modbus/TCP",
                    "modbus_fc": 16,
                    "register": 40020,
                    "injected_value": 120.0,
                    "unauthorized": True,
                    "description": "Modbus register clamp spoofing drum level sensor"
                },
                "telemetry_overrides": {
                    "P1_LIT01": 120.0,
                    "P1_FCV02D": 72.0
                }
            },
            "SCEN-C": {
                "id": "SCEN-C",
                "name": "Simulated Network Reconnaissance: Modbus & Service Discovery",
                "category": "Cyber Reconnaissance",
                "target_asset": "C-01",
                "target_controller": "SCADA-SRV-01",
                "purdue_level": "Level 2: Supervisory Network",
                "description": "Simulates unauthorized TCP SYN port scanning and Modbus slave ID enumeration originating from an untrusted subnet targeting refinery controllers.",
                "expected_observables": [
                    "Sequential connection attempts detected across ports 502, 102, 20000, 5900, 445",
                    "Nmap-style Modbus Device Identification probes received on PLC-01 (192.168.10.11)",
                    "Process physical variables remain nominal (no physical deviation yet)",
                    "SOC Correlator records pre-attack reconnaissance event"
                ],
                "network_event": {
                    "src_ip": "192.168.10.88",
                    "dest_ip": "192.168.10.0/24",
                    "dest_port": "502, 102, 5900, 445",
                    "protocol": "TCP SYN SCAN",
                    "unauthorized": True,
                    "description": "Nmap OT NSE reconnaissance sweep targeting ICS services"
                },
                "telemetry_overrides": {}  # Pure cyber reconnaissance, no physical alteration
            },
            "SCEN-D": {
                "id": "SCEN-D",
                "name": "Simulated Unauthorized Engineering Workstation Activity",
                "category": "Unauthorized Configuration / Lateral Movement",
                "target_asset": "E-01",
                "target_controller": "EWS-01",
                "purdue_level": "Level 2: Engineering & Configuration",
                "description": "Simulates an unapproved ladder logic modification or firmware download attempt from the Engineering Workstation outside scheduled maintenance windows.",
                "expected_observables": [
                    "Unauthorized SMBv2 session opened from unmanaged client host",
                    "PLC-01 program change contact triggered without MOC (Management of Change) authorization",
                    "Security Correlator flags unpatched SMB service and lateral movement vector on EWS-01"
                ],
                "network_event": {
                    "src_ip": "192.168.10.20",
                    "dest_ip": "192.168.10.11",
                    "dest_port": 102,
                    "protocol": "S7comm / SMB",
                    "unauthorized": True,
                    "description": "Unscheduled firmware / ladder logic block replacement"
                },
                "telemetry_overrides": {}
            },
            "SCEN-E": {
                "id": "SCEN-E",
                "name": "Simulated Loss of Controller Communication: PLC-01 Timeout",
                "category": "Denial of Service / Network Fault",
                "target_asset": "U-02",
                "target_controller": "PLC-01",
                "purdue_level": "Level 1: Basic Process Control",
                "description": "Simulates a network degradation or DoS flood rendering PLC-01 (Boiler Controller) unreachable from SCADA Host C-01.",
                "expected_observables": [
                    "SCADA Master reports Modbus connection timeout (Error: Gateway Target Device Failed)",
                    "Watchdog timer expires; telemetry health for U-02 drops from 100% to 0%",
                    "Failsafe alarm triggers on Operator HMI (H-01)"
                ],
                "network_event": {
                    "src_ip": "192.168.10.99",
                    "dest_ip": "192.168.10.11",
                    "dest_port": 502,
                    "protocol": "TCP SYN FLOOD",
                    "unauthorized": True,
                    "description": "Simulated Modbus connection exhaustion attack"
                },
                "telemetry_overrides": {},
                "comms_failure": "PLC-01"
            },
            "SCEN-F": {
                "id": "SCEN-F",
                "name": "Simulated Vulnerability Exploitation: Stuxnet Turbine Overspeed",
                "category": "Cyber-Physical Weaponization (Stuxnet-Style)",
                "target_asset": "U-04",
                "target_controller": "PLC-04",
                "purdue_level": "Level 1: Rotating Machinery",
                "description": "Simulates Stuxnet-style rotor speed perturbation driving Steam Turbine Governor (P4_ST_GOV) to 28,500 RPM while thrust bearing temperature surges to 74.0°C.",
                "expected_observables": [
                    "Turbine governor speed surges from nominal 18,135 RPM to 28,500 RPM (+57% overspeed)",
                    "Bearing temperature P4_ST_TT01 spikes from 27.1°C to 74.0°C (High trip: 65°C)",
                    "Dual-paradigm AI flags CRITICAL physical hazard with >90% attack confidence",
                    "Operator guidance demands immediate turbine trip and vibration analysis"
                ],
                "network_event": {
                    "src_ip": "192.168.10.20",
                    "dest_ip": "192.168.10.14",
                    "dest_port": 102,
                    "protocol": "S7comm",
                    "unauthorized": True,
                    "description": "Unauthorized S7comm write modifying variable frequency drive rotor parameters"
                },
                "telemetry_overrides": {
                    "P4_ST_GOV": 28500.0,
                    "P4_ST_TT01": 74.0,
                    "P4_ST_LD": 92.0
                }
            }
        }

    def execute_scenario(
        self,
        scenario_id: str,
        correlator: Any
    ) -> Dict[str, Any]:
        """
        Execute a predefined attack scenario through the full cyber-physical pipeline.
        Records an auditable, traceable run record.
        """
        scenarios = self.get_available_scenarios()
        if scenario_id not in scenarios:
            raise ValueError(f"Unknown scenario ID: {scenario_id}")

        scen = scenarios[scenario_id]
        run_id = f"RUN-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{scenario_id}"
        start_ts = datetime.now().isoformat()

        # Apply overrides to simulator
        overrides = scen.get("telemetry_overrides", {})
        for tag, val in overrides.items():
            self.set_override(tag, val)

        if "comms_failure" in scen:
            ctrl = scen["comms_failure"]
            self.controller_comms_status[ctrl] = "UNREACHABLE_TIMEOUT"

        # Generate telemetry sample reflecting the injected state
        current_telemetry = self.generate_single_step()
        net_event = scen.get("network_event", {})

        # Run through AI Cyber-Physical Correlator
        eval_result = correlator.evaluate_cyber_physical_event(
            process_telemetry=current_telemetry,
            network_event=net_event,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

        end_ts = datetime.now().isoformat()

        # Extract components safely from eval_result
        phys_det = eval_result.get("physical_ai_detection", {})
        alert_thresh = phys_det.get("alert_threshold", getattr(correlator.predictor, "threshold", 0.0132))
        top_devs = phys_det.get("top_deviating_sensors", phys_det.get("top_sensors", []))
        matched_vulns = eval_result.get("vapt_correlation", {}).get("known_vulnerabilities_on_targeted_assets", eval_result.get("correlated_vulnerabilities", []))

        # Build traceable event audit record
        audit_record = {
            "scenario_id": scen["id"],
            "scenario_name": scen["name"],
            "run_id": run_id,
            "category": scen["category"],
            "start_time": start_ts,
            "end_time": end_ts,
            "target_asset": scen["target_asset"],
            "target_controller": scen["target_controller"],
            "purdue_level": scen["purdue_level"],
            "input_telemetry": current_telemetry,
            "network_event": net_event,
            "expected_observables": scen["expected_observables"],
            "threat_classification": eval_result.get("threat_classification", "UNKNOWN"),
            "ai_prediction": phys_det.get("prediction", "UNKNOWN"),
            "ai_severity": phys_det.get("severity", "INFORMATIONAL"),
            "anomaly_score": phys_det.get("anomaly_score", 0.0),
            "alert_threshold": alert_thresh,
            "top_deviations": top_devs,
            "correlated_vulnerabilities": matched_vulns,
            "mitigation_status": "PENDING_MITIGATION" if "ATTACK" in eval_result.get("threat_classification", "") or "CRITICAL" in eval_result.get("threat_classification", "") else "N/A",
            "retest_status": "NOT_RETESTED"
        }

        # Keep bounded audit records
        self.audit_log.insert(0, audit_record)
        if len(self.audit_log) > self.max_audit_records:
            self.audit_log.pop()

        return audit_record

    def get_audit_history(self) -> List[Dict[str, Any]]:
        """Return all historical scenario run records."""
        return list(self.audit_log)
