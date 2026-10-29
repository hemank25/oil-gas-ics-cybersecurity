"""
attack_simulation.py
====================
Phase 9: Controlled ICS Attack Simulation Suite (Student 3 Integration).

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: Attack Simulation Specialist & AI Integration (Student 3 Interface)

Safety & Authorization Protocols:
- STRICT AUTHORIZATION: All attacks are executed strictly within an isolated, simulated environment.
- NO EXTERNAL TRAFFIC: Real refinery networks or physical devices are never targeted.
- REPEATABLE PROTOTYPING: Generates realistic benign and malicious industrial process events.
"""

import time
import json
from pathlib import Path
from datetime import datetime
import numpy as np

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent

class RefineryAttackSimulator:
    """Generates benign and malicious ICS events for detection pipeline validation."""

    def __init__(self):
        # Baseline normal values derived from trained SCADA baseline statistics
        self.nominal_state = {
            "P1_PCV01D": 27.94,   # Boiler steam pressure valve demand (%)
            "P1_PCV01Z": 28.40,   # Valve actual position feedback (%)
            "P1_PIT01":  1.12,    # Pressure transmitter (kPa)
            "P1_FCV01D": 32.12,   # Inflow control valve demand (%)
            "P1_FCV01Z": 31.95,   # Inflow valve feedback (%)
            "P1_LIT01":  349.36,  # Drum water level (mm)
            "P1_TIT01":  30.38,   # Steam temperature (°C)
            "P4_ST_GOV": 18135.0, # Turbine governor speed (RPM)
            "P4_ST_TT01": 27106.0,# Turbine temperature reading
            "P2_24Vdc":  28.035   # Emergency 24V bus voltage (V)
        }

    def generate_benign_event(self) -> tuple:
        """Simulate realistic stochastic noise around steady-state normal equilibrium."""
        telemetry = {}
        for tag, val in self.nominal_state.items():
            # Small realistic fluctuation within 0.5%
            noise = float(np.random.normal(0, 0.005 * abs(val))) if tag != "P2_24Vdc" else 0.0
            telemetry[tag] = round(val + noise, 3)

        network_event = {
            "src_ip": "192.168.10.5",  # Authorized SCADA Master HMI
            "dest_ip": "192.168.10.11", # PLC-01
            "dest_port": 502,
            "protocol": "Modbus/TCP",
            "modbus_fc": 3,            # Read Holding Registers (benign polling)
            "unauthorized": False,
            "description": "Routine SCADA Master cyclic telemetry poll"
        }
        return telemetry, network_event

    def generate_valve_spoofing_attack(self) -> tuple:
        """Simulate an attacker injecting unauthorized Modbus writes to force valve open."""
        telemetry = self.nominal_state.copy()
        # Force valve demand to 88% while pressure rises to dangerous threshold
        telemetry["P1_PCV01D"] = 88.0
        telemetry["P1_PCV01Z"] = 86.5
        telemetry["P1_PIT01"]  = 2.95  # Acute overpressure
        telemetry["P1_TIT01"]  = 58.0  # Associated thermal increase

        network_event = {
            "src_ip": "192.168.10.99", # Rogue / Compromised Workstation
            "dest_ip": "192.168.10.11", # PLC-01 (Vulnerable Boiler Controller)
            "dest_port": 502,
            "protocol": "Modbus/TCP",
            "modbus_fc": 6,            # Preset Single Register (Unauthorized Write)
            "register": 40001,
            "injected_value": 88.0,
            "unauthorized": True,
            "description": "Exploiting unauthenticated Modbus service (VAPT-2026-001) to force valve setpoint"
        }
        return telemetry, network_event

    def generate_stuxnet_turbine_attack(self) -> tuple:
        """Simulate Stuxnet-style rotor speed perturbation while reporting false telemetry."""
        telemetry = self.nominal_state.copy()
        # Stuxnet alters rotor frequency converter to damaging resonant speed
        telemetry["P4_ST_GOV"] = 28500.0 # Extreme overspeed (Normal is 18,500 RPM)
        telemetry["P4_ST_TT01"] = 74.0   # Bearing temperature acute spike

        network_event = {
            "src_ip": "192.168.10.20", # Compromised Engineering Workstation (EWS-01)
            "dest_ip": "192.168.10.14", # PLC-04 (Turbine Speed Controller)
            "dest_port": 102,          # Siemens S7comm protocol
            "protocol": "S7comm",
            "unauthorized": True,
            "description": "Stuxnet-style firmware block replacement altering turbine variable frequency drive parameters"
        }
        return telemetry, network_event
