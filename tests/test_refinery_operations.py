"""
test_refinery_operations.py
===========================
Comprehensive Integration & Verification Test Suite for MUJ Demo Refinery.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Center for a Simulated Oil & Gas Refinery
"""

import sys
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
INFERENCE_DIR = WORKSPACE_ROOT / "ai detection" / "inference"
MODELS_DIR = WORKSPACE_ROOT / "ai detection" / "models"
DASHBOARD_DIR = WORKSPACE_ROOT / "dashboard"
SIMULATION_DIR = WORKSPACE_ROOT / "simulation"

for p in [str(INFERENCE_DIR), str(DASHBOARD_DIR), str(SIMULATION_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from assets_config import get_all_assets, get_asset, filter_assets, get_facility_summary
from process_simulator import ProcessTelemetrySimulator
from predict import IndustrialPredictor
from integration_adapter import CyberPhysicalCorrelator

class TestRefineryOperations(unittest.TestCase):

    def setUp(self):
        self.simulator = ProcessTelemetrySimulator(seed=42)
        self.predictor = IndustrialPredictor(models_dir=MODELS_DIR)
        self.correlator = CyberPhysicalCorrelator(predictor=self.predictor)

    def test_asset_registry_integrity(self):
        """Verify all 9 assets exist with valid Purdue levels and tags."""
        assets = get_all_assets()
        self.assertEqual(len(assets), 9)
        self.assertIn("U-01", assets)
        self.assertIn("U-02", assets)
        self.assertIn("U-03", assets)
        self.assertIn("U-04", assets)
        self.assertIn("U-05", assets)
        self.assertIn("C-01", assets)
        self.assertIn("H-01", assets)
        self.assertIn("E-01", assets)
        self.assertIn("N-01", assets)

        # Verify U-01 tags
        u01 = assets["U-01"]
        tags = [t["tag"] for t in u01["tags"]]
        self.assertIn("P1_PCV01D", tags)
        self.assertIn("P1_PIT01", tags)

    def test_telemetry_simulation_deterministic(self):
        """Verify process simulator is deterministic and reproducible."""
        sim1 = ProcessTelemetrySimulator(seed=100)
        sim2 = ProcessTelemetrySimulator(seed=100)
        step1 = sim1.generate_single_step(step_idx=5)
        step2 = sim2.generate_single_step(step_idx=5)
        self.assertEqual(step1, step2)

    def test_ai_inference_normal_baseline(self):
        """Verify predictor scores normal baseline within safe bounds."""
        normal_data = {
            "P1_PCV01D": 27.94,
            "P1_PCV01Z": 28.40,
            "P1_PIT01": 1.12,
            "P1_FCV01D": 32.12
        }
        res = self.predictor.predict(normal_data)
        self.assertEqual(res["prediction"], "NORMAL")
        self.assertLess(res["anomaly_score"], res["alert_threshold"])

    def test_ai_inference_attack_excursion(self):
        """Verify predictor flags extreme actuator override."""
        attack_data = {
            "P1_PCV01D": 88.5,
            "P1_PCV01Z": 87.1,
            "P1_PIT01": 2.85,
            "P1_TIT01": 58.2
        }
        res = self.predictor.predict(attack_data)
        self.assertEqual(res["prediction"], "SUSPICIOUS")
        self.assertIn("CRITICAL", res["severity"])

    def test_scenarios_execution(self):
        """Verify all 6 scenarios execute through simulator and correlator."""
        scenarios = self.simulator.get_available_scenarios()
        self.assertEqual(len(scenarios), 6)
        for scen_id in ["SCEN-A", "SCEN-B", "SCEN-C", "SCEN-D", "SCEN-E", "SCEN-F"]:
            rec = self.simulator.execute_scenario(scen_id, self.correlator)
            self.assertEqual(rec["scenario_id"], scen_id)
            self.assertTrue(rec["run_id"].startswith("RUN-"))

    def test_facility_summary(self):
        """Verify facility summary aggregates accurately without VAPT keys."""
        summary = get_facility_summary()
        self.assertEqual(summary["total_assets"], 9)
        self.assertEqual(summary["process_units"], 5)
        self.assertNotIn("vulnerable_assets", summary)

if __name__ == "__main__":
    unittest.main()
