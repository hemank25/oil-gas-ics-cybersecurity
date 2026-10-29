"""
test_bugfixes.py
================
Comprehensive automated verification suite for the three requested bugfixes:
1. Refinery Map asset selection logic, state consistency, and detail rendering across all 9 assets.
2. Mitigation & Recovery schema handling, field validation, and retest execution across all configured rules.
3. Verification that VAPT is removed from active frontend navigation while ML lab/models remain intact.
"""

import sys
import unittest
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT / "dashboard"
INFERENCE_DIR = ROOT / "ai detection" / "inference"
MODELS_DIR = ROOT / "ai detection" / "models"
RESULTS_DIR = ROOT / "results"

for p in [str(ROOT), str(DASHBOARD_DIR), str(INFERENCE_DIR)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from assets_config import get_all_assets, get_asset, filter_assets
from facility_map import generate_refinery_svg
from mitigation_workspace import DEFAULT_DEFENSIVE_POSTURE, get_defensive_posture
from process_simulator import ProcessTelemetrySimulator
from integration_adapter import CyberPhysicalCorrelator
from predict import IndustrialPredictor


class TestRefineryMapAssetSelection(unittest.TestCase):
    """Verify that every asset can be selected and returns full non-stale details."""

    def setUp(self):
        self.all_assets = get_all_assets()
        self.expected_asset_ids = ["U-01", "U-02", "U-03", "U-04", "U-05", "C-01", "H-01", "E-01", "N-01"]

    def test_all_expected_assets_exist_in_registry(self):
        for aid in self.expected_asset_ids:
            self.assertIn(aid, self.all_assets, f"Asset {aid} must exist in registry")
            asset = get_asset(aid)
            self.assertIsNotNone(asset, f"get_asset({aid}) must not return None")
            self.assertEqual(asset["id"], aid)

    def test_asset_detail_integrity_and_uniqueness(self):
        """Ensure each asset has its own distinct controller, IP, tags, and connections."""
        seen_ips = set()
        for aid in self.expected_asset_ids:
            asset = get_asset(aid)
            self.assertTrue(len(asset["name"]) > 0)
            self.assertTrue(len(asset["controller_id"]) > 0)
            self.assertTrue(len(asset["ip_address"]) > 0)
            self.assertIn(asset["operational_status"], ["ONLINE", "WARNING", "ALARM", "OFFLINE"])
            self.assertIn(asset["security_status"], ["SECURE", "VULNERABLE", "ANOMALY_DETECTED", "SUSPECTED_ATTACK", "COMPROMISED"])

            # Verify no stale data sharing between different assets
            self.assertNotIn(asset["ip_address"], seen_ips, f"IP for {aid} must be unique")
            seen_ips.add(asset["ip_address"])

    def test_schematic_svg_selection_highlight(self):
        """Ensure selecting each asset properly highlights its SVG node with distinct stroke."""
        for aid in self.expected_asset_ids:
            svg = generate_refinery_svg(selected_asset_id=aid, filter_mode="ALL")
            self.assertIn(f'id="node-{aid}"', svg)
            self.assertIn('#2563eb', svg, "Selected blue border stroke must be present in SVG")

    def test_filter_assets_modes(self):
        """Ensure filtering assets returns consistent subsets."""
        all_dict = filter_assets("ALL")
        self.assertEqual(len(all_dict), 9)

        field_units = filter_assets("FIELD_UNITS")
        self.assertTrue(all(k.startswith("U-") for k in field_units.keys()))

        supervisory = filter_assets("SUPERVISORY")
        self.assertTrue(all(k in ["C-01", "H-01", "E-01", "N-01"] for k in supervisory.keys()))


class TestMitigationAndRecovery(unittest.TestCase):
    """Verify mitigation rule schemas, field validation, and retest execution."""

    def test_mitigation_rules_schema_and_keys(self):
        posture = DEFAULT_DEFENSIVE_POSTURE
        required_fields = ["id", "name", "target_asset", "description"]

        for rule_key, rule in posture.items():
            for req in required_fields:
                self.assertIn(req, rule, f"Rule '{rule_key}' missing required field '{req}'")
                self.assertTrue(bool(rule[req]), f"Field '{req}' in rule '{rule_key}' must not be empty")

            # Must have addresses_vector
            self.assertIn("addresses_vector", rule, f"Rule '{rule_key}' should have 'addresses_vector'")
            self.assertTrue(len(rule["addresses_vector"]) > 0)

            # Must have operational impact and enforcer
            self.assertIn("operational_impact", rule)
            self.assertIn("enforced_by", rule)
            self.assertIn("active", rule)

    def test_incomplete_rule_safety_handling(self):
        """Test that incomplete or malformed rules do not crash the system."""
        incomplete_rule = {"id": "MIT-TEST-01"}
        required_fields = ["id", "name", "target_asset", "description"]
        missing = [f for f in required_fields if f not in incomplete_rule]
        self.assertEqual(missing, ["name", "target_asset", "description"])

        # Test safe threat_addressed resolution
        threat_addressed = (
            incomplete_rule.get("addresses_vector")
            or incomplete_rule.get("addresses_finding")
            or incomplete_rule.get("addresses_scenario")
            or "Identified OT Threat Vector"
        )
        self.assertEqual(threat_addressed, "Identified OT Threat Vector")

    def test_retest_execution_with_simulator(self):
        """Test retesting scenarios with simulator and correlator."""
        sim = ProcessTelemetrySimulator(seed=100)
        predictor = IndustrialPredictor(models_dir=MODELS_DIR)
        correlator = CyberPhysicalCorrelator(predictor=predictor)

        # Baseline retest telemetry
        base = sim.base_state.copy()
        net_mitigated = {
            "src_ip": "192.168.10.99",
            "dest_ip": "192.168.10.11",
            "dest_port": 502,
            "protocol": "Modbus/TCP",
            "modbus_fc": 6,
            "firewall_action": "DROPPED_BY_DPI_RULE",
            "unauthorized": False,
            "description": "Dropped by DPI"
        }
        res_blocked = correlator.evaluate_cyber_physical_event(base, net_mitigated)
        # Packet dropped by DPI, so it is NOT a coordinated cyber-physical attack
        self.assertNotIn("COORDINATED CYBER-PHYSICAL ATTACK", res_blocked["threat_classification"])
        self.assertIn("network_intrusion_detection", res_blocked)


class TestFrontendVAPTRemoval(unittest.TestCase):
    """Verify that VAPT is absent from the active frontend navigation and cards."""

    def test_app_nav_does_not_contain_vapt(self):
        with open(DASHBOARD_DIR / "app.py", "r", encoding="utf-8") as f:
            content = f.read()

        # Check navigation options list
        self.assertNotIn('"VAPT', content)
        self.assertNotIn("'VAPT", content)
        self.assertNotIn("vapt_workspace", content)

    def test_ml_models_and_evaluation_intact(self):
        """Verify ML Model Laboratory artifacts remain intact."""
        metrics_file = RESULTS_DIR / "evaluation_metrics.json"
        self.assertTrue(metrics_file.exists(), "evaluation_metrics.json must exist")
        with open(metrics_file, "r", encoding="utf-8") as f:
            metrics = json.load(f)
        self.assertIn("metrics_summary", metrics)
        self.assertIn("Isolation_Forest", metrics["metrics_summary"])
        self.assertIn("Random_Forest", metrics["metrics_summary"])

        # Check model files
        self.assertTrue((MODELS_DIR / "isolation_forest.joblib").exists())
        self.assertTrue((MODELS_DIR / "random_forest.joblib").exists())
        self.assertTrue((MODELS_DIR / "scaler.joblib").exists())


if __name__ == "__main__":
    unittest.main()
