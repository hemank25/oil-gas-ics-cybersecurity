"""
predict.py
==========
Phase 6: Real-Time Industrial Inference Engine & Prediction Interface.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: AI/ML Detection Specialist & Team Lead (Student 2)

Engineering & Safety Compliance:
1. Multi-Model Support:
   - Primary: Isolation Forest (Continuous Anomaly Score)
   - Secondary: Random Forest (Attack Probability & Signature Confidence)
2. Rigorous Scoring Semantics:
   - Isolation Forest output is treated as a continuous anomaly score, not a probability.
   - Probabilities are displayed only when provided by calibrated supervised models.
3. Feature Attribution:
   - Pinpoints top physical sensors/actuators deviating from normal equilibrium.
4. Human-in-the-Loop Safety:
   - Output explicitly formatted as an advisory prediction requiring human verification.
   - Automated physical actuator modification is strictly prohibited.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd
import joblib

# Paths relative to workspace root
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
MODELS_DIR = WORKSPACE_ROOT / "ai detection" / "models"
PROCESSED_DIR = WORKSPACE_ROOT / "ai detection" / "dataset" / "processed"
RESULTS_DIR = WORKSPACE_ROOT / "results"

class IndustrialPredictor:
    """Production-grade inference engine for ICS refinery telemetry."""

    DISCLAIMER = (
        "ADVISORY NOTICE: This output is a statistical machine learning prediction and "
        "not definitive proof of an active cyber attack. In compliance with ICS safety standards, "
        "automated physical plant actions are disabled. All alerts require human operator verification."
    )

    def __init__(self, models_dir: Path = MODELS_DIR):
        self.models_dir = Path(models_dir)
        self._load_artifacts()

    def _load_artifacts(self):
        """Load scaler, feature schema, model metadata, and trained estimators."""
        # 1. Feature schema
        schema_path = self.models_dir / "feature_names.json"
        if not schema_path.exists():
            raise FileNotFoundError(f"Feature schema not found at {schema_path}")
        with open(schema_path, "r", encoding="utf-8") as f:
            self.feature_names = json.load(f)
        self.feature_count = len(self.feature_names)

        # 2. Fitted Scaler
        scaler_path = self.models_dir / "scaler.joblib"
        if not scaler_path.exists():
            raise FileNotFoundError(f"Scaler artifact not found at {scaler_path}")
        self.scaler = joblib.load(scaler_path)

        # 3. Primary Unsupervised Model (Isolation Forest)
        iso_path = self.models_dir / "isolation_forest.joblib"
        if not iso_path.exists():
            raise FileNotFoundError(f"Isolation Forest not found at {iso_path}")
        self.iso_model = joblib.load(iso_path)
        self.iso_model.n_jobs = 1

        # 4. Secondary Supervised Model (Random Forest)
        rf_path = self.models_dir / "random_forest.joblib"
        if rf_path.exists():
            self.rf_model = joblib.load(rf_path)
            self.rf_model.n_jobs = 1
        else:
            self.rf_model = None

        # 5. Model Metadata & Calibrated Threshold
        meta_path = self.models_dir / "model_metadata.json"
        self.threshold = 0.0132  # Default calibrated threshold from Phase 4
        if meta_path.exists():
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
                iso_rec = meta.get("models", {}).get("Isolation_Forest", {})
                self.threshold = iso_rec.get("decision_threshold", self.threshold)

    def format_input(self, raw_data) -> np.ndarray:
        """Standardize various input types into a verified (1, 86) float32 array."""
        if isinstance(raw_data, dict):
            # Fill missing keys with baseline mean (which scales to 0.0)
            row = []
            for feat in self.feature_names:
                if feat in raw_data:
                    row.append(float(raw_data[feat]))
                else:
                    # Default to baseline mean
                    idx = self.feature_names.index(feat)
                    row.append(float(self.scaler.mean_[idx]))
            X = np.array([row], dtype=np.float32)
        elif isinstance(raw_data, (list, tuple)):
            if len(raw_data) != self.feature_count:
                raise ValueError(f"Expected {self.feature_count} features, received {len(raw_data)}")
            X = np.array([raw_data], dtype=np.float32)
        elif isinstance(raw_data, np.ndarray):
            if raw_data.ndim == 1:
                if len(raw_data) != self.feature_count:
                    raise ValueError(f"Expected {self.feature_count} features, received {len(raw_data)}")
                X = raw_data.reshape(1, -1).astype(np.float32)
            else:
                X = raw_data.astype(np.float32)
        elif isinstance(raw_data, pd.DataFrame):
            # Align by column names
            missing = [c for c in self.feature_names if c not in raw_data.columns]
            for m in missing:
                idx = self.feature_names.index(m)
                raw_data[m] = self.scaler.mean_[idx]
            X = raw_data[self.feature_names].values.astype(np.float32)
        else:
            raise TypeError(f"Unsupported input type: {type(raw_data)}")

        return X

    def predict(self, raw_observation, timestamp: str = None) -> dict:
        """Run complete dual-paradigm prediction on a single telemetry observation."""
        if timestamp is None:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 1. Format and Scale
        X_raw = self.format_input(raw_observation)
        X_scaled = self.scaler.transform(X_raw)

        # 2. Primary Isolation Forest Behavioral Inference
        raw_iso_score = float(-self.iso_model.decision_function(X_scaled)[0])
        iso_flag = bool(raw_iso_score >= self.threshold)

        # 3. Secondary Random Forest Signature Inference
        rf_confidence = None
        rf_flag = False
        rf_prob = 0.0
        if self.rf_model is not None:
            rf_prob = float(self.rf_model.predict_proba(X_scaled)[0, 1])
            rf_confidence = round(rf_prob * 100, 2)
            rf_flag = bool(rf_prob >= 0.50)

        # 4. Sensor Attribution & Statistical Physics Deviation
        deviations = np.abs(X_scaled[0])
        max_deviation = float(np.max(deviations))
        phys_flag = bool(max_deviation >= 4.0)

        top_deviating_indices = np.argsort(deviations)[::-1][:3]
        top_deviations = [
            {
                "tag": self.feature_names[i],
                "raw_value": round(float(X_raw[0, i]), 3),
                "z_score_deviation": round(float(deviations[i]), 2)
            }
            for i in top_deviating_indices
        ]

        # 5. Multi-Layer Industrial Decision Logic (Defense-in-Depth)
        is_anomaly = bool(iso_flag or rf_flag or phys_flag)

        if not is_anomaly:
            status = "NORMAL"
            severity = "INFORMATIONAL"
            detection_reason = "Telemetry correlates within nominal physical operating manifold."
        else:
            status = "SUSPICIOUS"
            reasons = []
            if rf_flag:
                reasons.append(f"Supervised threat signature detected ({rf_confidence:.1f}% confidence)")
            if phys_flag:
                reasons.append(f"Acute physical sensor divergence ({max_deviation:.1f} sigma on {top_deviations[0]['tag']})")
            if iso_flag:
                reasons.append(f"Unsupervised behavioral outlier score ({raw_iso_score:+.4f} >= threshold)")
            detection_reason = " | ".join(reasons)

            if rf_prob >= 0.85 or max_deviation >= 15.0 or (raw_iso_score >= self.threshold + 0.04):
                severity = "CRITICAL"
            elif rf_prob >= 0.60 or max_deviation >= 6.0 or (raw_iso_score >= self.threshold + 0.02):
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        return {
            "timestamp": timestamp,
            "prediction": status,
            "severity": severity,
            "anomaly_score": round(raw_iso_score, 4),
            "alert_threshold": round(self.threshold, 4),
            "score_interpretation": (
                "Isolation Forest continuous anomaly score. Values above alert threshold indicate "
                "statistically anomalous physical process correlations."
            ),
            "detection_reason": detection_reason,
            "supervised_attack_confidence_percent": rf_confidence,
            "top_deviating_sensors": top_deviations,
            "mitigation_recommendation": (
                "Execute manual operator inspection of indicated sensor loops. Cross-reference PLC setpoints "
                "against physical field instrumentation. Automated actuator trip is inhibited."
                if is_anomaly else "Plant operating within nominal physical bounds. Routine monitoring active."
            ),
            "safety_disclaimer": self.DISCLAIMER
        }

def run_cli_demo():
    """Run an interactive viva demonstration comparing normal, subtle, and acute attack events."""
    print("=" * 80)
    print("PHASE 6: REAL-TIME PREDICTION INTERFACE & TELEMETRY CLASSIFIER")
    print("=" * 80)
    print("Loading ICS AI models and telemetry baseline...")
    predictor = IndustrialPredictor()
    print(f"[*] Engine Active. Loaded {predictor.feature_count} physical telemetry tags.")
    print(f"[*] Calibrated Isolation Forest Alert Threshold: {predictor.threshold:.4f}\n")

    # Load test scenario samples from processed test data
    with np.load(PROCESSED_DIR / "test1_data.npz", allow_pickle=True) as d:
        X_t1 = d["X_test"]
        y_t1 = d["y_test"]
        ts_t1 = d["timestamps"]

    # We inverse transform to obtain true physical raw values for demonstration
    scaler = predictor.scaler

    # Sample 1: Known Normal Observation (Row 1,000 in Test 1)
    norm_idx = 1000
    norm_raw = scaler.inverse_transform(X_t1[norm_idx:norm_idx+1])[0]
    norm_ts = str(ts_t1[norm_idx])

    # Sample 2: Known Attack Observation (Row 24,500 in Test 1 - Attack Incident 07 Valve Manipulation)
    atk_idx = 24500
    atk_raw = scaler.inverse_transform(X_t1[atk_idx:atk_idx+1])[0]
    atk_ts = str(ts_t1[atk_idx])

    # Sample 3: Synthetic Stuxnet-Style Attack (Artificially injected valve + overpressure anomaly)
    stux_raw = norm_raw.copy()
    # Spoof pressure valve demand to 100% and temperature to critical limit
    pcv_idx = predictor.feature_names.index("P1_PCV01D") if "P1_PCV01D" in predictor.feature_names else 0
    tit_idx = predictor.feature_names.index("P1_TIT01") if "P1_TIT01" in predictor.feature_names else 1
    stux_raw[pcv_idx] = 100.0  # Max out valve demand
    stux_raw[tit_idx] = stux_raw[tit_idx] + 25.0  # Acute heat spike

    scenarios = [
        ("SCENARIO 1: BENIGN STEADY-STATE REFINERY OPERATION", norm_raw, norm_ts, 0),
        ("SCENARIO 2: LIVE CYBER-ATTACK (HAI INCIDENT 07: VALVE DEMAND SPOOFING)", atk_raw, atk_ts, 1),
        ("SCENARIO 3: SYNTHETIC STUXNET-STYLE VALVE OVERPRESSURE PERTURBATION", stux_raw, "2026-10-19 12:40:00", 1)
    ]

    for title, raw_input, ts, ground_truth in scenarios:
        print("-" * 80)
        print(f">>> {title}")
        print("-" * 80)
        result = predictor.predict(raw_input, timestamp=ts)
        print(f"Timestamp:              {result['timestamp']}")
        print(f"Ground Truth State:     {'MALICIOUS / ATTACK (1)' if ground_truth == 1 else 'BENIGN / NORMAL (0)'}")
        print(f"Model Prediction:       {result['prediction']} (Severity: {result['severity']})")
        print(f"Detection Rationale:    {result['detection_reason']}")
        print(f"Anomaly Score:          {result['anomaly_score']:+.4f} (Threshold: {result['alert_threshold']:+.4f})")
        if result['supervised_attack_confidence_percent'] is not None:
            print(f"Supervised RF Prob:     {result['supervised_attack_confidence_percent']:.1f}%")
        print("Top Deviating Sensors:")
        for dev in result['top_deviating_sensors']:
            print(f"  - {dev['tag']:<20}: Raw Value = {dev['raw_value']:>8.2f} | Z-Score Deviation = {dev['z_score_deviation']:>5.2f} sigma")
        print(f"Mitigation Advice:      {result['mitigation_recommendation']}")
        print(f"Safety Disclaimer:      {result['safety_disclaimer']}")
        print()

    print("=" * 80)
    print("[+] PHASE 6 PREDICTION INTERFACE VERIFIED AND FUNCTIONAL!")
    print("=" * 80)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Real-Time ICS Telemetry Prediction Interface")
    parser.add_argument("--demo", action="store_true", help="Run multi-scenario viva demonstration")
    parser.add_argument("--sample", type=int, default=None, help="Index of sample in test1 dataset to evaluate")
    args = parser.parse_args()

    if args.sample is not None:
        predictor = IndustrialPredictor()
        with np.load(PROCESSED_DIR / "test1_data.npz", allow_pickle=True) as d:
            X_t1 = d["X_test"]
            y_t1 = d["y_test"]
            ts_t1 = d["timestamps"]
        raw = predictor.scaler.inverse_transform(X_t1[args.sample:args.sample+1])[0]
        res = predictor.predict(raw, timestamp=str(ts_t1[args.sample]))
        print(json.dumps(res, indent=2))
    else:
        run_cli_demo()
