"""
alert_system.py
===============
Phase 7: Industrial Security Alert System & Incident Workflow.

Academic Context:
- Course: 5th-Semester ICS Cybersecurity Project, Manipal University Jaipur
- Project: AI-Assisted Cybersecurity Framework for a Simulated Oil & Gas Refinery
- Role: AI/ML Detection Specialist & Team Lead (Student 2)

Workflow Architecture:
  Input Observation -> Model Inference -> Multi-Layer Decision Rule -> Security Alert Record

ICS Safety & Operational Mandates:
1. Separation of Alerting from Physical Actuation:
   - The alert engine generates advisory records for control room operators.
   - It NEVER automatically modifies PLC logic, actuates trip valves, or halts pumps.
2. Comprehensive Audit Trail:
   - Every alert is tagged with a unique UUID, timestamp, severity, anomaly score,
     affected refinery unit, deviating sensors, and actionable remediation checklist.
3. Incident Aggregation:
   - Groups continuous 1.0 Hz anomalous seconds into cohesive Security Incident episodes
     to prevent control room alarm fatigue.
4. Dual Persistence:
   - JSON Lines (`results/security_alerts.jsonl`) for SIEM/SOC log ingestion.
   - Tabular CSV (`results/security_alerts.csv`) for operator spreadsheets.
"""

import os
import sys
import json
import uuid
import time
from pathlib import Path
from datetime import datetime
import numpy as np
import pandas as pd

# Add current directory to path for local imports
CURRENT_DIR = Path(__file__).resolve().parent
if str(CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(CURRENT_DIR))

from predict import IndustrialPredictor

# Paths relative to workspace root
WORKSPACE_ROOT = CURRENT_DIR.parent.parent
PROCESSED_DIR = WORKSPACE_ROOT / "ai detection" / "dataset" / "processed"
RESULTS_DIR = WORKSPACE_ROOT / "results"

# Physical refinery subsystem mapping
SUBSYSTEM_MAP = {
    "P1": "Process Unit 1: Water Treatment & Steam Boiler Feed Loop",
    "P2": "Process Unit 2: Storage Tanks & Emergency Isolation Loop",
    "P3": "Process Unit 3: Auxiliary Heat Exchanger & Cooling Loop",
    "P4": "Process Unit 4: Rotating Equipment & Turbine Drive",
    "x1001": "Supervisory Controller: Interlock Loop 1",
    "x1002": "Supervisory Controller: Interlock Loop 2",
    "x1003": "Supervisory Controller: Multi-Loop Setpoint Sum"
}

def identify_subsystems(deviating_tags: list) -> list:
    """Map deviating physical sensor tags to plant units."""
    subsystems = set()
    for tag in deviating_tags:
        prefix = tag.split("_")[0]
        subsystems.add(SUBSYSTEM_MAP.get(prefix, f"Field Controller Subsystem ({prefix})"))
    return sorted(list(subsystems))

def generate_remediation_advice(severity: str, subsystems: list, top_sensor: str) -> str:
    """Generate specific, non-disruptive mitigation actions for human operators."""
    actions = [
        f"1. Dispatch field operator to visually inspect instrumentation loop around '{top_sensor}'.",
        "2. Cross-reference SCADA HMI values against physical pressure/temperature gauges.",
        "3. Review Engineering Workstation audit logs for unauthorized PLC ladder logic changes."
    ]
    if severity == "CRITICAL":
        actions.append("4. Prepare manual bypass line if pneumatic actuator displays mechanical oscillation.")
        actions.append("5. Notify Plant Cybersecurity Incident Response Team (CSIRT).")
    elif severity == "HIGH":
        actions.append("4. Monitor secondary transmitters for correlation drift.")
    return " | ".join(actions)

class SecurityAlertSystem:
    """Industrial Cyber Security Alert System for Refinery SCADA."""

    def __init__(self, predictor: IndustrialPredictor = None):
        self.predictor = predictor if predictor is not None else IndustrialPredictor()
        self.alert_history = []
        self.incident_history = []

    def evaluate_observation(self, raw_data, timestamp: str = None) -> dict:
        """Run observation through inference engine and generate alert if anomalous."""
        result = self.predictor.predict(raw_data, timestamp=timestamp)

        if result["prediction"] == "SUSPICIOUS":
            alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
            deviating_tags = [d["tag"] for d in result["top_deviating_sensors"]]
            subsystems = identify_subsystems(deviating_tags)
            top_sensor = deviating_tags[0] if deviating_tags else "Unknown"

            alert_record = {
                "alert_id": alert_id,
                "timestamp": result["timestamp"],
                "detection_result": "SUSPICIOUS_ACTIVITY_DETECTED",
                "severity": result["severity"],
                "detection_rationale": result["detection_reason"],
                "anomaly_score": result["anomaly_score"],
                "alert_threshold": result["alert_threshold"],
                "supervised_attack_confidence_percent": result["supervised_attack_confidence_percent"],
                "affected_subsystems": subsystems,
                "deviating_sensors": result["top_deviating_sensors"],
                "primary_deviating_sensor": top_sensor,
                "mitigation_recommendation": generate_remediation_advice(result["severity"], subsystems, top_sensor),
                "operator_status": "UNACKNOWLEDGED",
                "safety_disclaimer": result["safety_disclaimer"]
            }
            self.alert_history.append(alert_record)
            return alert_record
        else:
            return None

    def process_telemetry_stream(self, X_stream: np.ndarray, timestamps: list, y_true: list = None) -> dict:
        """Process a continuous stream of telemetry, generating alerts and grouping incidents."""
        n_samples = len(X_stream)
        alerts_generated = []
        active_incident = None
        incidents = []

        print(f"[*] Processing telemetry stream of {n_samples:,d} sequential observations...")

        # Vectorized batch transformation and scoring for maximum speed
        X_scaled = self.predictor.scaler.transform(X_stream)
        iso_scores = -self.predictor.iso_model.decision_function(X_scaled)
        rf_probs = (
            self.predictor.rf_model.predict_proba(X_scaled)[:, 1]
            if self.predictor.rf_model is not None
            else np.zeros(n_samples, dtype=np.float32)
        )
        deviations = np.abs(X_scaled)
        max_deviations = np.max(deviations, axis=1)

        threshold = self.predictor.threshold
        feature_names = self.predictor.feature_names

        for i in range(n_samples):
            raw_iso_score = float(iso_scores[i])
            rf_prob = float(rf_probs[i])
            rf_confidence = round(rf_prob * 100, 2)
            max_dev = float(max_deviations[i])

            iso_flag = bool(raw_iso_score >= threshold)
            rf_flag = bool(rf_prob >= 0.50)
            phys_flag = bool(max_dev >= 4.0)

            is_anomaly = bool(iso_flag or rf_flag or phys_flag)

            ts = str(timestamps[i])
            true_label = int(y_true[i]) if y_true is not None else None

            if is_anomaly:
                # Sensor attribution
                top_indices = np.argsort(deviations[i])[::-1][:3]
                top_deviations = [
                    {
                        "tag": feature_names[idx],
                        "raw_value": round(float(X_stream[i, idx]), 3),
                        "z_score_deviation": round(float(deviations[i, idx]), 2)
                    }
                    for idx in top_indices
                ]
                deviating_tags = [d["tag"] for d in top_deviations]
                subsystems = identify_subsystems(deviating_tags)
                top_sensor = deviating_tags[0] if deviating_tags else "Unknown"

                # Severity
                if rf_prob >= 0.85 or max_dev >= 15.0 or (raw_iso_score >= threshold + 0.04):
                    severity = "CRITICAL"
                elif rf_prob >= 0.60 or max_dev >= 6.0 or (raw_iso_score >= threshold + 0.02):
                    severity = "HIGH"
                else:
                    severity = "MEDIUM"

                reasons = []
                if rf_flag:
                    reasons.append(f"Supervised threat signature detected ({rf_confidence:.1f}% confidence)")
                if phys_flag:
                    reasons.append(f"Acute physical sensor divergence ({max_dev:.1f} sigma on {top_sensor})")
                if iso_flag:
                    reasons.append(f"Unsupervised behavioral outlier score ({raw_iso_score:+.4f} >= threshold)")
                detection_reason = " | ".join(reasons)

                alert_id = f"ALT-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"

                alert = {
                    "alert_id": alert_id,
                    "timestamp": ts,
                    "detection_result": "SUSPICIOUS_ACTIVITY_DETECTED",
                    "severity": severity,
                    "detection_rationale": detection_reason,
                    "anomaly_score": round(raw_iso_score, 4),
                    "alert_threshold": round(threshold, 4),
                    "supervised_attack_confidence_percent": rf_confidence,
                    "affected_subsystems": subsystems,
                    "deviating_sensors": top_deviations,
                    "primary_deviating_sensor": top_sensor,
                    "mitigation_recommendation": generate_remediation_advice(severity, subsystems, top_sensor),
                    "operator_status": "UNACKNOWLEDGED",
                    "ground_truth_label": true_label,
                    "safety_disclaimer": self.predictor.DISCLAIMER
                }
                alerts_generated.append(alert)
                self.alert_history.append(alert)

                # Incident grouping (continuous anomaly seconds)
                if active_incident is None:
                    active_incident = {
                        "incident_id": f"INC-{len(incidents)+1:03d}",
                        "start_time": ts,
                        "end_time": ts,
                        "duration_seconds": 1,
                        "peak_severity": severity,
                        "peak_anomaly_score": round(raw_iso_score, 4),
                        "peak_supervised_prob": rf_confidence,
                        "subsystems": set(subsystems),
                        "flagged_sensors": {top_sensor},
                        "alert_count": 1
                    }
                else:
                    active_incident["end_time"] = ts
                    active_incident["duration_seconds"] += 1
                    active_incident["alert_count"] += 1
                    active_incident["subsystems"].update(subsystems)
                    active_incident["flagged_sensors"].add(top_sensor)
                    if raw_iso_score > active_incident["peak_anomaly_score"]:
                        active_incident["peak_anomaly_score"] = round(raw_iso_score, 4)
                    if rf_confidence > active_incident["peak_supervised_prob"]:
                        active_incident["peak_supervised_prob"] = rf_confidence
                    if severity == "CRITICAL":
                        active_incident["peak_severity"] = "CRITICAL"
            else:
                if active_incident is not None:
                    active_incident["subsystems"] = sorted(list(active_incident["subsystems"]))
                    active_incident["flagged_sensors"] = sorted(list(active_incident["flagged_sensors"]))
                    incidents.append(active_incident)
                    active_incident = None

        if active_incident is not None:
            active_incident["subsystems"] = sorted(list(active_incident["subsystems"]))
            active_incident["flagged_sensors"] = sorted(list(active_incident["flagged_sensors"]))
            incidents.append(active_incident)

        self.incident_history.extend(incidents)

        return {
            "total_observations_evaluated": n_samples,
            "total_alerts_generated": len(alerts_generated),
            "total_incidents_grouped": len(incidents),
            "alerts": alerts_generated,
            "incidents": incidents
        }

    def save_alerts(self, jsonl_path: Path = None, csv_path: Path = None):
        """Save generated alert records to JSON Lines and CSV."""
        if not self.alert_history:
            print("[!] No alerts in memory to save.")
            return

        jsonl_path = jsonl_path or RESULTS_DIR / "security_alerts.jsonl"
        csv_path = csv_path or RESULTS_DIR / "security_alerts.csv"

        RESULTS_DIR.mkdir(parents=True, exist_ok=True)

        # 1. Save JSONL
        with open(jsonl_path, "w", encoding="utf-8") as f:
            for alert in self.alert_history:
                f.write(json.dumps(alert) + "\n")
        print(f"[+] Saved {len(self.alert_history):,d} alert records to: {jsonl_path.name}")

        # 2. Save CSV (Flattened)
        flattened = []
        for a in self.alert_history:
            flattened.append({
                "alert_id": a["alert_id"],
                "timestamp": a["timestamp"],
                "severity": a["severity"],
                "anomaly_score": a["anomaly_score"],
                "supervised_prob_pct": a["supervised_attack_confidence_percent"],
                "subsystems": "; ".join(a["affected_subsystems"]),
                "primary_sensor": a["primary_deviating_sensor"],
                "detection_rationale": a["detection_rationale"],
                "operator_status": a["operator_status"]
            })
        df_alerts = pd.DataFrame(flattened)
        df_alerts.to_csv(csv_path, index=False)
        print(f"[+] Saved tabular alert log to: {csv_path.name}")

def run_alert_demo():
    """Run an end-to-end alert demonstration on a live attack telemetry window."""
    print("=" * 80)
    print("PHASE 7: SECURITY ALERT SYSTEM & INCIDENT WORKFLOW")
    print("=" * 80)
    print(f"Timestamp:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Initializing ICS Security Alert Engine...")
    alert_sys = SecurityAlertSystem()

    # Load a focused telemetry slice around Attack Incident 07 (Rows 24,300 to 25,200 = 900 seconds)
    with np.load(PROCESSED_DIR / "test1_data.npz", allow_pickle=True) as d:
        X_t1 = d["X_test"]
        y_t1 = d["y_test"]
        ts_t1 = d["timestamps"]

    # Reconstruct raw telemetry for realistic field simulator
    start_row, end_row = 24350, 25100
    slice_X_scaled = X_t1[start_row:end_row]
    slice_y = y_t1[start_row:end_row]
    slice_ts = ts_t1[start_row:end_row]

    slice_X_raw = alert_sys.predictor.scaler.inverse_transform(slice_X_scaled)

    print(f"[*] Simulating real-time SCADA telemetry ingest ({len(slice_X_raw)} seconds)...")
    summary = alert_sys.process_telemetry_stream(slice_X_raw, slice_ts, y_true=slice_y)

    print(f"\n[+] Ingestion Summary:")
    print(f"    - Observations Analyzed:   {summary['total_observations_evaluated']:,d}")
    print(f"    - Security Alerts Emitted: {summary['total_alerts_generated']:,d}")
    print(f"    - Distinct Incidents:      {summary['total_incidents_grouped']}")

    # Display Top Incident Card
    if summary["incidents"]:
        inc = summary["incidents"][0]
        print("\n" + "=" * 80)
        print(f"ACTIVE SECURITY INCIDENT CARD: [{inc['incident_id']}]")
        print("=" * 80)
        print(f"Incident ID:         {inc['incident_id']}")
        print(f"Timespan:            {inc['start_time']} to {inc['end_time']} ({inc['duration_seconds']} seconds)")
        print(f"Peak Severity:       {inc['peak_severity']}")
        print(f"Peak Anomaly Score:  {inc['peak_anomaly_score']:+.4f}")
        print(f"Peak Supervised RF:  {inc['peak_supervised_prob']:.1f}%")
        print(f"Refinery Subsystems: {', '.join(inc['subsystems'])}")
        print(f"Targeted Sensors:    {', '.join(inc['flagged_sensors'])}")
        print(f"Total Alert Events:  {inc['alert_count']}")
        print("-" * 80)

    # Display Sample Individual Alert
    if summary["alerts"]:
        a = summary["alerts"][0]
        print("\nSAMPLE ALERT RECORD (HMI / SIEM DISPATCH):")
        print(json.dumps(a, indent=2))

    # Persist alerts to disk
    alert_sys.save_alerts()

    # Save incident summary report
    inc_report_path = RESULTS_DIR / "incident_summary.json"
    with open(inc_report_path, "w", encoding="utf-8") as f:
        json.dump(summary["incidents"], f, indent=2)
    print(f"[+] Saved incident aggregation report to: {inc_report_path.name}")
    print("=" * 80)

if __name__ == "__main__":
    run_alert_demo()
