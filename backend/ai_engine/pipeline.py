"""
AlertIQ 2.0 - Phase 2 ML Pipeline
-------------------------------------
This is what actually closes the gap the user flagged: Malware
Beaconing, Botnet Communication, and Unknown Attack all require
statistical modeling, not signatures, and this module is where that
modeling happens - wired in as a second opinion AFTER the Phase 1 rule
engine on every flushed flow.

Flow:
    1. Update the BeaconTracker with this flow's timing/size.
    2. Assemble the canonical ML feature vector (features.py).
    3. Ask the trained classifier: is this SYN_FLOOD / DNS_TUNNELING /
       DATA_EXFILTRATION / MALWARE_BEACONING / BOTNET_C2 / BENIGN?
    4. If confidently NOT benign -> emit a Detection with a SHAP
       explanation and a computed risk score.
    5. If the classifier says BENIGN (or isn't confident) -> fall back
       to the Isolation Forest. If IT thinks the traffic is abnormal
       relative to known-benign traffic -> emit "Unknown Attack".

MALWARE_BEACONING vs BOTNET_C2 is decided by the classifier itself via
the `dst_fanout_count_for_src` feature (single persistent C2 destination
vs many), which is exactly the distinction a SOC analyst would look for.
"""
from __future__ import annotations

import logging

import joblib
import numpy as np

from ai_engine.anomaly import AnomalyDetector
from ai_engine.explainer import ShapExplainer
from ai_engine.features import extract_ml_features
from ai_engine.risk_score import compute_risk_score
from config import settings
from detection.beacon_tracker import BeaconTracker
from detection.trackers import Deduplicator
from packet_capture.models import AttackCategory, Detection, Flow, Severity

logger = logging.getLogger("alertiq.ml_pipeline")

_LABEL_META = {
    "SYN_FLOOD": {
        "attack_type": "SYN Flood",
        "category": AttackCategory.NETWORK_ATTACKS,
        "severity": Severity.CRITICAL,
    },
    "DNS_TUNNELING": {
        "attack_type": "DNS Tunneling",
        "category": AttackCategory.MALWARE_BEHAVIORS,
        "severity": Severity.HIGH,
    },
    "DATA_EXFILTRATION": {
        "attack_type": "Data Exfiltration",
        "category": AttackCategory.DATA_THEFT,
        "severity": Severity.CRITICAL,
    },
    "MALWARE_BEACONING": {
        "attack_type": "Malware Beaconing",
        "category": AttackCategory.MALWARE_BEHAVIORS,
        "severity": Severity.HIGH,
    },
    "BOTNET_C2": {
        "attack_type": "Botnet Communication",
        "category": AttackCategory.MALWARE_BEHAVIORS,
        "severity": Severity.CRITICAL,
    },
}

# Jitter ratio below this is considered "periodic enough" to count
# towards fan-out tracking (feeds dst_fanout_count_for_src feature).
_BEACON_LIKE_JITTER_THRESHOLD = 0.2

# Minimum classifier confidence required to trust a non-BENIGN prediction.
_ML_CONFIDENCE_THRESHOLD = 0.75


class MLPipeline:
    def __init__(self):
        from pathlib import Path

        models_dir = Path(__file__).parent / "models_store"
        self.model = joblib.load(models_dir / "best_model.joblib")
        self.encoder = joblib.load(models_dir / "label_encoder.joblib")
        self.shap_explainer = ShapExplainer()
        self.anomaly_detector = AnomalyDetector()
        self.beacon_tracker = BeaconTracker()
        self._dedup = Deduplicator(cooldown_seconds=45.0)
        logger.info("ML pipeline loaded (classifier=%s)", type(self.model).__name__)

    def evaluate_flow(self, flow: Flow, dns_stats: dict | None = None) -> list[Detection]:
        detections: list[Detection] = []

        self.beacon_tracker.record_flow(
            flow.src_ip, flow.dst_ip, flow.dst_port, flow.start_time, flow.fwd_bytes
        )
        beacon_stats = self.beacon_tracker.stats(flow.src_ip, flow.dst_ip, flow.dst_port)

        dst_fanout = self.beacon_tracker.fanout_count(flow.src_ip)
        if beacon_stats and beacon_stats["interval_jitter_ratio"] <= _BEACON_LIKE_JITTER_THRESHOLD:
            dst_fanout = self.beacon_tracker.mark_beacon_like(flow.src_ip, flow.dst_ip)

        features = extract_ml_features(
            flow, beacon_stats=beacon_stats, dns_stats=dns_stats, dst_fanout_count=dst_fanout
        )

        classifier_detection = self._run_classifier(flow, features)
        if classifier_detection:
            detections.append(classifier_detection)
            return detections  # classifier was confident; skip anomaly check

        if settings.enable_anomaly_detection:
            anomaly_detection = self._run_anomaly(flow, features)
            if anomaly_detection:
                detections.append(anomaly_detection)

        return detections

    # ------------------------------------------------------------------
    def _run_classifier(self, flow: Flow, features: dict) -> Detection | None:
        from ai_engine.dataset import FEATURE_COLUMNS

        x = np.array([[float(features[c]) for c in FEATURE_COLUMNS]], dtype=np.float64)
        proba = self.model.predict_proba(x)[0]
        idx = int(np.argmax(proba))
        confidence = float(proba[idx])
        label = self.encoder.inverse_transform([idx])[0]

        if label == "BENIGN" or confidence < _ML_CONFIDENCE_THRESHOLD:
            return None

        dedup_key = f"ml:{label}:{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}"
        if not self._dedup.should_emit(dedup_key):
            return None

        meta = _LABEL_META[label]
        shap_result = self.shap_explainer.explain(features, predicted_class_index=idx)
        shap_importance = min(sum(abs(f["shap_value"]) for f in shap_result["top_features"]), 1.0)

        risk = compute_risk_score(
            severity=meta["severity"].value,
            model_confidence=confidence,
            shap_importance=shap_importance,
            anomaly_score=0.0,
            destination_ip=flow.dst_ip,
        )

        return Detection(
            attack_type=meta["attack_type"],
            category=meta["category"],
            severity=meta["severity"],
            confidence=confidence,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            destination_port=flow.dst_port,
            evidence={
                "model": type(self.model).__name__,
                "risk_score": risk,
                "shap_top_features": shap_result["top_features"],
                "beacon_observation_count": features["beacon_observation_count"],
                "beacon_interval_jitter": features["beacon_interval_jitter"],
                "dst_fanout_count_for_src": features["dst_fanout_count_for_src"],
            },
            explanation=shap_result["explanation"],
        )

    def _run_anomaly(self, flow: Flow, features: dict) -> Detection | None:
        result = self.anomaly_detector.evaluate(features)
        if not result["is_anomaly"]:
            return None

        dedup_key = f"anomaly:{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}"
        if not self._dedup.should_emit(dedup_key):
            return None

        anomaly_score = result["anomaly_score"]
        severity = Severity.CRITICAL if anomaly_score > 0.75 else Severity.HIGH if anomaly_score > 0.5 else Severity.MEDIUM

        risk = compute_risk_score(
            severity=severity.value,
            model_confidence=anomaly_score,
            shap_importance=0.5,
            anomaly_score=anomaly_score,
            destination_ip=flow.dst_ip,
        )

        top = result["top_deviations"][:3]
        deviation_phrases = ", ".join(
            f"{d['feature']}={d['value']} (z={d['z_score']} vs benign avg {d['benign_mean']})" for d in top
        )

        return Detection(
            attack_type="Unknown Attack",
            category=AttackCategory.UNKNOWN_THREATS,
            severity=severity,
            confidence=anomaly_score,
            source_ip=flow.src_ip,
            destination_ip=flow.dst_ip,
            destination_port=flow.dst_port,
            evidence={
                "anomaly_score": anomaly_score,
                "risk_score": risk,
                "top_deviations": top,
            },
            explanation=(
                f"Traffic between {flow.src_ip} and {flow.dst_ip} did not match any known "
                f"attack signature or trained attack class, but scored as statistically "
                f"abnormal (anomaly score {anomaly_score}) compared to normal traffic on "
                f"this network. Most unusual: {deviation_phrases}."
            ),
        )
