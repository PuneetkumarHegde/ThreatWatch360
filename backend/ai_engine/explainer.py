"""
AlertIQ 2.0 - Phase 2 SHAP Explainability
----------------------------------------------
Wraps SHAP's TreeExplainer around the trained best_model so every
supervised-model detection can answer "why was this flagged?" with the
top contributing features - exactly what the project spec's
Investigation page needs to show under "AI Explanation".
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import shap

from ai_engine.dataset import FEATURE_COLUMNS

MODELS_DIR = Path(__file__).parent / "models_store"

_READABLE_NAMES = {
    "duration": "Flow Duration",
    "packet_count": "Packet Count",
    "byte_count": "Byte Count",
    "packet_rate": "Packet Rate",
    "bytes_per_second": "Bytes/Second",
    "fwd_packets": "Forward Packets",
    "bwd_packets": "Backward Packets",
    "fwd_bytes": "Forward Bytes",
    "bwd_bytes": "Backward Bytes",
    "fwd_bwd_packet_ratio": "Fwd/Bwd Packet Ratio",
    "syn_count": "SYN Count",
    "ack_count": "ACK Count",
    "fin_count": "FIN Count",
    "rst_count": "RST Count",
    "syn_ack_ratio": "SYN:ACK Ratio",
    "ttl_mean": "Mean TTL",
    "ttl_stdev": "TTL Std Dev",
    "distinct_dst_ports": "Distinct Destination Ports",
    "dns_qname_len_mean": "DNS Query Name Length",
    "dns_query_rate": "DNS Query Rate",
    "beacon_observation_count": "Beacon Observation Count",
    "beacon_interval_jitter": "Beacon Interval Jitter",
    "beacon_mean_bytes": "Beacon Mean Bytes",
    "dst_fanout_count_for_src": "Destination Fan-Out Count",
}


class ShapExplainer:
    def __init__(self):
        model_path = MODELS_DIR / "best_model.joblib"
        encoder_path = MODELS_DIR / "label_encoder.joblib"
        if not model_path.exists():
            raise FileNotFoundError("No trained model found. Run: python3 -m ai_engine.train")

        self.model = joblib.load(model_path)
        self.encoder = joblib.load(encoder_path)
        self.explainer = shap.TreeExplainer(self.model)

    def explain(self, features: dict, predicted_class_index: int, top_n: int = 4) -> dict:
        """Returns top_n SHAP-ranked features pushing the prediction
        towards the predicted class, plus a human-readable sentence.
        """
        x = np.array([[float(features[c]) for c in FEATURE_COLUMNS]], dtype=np.float64)

        shap_values = self.explainer.shap_values(x)
        # shap_values shape handling: list-per-class (older API) vs 3D array (newer API)
        if isinstance(shap_values, list):
            class_shap = shap_values[predicted_class_index][0]
        else:
            arr = np.asarray(shap_values)
            if arr.ndim == 3:
                class_shap = arr[0, :, predicted_class_index]
            else:
                class_shap = arr[0]

        ranked = sorted(
            zip(FEATURE_COLUMNS, class_shap, x[0]),
            key=lambda t: abs(t[1]),
            reverse=True,
        )[:top_n]

        top_features = [
            {
                "feature": _READABLE_NAMES.get(name, name),
                "raw_feature": name,
                "shap_value": round(float(val), 4),
                "value": round(float(raw_val), 3),
                "direction": "increases" if val > 0 else "decreases",
            }
            for name, val, raw_val in ranked
        ]

        class_name = self.encoder.inverse_transform([predicted_class_index])[0]
        feature_phrases = ", ".join(
            f"{f['feature']}={f['value']} ({f['direction']} risk)" for f in top_features
        )
        explanation = (
            f"Classified as {class_name.replace('_', ' ').title()} primarily due to: "
            f"{feature_phrases}."
        )

        return {"top_features": top_features, "explanation": explanation}
