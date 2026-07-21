"""
AlertIQ 2.0 - Phase 2 Anomaly Detection (Unknown Attack)
--------------------------------------------------------------
Trains an Isolation Forest on BENIGN-only flow features. Anything that
doesn't match any of the 9 rule-engine signatures AND isn't classified
confidently by the supervised model (train.py) is scored against this
forest. A low isolation score (i.e. "easy to isolate" = abnormal) means
the traffic looks statistically unlike anything we've labeled - this is
what the project spec calls "Unknown Attack".

Explainability without SHAP-on-IsolationForest (SHAP's TreeExplainer
does not reliably support sklearn's IsolationForest): we instead report
the features with the largest z-score deviation from the benign
training distribution. This is simple, fast, and just as legible as
"why was this flagged" - e.g. "packet_rate is 8.3 standard deviations
above normal".
"""
from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from ai_engine.dataset import FEATURE_COLUMNS, generate_dataset

MODELS_DIR = Path(__file__).parent / "models_store"
MODELS_DIR.mkdir(exist_ok=True)

ANOMALY_MODEL_PATH = MODELS_DIR / "isolation_forest.joblib"
BENIGN_STATS_PATH = MODELS_DIR / "benign_feature_stats.json"


def train_isolation_forest(n_benign: int = 3000, contamination: float = 0.03, seed: int = 42) -> None:
    """Train on synthetic BENIGN data only (see ai_engine/dataset.py for
    why synthetic data is used in this environment, and how to swap in
    real captured benign traffic later without touching this code)."""
    df = generate_dataset(n_per_class=n_benign, seed=seed)
    benign = df[df["label"] == "BENIGN"][FEATURE_COLUMNS]
    X = np.asarray(benign.values, dtype=np.float64)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X)
    joblib.dump(model, ANOMALY_MODEL_PATH)

    stats = {
        "mean": benign.mean().to_dict(),
        "std": (benign.std() + 1e-9).to_dict(),  # avoid div-by-zero downstream
    }
    BENIGN_STATS_PATH.write_text(json.dumps(stats, indent=2))
    print(f"Isolation Forest trained on {len(X)} benign samples, contamination={contamination}")
    print(f"Saved -> {ANOMALY_MODEL_PATH}")


class AnomalyDetector:
    """Runtime wrapper: load once, call `.evaluate(features_dict)` per flow."""

    def __init__(self):
        if not ANOMALY_MODEL_PATH.exists():
            raise FileNotFoundError(
                "Isolation Forest model not found. Run: python3 -m ai_engine.anomaly"
            )
        self.model: IsolationForest = joblib.load(ANOMALY_MODEL_PATH)
        stats = json.loads(BENIGN_STATS_PATH.read_text())
        self.benign_mean = stats["mean"]
        self.benign_std = stats["std"]

    def evaluate(self, features: dict) -> dict:
        """
        Args:
            features: dict with (at least) all keys in FEATURE_COLUMNS
                       (extra `_`-prefixed metadata keys are ignored).
        Returns:
            {
              "is_anomaly": bool,
              "anomaly_score": float,   # higher = more anomalous, roughly 0-1
              "top_deviations": [ {"feature": ..., "z_score": ..., "value": ..., "benign_mean": ...}, ... ]
            }
        """
        x = np.array([[float(features[c]) for c in FEATURE_COLUMNS]], dtype=np.float64)

        raw_score = self.model.score_samples(x)[0]  # higher = more normal
        prediction = self.model.predict(x)[0]  # 1 = normal, -1 = anomaly
        # Normalize score_samples (~[-0.6, -0.3] typically) into an
        # intuitive 0-1 "anomaly_score" where higher = more anomalous.
        anomaly_score = float(np.clip((-raw_score - 0.3) / 0.3, 0.0, 1.0))

        deviations = []
        for c in FEATURE_COLUMNS:
            mean = self.benign_mean.get(c, 0.0)
            std = self.benign_std.get(c, 1.0) or 1.0
            z = (float(features[c]) - mean) / std
            deviations.append({
                "feature": c,
                "z_score": round(float(z), 2),
                "value": features[c],
                "benign_mean": round(mean, 2),
            })
        deviations.sort(key=lambda d: abs(d["z_score"]), reverse=True)

        return {
            "is_anomaly": bool(prediction == -1),
            "anomaly_score": round(anomaly_score, 3),
            "top_deviations": deviations[:5],
        }


if __name__ == "__main__":
    train_isolation_forest()
