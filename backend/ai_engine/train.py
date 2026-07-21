"""
AlertIQ 2.0 - Phase 2 Model Training & Comparison
------------------------------------------------------
Trains 4 candidate classifiers on the synthetic flow-feature dataset,
evaluates each on a held-out test split (Accuracy, macro Precision/Recall/
F1, macro ROC-AUC, confusion matrix), and automatically selects the best
model by macro F1 (a reasonable default for a multi-class, roughly
balanced security dataset - it doesn't let one easy class inflate the
score the way plain accuracy can).

Run:
    python3 -m ai_engine.train

Outputs (into ai_engine/models_store/):
    best_model.joblib          - the winning classifier
    label_encoder.joblib       - label <-> int mapping
    feature_columns.json       - exact column order the model expects
    metrics_report.json        - full comparison table + confusion matrices
    training_summary.txt       - human-readable summary
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, label_binarize

from ai_engine.dataset import FEATURE_COLUMNS, generate_dataset

MODELS_DIR = Path(__file__).parent / "models_store"
MODELS_DIR.mkdir(exist_ok=True)


def _build_candidates(random_state: int = 42) -> dict:
    import lightgbm as lgb
    import xgboost as xgb
    from catboost import CatBoostClassifier

    return {
        "RandomForest": RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=random_state, n_jobs=-1
        ),
        "XGBoost": xgb.XGBClassifier(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            random_state=random_state,
            eval_metric="mlogloss",
            n_jobs=-1,
            verbosity=0,
        ),
        "CatBoost": CatBoostClassifier(
            iterations=200,
            depth=6,
            learning_rate=0.1,
            random_state=random_state,
            verbose=False,
        ),
        "LightGBM": lgb.LGBMClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            random_state=random_state,
            verbosity=-1,
        ),
    }


def _evaluate(model, X_test, y_test, classes: list[str]) -> dict:
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    y_test_bin = label_binarize(y_test, classes=list(range(len(classes))))
    try:
        roc_auc = roc_auc_score(y_test_bin, y_proba, average="macro", multi_class="ovr")
    except ValueError:
        roc_auc = float("nan")

    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(classes))))

    return {
        "accuracy": round(float(accuracy_score(y_test, y_pred)), 4),
        "precision_macro": round(float(precision_score(y_test, y_pred, average="macro", zero_division=0)), 4),
        "recall_macro": round(float(recall_score(y_test, y_pred, average="macro", zero_division=0)), 4),
        "f1_macro": round(float(f1_score(y_test, y_pred, average="macro", zero_division=0)), 4),
        "roc_auc_macro": round(float(roc_auc), 4) if roc_auc == roc_auc else None,  # NaN check
        "confusion_matrix": cm.tolist(),
        "classes": classes,
    }


def train_and_select_best(n_per_class: int = 1500, seed: int = 42) -> dict:
    print("[1/4] Generating synthetic training dataset...")
    df = generate_dataset(n_per_class=n_per_class, seed=seed)

    encoder = LabelEncoder()
    y = encoder.fit_transform(df["label"])
    X = np.asarray(df[FEATURE_COLUMNS].values, dtype=np.float64)
    classes = list(encoder.classes_)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=seed, stratify=y
    )

    print(f"[2/4] Training {len(X_train)} samples across {len(classes)} classes: {classes}")
    candidates = _build_candidates(seed)

    results = {}
    trained_models = {}
    for name, model in candidates.items():
        t0 = time.time()
        model.fit(X_train, y_train)
        elapsed = round(time.time() - t0, 2)
        metrics = _evaluate(model, X_test, y_test, classes)
        metrics["train_time_seconds"] = elapsed
        results[name] = metrics
        trained_models[name] = model
        print(
            f"    {name:<14} acc={metrics['accuracy']:.4f}  "
            f"f1_macro={metrics['f1_macro']:.4f}  "
            f"roc_auc={metrics['roc_auc_macro']}  ({elapsed}s)"
        )

    print("[3/4] Selecting best model by macro F1...")
    best_name = max(results, key=lambda n: results[n]["f1_macro"])
    best_model = trained_models[best_name]
    print(f"    -> Best model: {best_name} (f1_macro={results[best_name]['f1_macro']})")

    print("[4/4] Saving artifacts...")
    joblib.dump(best_model, MODELS_DIR / "best_model.joblib")
    joblib.dump(encoder, MODELS_DIR / "label_encoder.joblib")
    (MODELS_DIR / "feature_columns.json").write_text(json.dumps(FEATURE_COLUMNS, indent=2))

    report = {
        "best_model": best_name,
        "selection_metric": "f1_macro",
        "trained_at": time.time(),
        "n_per_class": n_per_class,
        "results": results,
    }
    (MODELS_DIR / "metrics_report.json").write_text(json.dumps(report, indent=2))

    summary_lines = [
        "AlertIQ 2.0 - Model Training Summary",
        "=" * 50,
        f"Classes: {classes}",
        f"Samples per class: {n_per_class}",
        "",
        f"{'Model':<14}{'Accuracy':<12}{'F1(macro)':<12}{'ROC-AUC':<10}{'Time(s)'}",
    ]
    for name, m in sorted(results.items(), key=lambda kv: -kv[1]["f1_macro"]):
        summary_lines.append(
            f"{name:<14}{m['accuracy']:<12}{m['f1_macro']:<12}{m['roc_auc_macro']}{'':<4}{m['train_time_seconds']}"
        )
    summary_lines += ["", f"SELECTED MODEL: {best_name}", ""]
    (MODELS_DIR / "training_summary.txt").write_text("\n".join(summary_lines))
    print("\n".join(summary_lines))

    return report


if __name__ == "__main__":
    train_and_select_best()
