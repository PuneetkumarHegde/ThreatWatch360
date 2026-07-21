"""
AlertIQ 2.0 - Phase 2 Risk Score (0-100)
--------------------------------------------
Combines:
  - Model confidence      (classifier predict_proba, or 1.0 for rule engine)
  - Attack severity        (static weight per attack type)
  - SHAP / evidence weight (how strongly the top features stood out)
  - Anomaly score          (0 for known attacks, isolation-forest score for Unknown)
  - Asset criticality      (destination IP importance - gateway/servers > regular hosts)

into a single 0-100 score used across Dashboard, Threats, and Investigation pages.
"""
from __future__ import annotations

_SEVERITY_WEIGHT = {
    "LOW": 0.25,
    "MEDIUM": 0.5,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}

# Simple, overridable-later criticality map. In Phase 3 this becomes a
# per-device field set from the Devices page instead of a static dict.
_DEFAULT_ASSET_CRITICALITY = 0.5
CRITICAL_ASSET_IPS: set[str] = set()  # e.g. populate with your server/gateway IPs


def asset_criticality(ip: str | None) -> float:
    if ip and ip in CRITICAL_ASSET_IPS:
        return 1.0
    return _DEFAULT_ASSET_CRITICALITY


def compute_risk_score(
    *,
    severity: str,
    model_confidence: float = 1.0,
    shap_importance: float = 0.5,
    anomaly_score: float = 0.0,
    destination_ip: str | None = None,
) -> int:
    """All inputs except `severity` are expected in [0, 1]. Returns an
    integer 0-100 risk score.

    Weighting rationale: severity and model confidence dominate (they
    most directly answer "how bad, how sure"), asset criticality and
    SHAP/anomaly evidence act as modifiers.
    """
    sev_w = _SEVERITY_WEIGHT.get(severity.upper(), 0.5)
    crit_w = asset_criticality(destination_ip)

    score = (
        0.35 * sev_w
        + 0.30 * model_confidence
        + 0.15 * min(shap_importance, 1.0)
        + 0.10 * anomaly_score
        + 0.10 * crit_w
    ) * 100

    return int(round(min(max(score, 0), 100)))
