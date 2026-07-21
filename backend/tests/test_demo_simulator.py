"""
Verifies Demo Simulation Mode actually exercises real detection logic -
every one of the 12 scenarios must produce at least one Detection of the
expected attack_type, tagged demo=True. This is what makes Demo Mode
trustworthy: a passing demo is real evidence the detector works.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

MODELS_DIR = Path(__file__).resolve().parents[1] / "ai_engine" / "models_store"

from config import settings  # noqa: E402
from detection.demo_simulator import ML_SCENARIOS, RULE_SCENARIOS  # noqa: E402
from detection.rule_engine import RuleEngine  # noqa: E402


@pytest.fixture(autouse=True)
def reset_thresholds():
    """Demo scenarios are tuned against DEFAULT thresholds; reset in case
    an earlier test module mutated the shared settings object."""
    from config import RuleThresholds

    settings.rules.__dict__.update(RuleThresholds().__dict__)
    yield


@pytest.mark.parametrize("attack_type,simulator_fn", RULE_SCENARIOS.items())
def test_rule_based_demo_scenario_triggers_detection(attack_type, simulator_fn):
    engine = RuleEngine()
    detections = simulator_fn(engine)
    matching = [d for d in detections if d.attack_type == attack_type]
    assert matching, f"Demo scenario '{attack_type}' produced no matching detection: {[d.attack_type for d in detections]}"
    assert all(d.evidence.get("demo") is True for d in matching)


@pytest.mark.skipif(
    not (MODELS_DIR / "best_model.joblib").exists(),
    reason="ML models not trained - run ai_engine.train and ai_engine.anomaly first",
)
@pytest.mark.parametrize("attack_type,simulator_fn", ML_SCENARIOS.items())
def test_ml_based_demo_scenario_triggers_detection(attack_type, simulator_fn):
    from ai_engine.pipeline import MLPipeline

    pipeline = MLPipeline()
    detections = simulator_fn(pipeline)
    matching = [d for d in detections if d.attack_type == attack_type]
    assert matching, f"Demo scenario '{attack_type}' produced no matching detection: {[d.attack_type for d in detections]}"
    assert all(d.evidence.get("demo") is True for d in matching)
