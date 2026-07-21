"""
Unit tests for the Phase 2 ML pipeline - specifically the 3 attack types
that Phase 1's rule engine cannot cover: Malware Beaconing, Botnet
Communication, and Unknown Attack.

These tests require trained models. Run once before testing:
    python3 -m ai_engine.train
    python3 -m ai_engine.anomaly
"""
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

MODELS_DIR = Path(__file__).resolve().parents[1] / "ai_engine" / "models_store"
pytestmark = pytest.mark.skipif(
    not (MODELS_DIR / "best_model.joblib").exists(),
    reason="Models not trained yet - run `python3 -m ai_engine.train` and `python3 -m ai_engine.anomaly` first",
)

from ai_engine.pipeline import MLPipeline  # noqa: E402
from packet_capture.models import Flow, Protocol  # noqa: E402


def make_flow(src_ip, dst_ip, dst_port, start_time, fwd_bytes=500, packet_count=8, duration=0.3):
    flow = Flow(
        key=((src_ip, 40000), (dst_ip, dst_port), "TCP"),
        protocol=Protocol.TCP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=40000,
        dst_port=dst_port,
    )
    flow.start_time = start_time
    flow.last_seen = start_time + duration
    flow.fwd_bytes = fwd_bytes
    flow.bwd_bytes = fwd_bytes // 4
    flow.byte_count = flow.fwd_bytes + flow.bwd_bytes
    flow.packet_count = packet_count
    flow.fwd_packets = packet_count // 2
    flow.bwd_packets = packet_count - flow.fwd_packets
    flow.syn_count = 1
    flow.ack_count = 1
    flow.ttl_values = [64]
    flow.dst_ports_seen = {dst_port}
    return flow


@pytest.fixture(scope="module")
def pipeline():
    return MLPipeline()


def test_malware_beaconing_detected_from_periodic_flows(pipeline):
    """Simulate 15 near-identical, evenly-spaced connections from one
    infected host to ONE external C2 server - classic beacon behavior."""
    src, dst, port = "10.0.0.77", "203.0.113.50", 8443
    # Anchored at "now" rather than in the past: BeaconTracker prunes
    # history relative to real wall-clock time, so synthetic timestamps
    # need to stay within its rolling window relative to when the test
    # actually runs, not relative to some simulated past.
    base_time = time.time()

    all_detections = []
    for i in range(15):
        flow = make_flow(src, dst, port, start_time=base_time + i * 60, fwd_bytes=480, packet_count=6)
        all_detections += pipeline.evaluate_flow(flow)

    beacon_hits = [d for d in all_detections if d.attack_type == "Malware Beaconing"]
    assert beacon_hits, f"Expected Malware Beaconing detection, got: {[d.attack_type for d in all_detections]}"
    d = beacon_hits[0]
    assert d.source_ip == src
    assert d.confidence >= 0.75
    assert "shap_top_features" in d.evidence


def test_botnet_communication_detected_from_fanout_beaconing(pipeline):
    """Simulate one host periodically beaconing to SEVERAL distinct
    external hosts - the fan-out pattern that distinguishes botnet C2
    from a single infected-host-to-C2 beacon."""
    src = "10.0.0.88"
    destinations = [f"198.51.100.{n}" for n in range(1, 6)]
    base_time = time.time()

    all_detections = []
    for dst in destinations:
        for i in range(12):
            flow = make_flow(src, dst, 443, start_time=base_time + i * 45, fwd_bytes=300, packet_count=5)
            all_detections += pipeline.evaluate_flow(flow)

    botnet_hits = [d for d in all_detections if d.attack_type == "Botnet Communication"]
    assert botnet_hits, (
        f"Expected Botnet Communication detection from fan-out beaconing, "
        f"got: {[d.attack_type for d in all_detections]}"
    )
    assert botnet_hits[0].evidence["dst_fanout_count_for_src"] >= 3


def test_normal_traffic_produces_no_detections(pipeline):
    """A handful of ordinary, non-periodic, moderate-size flows should
    not trigger the classifier or the anomaly detector."""
    src, dst = "10.0.0.5", "93.184.216.34"
    detections = []
    for i in range(3):
        flow = make_flow(src, dst, 443, start_time=time.time() + i * 137.3, fwd_bytes=4000, packet_count=20, duration=2.5)
        detections += pipeline.evaluate_flow(flow)
    assert detections == []


def test_unknown_attack_flagged_for_statistically_abnormal_traffic(pipeline):
    """Construct a flow whose stats resemble nothing in the training
    set (extremely high TTL variance + unusual byte/packet ratio) and
    confirm the Isolation Forest flags it as Unknown Attack rather than
    silently passing it through."""
    flow = make_flow("10.0.0.99", "203.0.113.200", 31337, start_time=time.time(), fwd_bytes=17, packet_count=1, duration=0.01)
    flow.ttl_values = [1, 255, 3, 250, 5, 240]  # wildly abnormal TTL jitter
    flow.syn_count = 0
    flow.ack_count = 0

    detections = pipeline.evaluate_flow(flow)
    unknown_hits = [d for d in detections if d.attack_type == "Unknown Attack"]
    assert unknown_hits, f"Expected Unknown Attack, got: {[d.attack_type for d in detections]}"
    assert unknown_hits[0].category.value == "Unknown Threats"
    assert "top_deviations" in unknown_hits[0].evidence
