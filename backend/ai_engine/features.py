"""
AlertIQ 2.0 - Phase 2 ML Feature Assembly
---------------------------------------------
Combines three sources into ONE feature dict matching
`ai_engine.dataset.FEATURE_COLUMNS` exactly:

  1. `extract_features(flow)`       - Phase 1 per-flow stats
  2. `BeaconTracker.stats(...)`     - cross-flow periodicity stats
  3. `RuleEngine.dns_features(...)` - live DNS activity for the source

Keeping this assembly in one place means the live engine and the
synthetic training dataset can never silently drift apart in shape.
"""
from __future__ import annotations

from ai_engine.dataset import FEATURE_COLUMNS
from packet_capture.feature_extractor import extract_features
from packet_capture.models import Flow


def extract_ml_features(
    flow: Flow,
    beacon_stats: dict | None = None,
    dns_stats: dict | None = None,
    dst_fanout_count: int = 0,
) -> dict:
    base = extract_features(flow)

    merged = {
        "duration": base["duration"],
        "packet_count": base["packet_count"],
        "byte_count": base["byte_count"],
        "packet_rate": base["packet_rate"],
        "bytes_per_second": base["bytes_per_second"],
        "fwd_packets": base["fwd_packets"],
        "bwd_packets": base["bwd_packets"],
        "fwd_bytes": base["fwd_bytes"],
        "bwd_bytes": base["bwd_bytes"],
        "fwd_bwd_packet_ratio": base["fwd_bwd_packet_ratio"],
        "syn_count": base["syn_count"],
        "ack_count": base["ack_count"],
        "fin_count": base["fin_count"],
        "rst_count": base["rst_count"],
        "syn_ack_ratio": base["syn_ack_ratio"],
        "ttl_mean": base["ttl_mean"],
        "ttl_stdev": base["ttl_stdev"],
        "distinct_dst_ports": base["distinct_dst_ports"],
        "dns_qname_len_mean": 0.0,
        "dns_query_rate": 0.0,
        "beacon_observation_count": 0,
        "beacon_interval_jitter": 1.0,   # 1.0 = "no periodicity signal" (max jitter default)
        "beacon_mean_bytes": base["byte_count"],
        "dst_fanout_count_for_src": dst_fanout_count,
    }

    if dns_stats:
        merged["dns_qname_len_mean"] = dns_stats.get("dns_qname_len_mean", 0.0)
        merged["dns_query_rate"] = dns_stats.get("dns_query_rate", 0.0)

    if beacon_stats:
        merged["beacon_observation_count"] = beacon_stats.get("observation_count", 0)
        merged["beacon_interval_jitter"] = beacon_stats.get("interval_jitter_ratio", 1.0)
        merged["beacon_mean_bytes"] = beacon_stats.get("mean_bytes", base["byte_count"])

    # Guarantee exact column order for model input.
    ordered = {col: merged[col] for col in FEATURE_COLUMNS}
    ordered["_flow_id"] = base["flow_id"]
    ordered["_src_ip"] = base["src_ip"]
    ordered["_dst_ip"] = base["dst_ip"]
    ordered["_dst_port"] = base["dst_port"]
    return ordered
