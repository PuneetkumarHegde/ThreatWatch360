"""
AlertIQ 2.0 - Phase 2 Dataset Generator
-------------------------------------------
Generates a labeled, synthetic-but-realistic flow-feature dataset for
training the supervised classifier and the Isolation Forest baseline.

WHY SYNTHETIC: this environment has no access to a labeled PCAP corpus
(CICIDS2017/2018 etc. require multi-GB downloads from restricted hosts,
and running real attacks against a real network isn't something this
build environment can do). Instead we generate statistically realistic
flow feature vectors *in the exact schema produced by
`packet_capture.feature_extractor.extract_features()` plus the beacon/
fan-out features from `detection.beacon_engine`* — the same schema the
live engine produces. This means:

  1. The trained model's input contract exactly matches production data.
  2. Swapping this generator for a real labeled dataset later (e.g. after
     capturing your own attack/benign traffic with Phase 1, or loading
     CICIDS2017) requires ZERO changes to train.py, pipeline.py, or the
     feature schema — only this file changes.

Classes generated (BENIGN + 5 attack classes handled by ML/anomaly,
as opposed to the 9 attack classes already covered by the deterministic
rule engine in Phase 1):

  BENIGN, SYN_FLOOD, DNS_TUNNELING, DATA_EXFILTRATION,
  MALWARE_BEACONING, BOTNET_C2

Everything the model does NOT recognize confidently, and that also looks
statistically abnormal relative to BENIGN, falls to the Isolation Forest
as "Unknown Attack" (see anomaly.py).
"""
from __future__ import annotations

import numpy as np
import pandas as pd

# Canonical feature column order used everywhere in Phase 2. This list
# MUST match the keys produced by ai_engine.features.extract_ml_features().
FEATURE_COLUMNS = [
    "duration",
    "packet_count",
    "byte_count",
    "packet_rate",
    "bytes_per_second",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "fwd_bwd_packet_ratio",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "syn_ack_ratio",
    "ttl_mean",
    "ttl_stdev",
    "distinct_dst_ports",
    "dns_qname_len_mean",
    "dns_query_rate",
    "beacon_observation_count",
    "beacon_interval_jitter",
    "beacon_mean_bytes",
    "dst_fanout_count_for_src",
]

LABELS = [
    "BENIGN",
    "SYN_FLOOD",
    "DNS_TUNNELING",
    "DATA_EXFILTRATION",
    "MALWARE_BEACONING",
    "BOTNET_C2",
]


def _clip(arr, lo, hi=None):
    arr = np.clip(arr, lo, hi if hi is not None else np.inf)
    return arr


def _base_benign(n: int, rng: np.random.Generator) -> pd.DataFrame:
    duration = rng.uniform(0.5, 40, n)
    packet_count = _clip(rng.normal(30, 20, n), 1)
    byte_count = packet_count * rng.uniform(60, 1200, n)
    fwd_packets = _clip(packet_count * rng.uniform(0.4, 0.6, n), 1)
    bwd_packets = _clip(packet_count - fwd_packets, 1)
    fwd_bytes = byte_count * rng.uniform(0.3, 0.6, n)
    bwd_bytes = byte_count - fwd_bytes
    syn_count = rng.integers(1, 3, n)
    ack_count = syn_count + rng.integers(0, 3, n)
    return pd.DataFrame({
        "duration": duration,
        "packet_count": packet_count,
        "byte_count": byte_count,
        "packet_rate": packet_count / duration,
        "bytes_per_second": byte_count / duration,
        "fwd_packets": fwd_packets,
        "bwd_packets": bwd_packets,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "fwd_bwd_packet_ratio": fwd_packets / bwd_packets,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": rng.integers(0, 2, n),
        "rst_count": rng.integers(0, 1, n),
        "syn_ack_ratio": syn_count / np.maximum(ack_count, 1),
        "ttl_mean": rng.normal(64, 3, n),
        "ttl_stdev": _clip(rng.normal(0.5, 0.5, n), 0),
        "distinct_dst_ports": rng.integers(1, 2, n),
        "dns_qname_len_mean": rng.uniform(8, 25, n),
        "dns_query_rate": rng.uniform(0, 5, n),
        "beacon_observation_count": rng.integers(0, 3, n),
        "beacon_interval_jitter": rng.uniform(0.4, 1.5, n),
        "beacon_mean_bytes": rng.uniform(200, 3000, n),
        "dst_fanout_count_for_src": rng.integers(0, 2, n),
    })


def _syn_flood(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _base_benign(n, rng)
    duration = rng.uniform(1, 5, n)
    syn_count = rng.integers(200, 2000, n)
    ack_count = rng.integers(0, 20, n)
    packet_count = syn_count + ack_count
    df.update(pd.DataFrame({
        "duration": duration,
        "packet_count": packet_count,
        "byte_count": packet_count * rng.uniform(60, 80, n),
        "packet_rate": packet_count / duration,
        "bytes_per_second": (packet_count * 70) / duration,
        "fwd_packets": packet_count,
        "bwd_packets": ack_count + 1,
        "syn_count": syn_count,
        "ack_count": ack_count,
        "syn_ack_ratio": syn_count / np.maximum(ack_count, 1),
        "rst_count": rng.integers(0, 5, n),
    }))
    return df


def _dns_tunneling(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _base_benign(n, rng)
    df.update(pd.DataFrame({
        "dns_qname_len_mean": rng.uniform(55, 253, n),
        "dns_query_rate": rng.uniform(30, 200, n),
        "byte_count": rng.uniform(3000, 30000, n),
        "packet_count": rng.integers(30, 300, n),
        "duration": rng.uniform(5, 60, n),
    }))
    return df


def _data_exfiltration(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _base_benign(n, rng)
    duration = rng.uniform(10, 120, n)
    fwd_bytes = rng.uniform(20_000_000, 500_000_000, n)
    bwd_bytes = rng.uniform(10_000, 200_000, n)
    packet_count = rng.integers(5000, 200_000, n)
    df.update(pd.DataFrame({
        "duration": duration,
        "packet_count": packet_count,
        "byte_count": fwd_bytes + bwd_bytes,
        "packet_rate": packet_count / duration,
        "bytes_per_second": (fwd_bytes + bwd_bytes) / duration,
        "fwd_bytes": fwd_bytes,
        "bwd_bytes": bwd_bytes,
        "fwd_bwd_packet_ratio": rng.uniform(3, 20, n),
    }))
    return df


def _malware_beaconing(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _base_benign(n, rng)
    df.update(pd.DataFrame({
        "byte_count": rng.uniform(200, 4000, n),
        "duration": rng.uniform(0.1, 2, n),
        "beacon_observation_count": rng.integers(8, 60, n),
        "beacon_interval_jitter": rng.uniform(0.01, 0.12, n),  # low jitter = periodic
        "beacon_mean_bytes": rng.uniform(150, 1500, n),
        "dst_fanout_count_for_src": rng.integers(1, 2, n),  # single C2 host
    }))
    return df


def _botnet_c2(n: int, rng: np.random.Generator) -> pd.DataFrame:
    df = _base_benign(n, rng)
    df.update(pd.DataFrame({
        "byte_count": rng.uniform(200, 4000, n),
        "duration": rng.uniform(0.1, 2, n),
        "beacon_observation_count": rng.integers(8, 60, n),
        "beacon_interval_jitter": rng.uniform(0.01, 0.15, n),
        "beacon_mean_bytes": rng.uniform(150, 1500, n),
        "dst_fanout_count_for_src": rng.integers(3, 15, n),  # fan-out to many C2/peers
    }))
    return df


_GENERATORS = {
    "BENIGN": _base_benign,
    "SYN_FLOOD": _syn_flood,
    "DNS_TUNNELING": _dns_tunneling,
    "DATA_EXFILTRATION": _data_exfiltration,
    "MALWARE_BEACONING": _malware_beaconing,
    "BOTNET_C2": _botnet_c2,
}


def generate_dataset(n_per_class: int = 1500, seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    frames = []
    for label, gen in _GENERATORS.items():
        df = gen(n_per_class, rng)
        df = df[FEATURE_COLUMNS].copy()
        df["label"] = label
        frames.append(df)
    full = pd.concat(frames, ignore_index=True)
    full = full.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # shuffle
    return full


if __name__ == "__main__":
    ds = generate_dataset()
    print(ds["label"].value_counts())
    print(ds.describe().T[["mean", "std", "min", "max"]])
