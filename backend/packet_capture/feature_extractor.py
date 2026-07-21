"""
AlertIQ 2.0 - Phase 1 Feature Extraction
-------------------------------------------
Turns a completed Flow into a flat, numeric feature dict. This dict is
consumed by:
  - the rule engine (Phase 1, this delivery)
  - the ML pipeline / SHAP explainer (Phase 2)

Keeping this as one canonical function means both the rule engine and
the future ML model see EXACTLY the same features, which is what makes
the SHAP explanations meaningful later ("SYN Count", "Flow Duration",
"Destination Ports" etc. map directly to real, human-readable fields).
"""
from __future__ import annotations

from statistics import pstdev
from typing import Any

from packet_capture.models import Flow


def extract_features(flow: Flow) -> dict[str, Any]:
    duration = flow.duration()
    ttl_values = flow.ttl_values or [0]

    return {
        "flow_id": flow.flow_id,
        "protocol": flow.protocol.value,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,

        # Volume / timing
        "duration": round(duration, 3),
        "packet_count": flow.packet_count,
        "byte_count": flow.byte_count,
        "packet_rate": round(flow.packet_rate(), 3),
        "bytes_per_second": round(flow.byte_count / duration, 3) if duration > 0 else float(flow.byte_count),

        # Directionality
        "fwd_packets": flow.fwd_packets,
        "bwd_packets": flow.bwd_packets,
        "fwd_bytes": flow.fwd_bytes,
        "bwd_bytes": flow.bwd_bytes,
        "fwd_bwd_packet_ratio": round(flow.fwd_packets / flow.bwd_packets, 3) if flow.bwd_packets else float(flow.fwd_packets),

        # TCP flags
        "syn_count": flow.syn_count,
        "ack_count": flow.ack_count,
        "fin_count": flow.fin_count,
        "rst_count": flow.rst_count,
        "syn_ack_ratio": round(flow.syn_count / flow.ack_count, 3) if flow.ack_count else float(flow.syn_count),

        # Network-layer
        "ttl_mean": round(sum(ttl_values) / len(ttl_values), 2),
        "ttl_stdev": round(pstdev(ttl_values), 2) if len(ttl_values) > 1 else 0.0,
        "distinct_dst_ports": len(flow.dst_ports_seen),
    }
