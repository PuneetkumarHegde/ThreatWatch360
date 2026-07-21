import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import settings  # noqa: E402
from packet_capture.flow_manager import FlowManager  # noqa: E402
from packet_capture.models import PacketRecord, Protocol  # noqa: E402


def make_packet(src_ip, dst_ip, src_port, dst_port, length=100, syn=False, ack=False):
    return PacketRecord(
        timestamp=time.time(),
        protocol=Protocol.TCP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        ttl=64,
        flag_syn=syn,
        flag_ack=ack,
    )


def test_bidirectional_packets_map_to_same_flow():
    fm = FlowManager(on_flow_flush=lambda f: None)
    fm.ingest(make_packet("10.0.0.5", "10.0.0.10", 40000, 443, syn=True))
    fm.ingest(make_packet("10.0.0.10", "10.0.0.5", 443, 40000, syn=True, ack=True))
    fm.ingest(make_packet("10.0.0.5", "10.0.0.10", 40000, 443, ack=True))

    assert fm.active_flow_count() == 1
    flow = fm.snapshot()[0]
    assert flow.packet_count == 3
    assert flow.fwd_packets == 2  # two packets originated from 10.0.0.5
    assert flow.bwd_packets == 1
    assert flow.syn_count == 2
    assert flow.ack_count == 2


def test_flow_sweep_flushes_idle_flows():
    flushed = []
    fm = FlowManager(on_flow_flush=lambda f: flushed.append(f))
    fm.ingest(make_packet("10.0.0.5", "10.0.0.10", 40000, 443, syn=True))

    original_timeout = settings.capture.flow_idle_timeout
    settings.capture.flow_idle_timeout = 0.01
    try:
        time.sleep(0.05)
        n = fm.sweep()
        assert n == 1
        assert len(flushed) == 1
        assert fm.active_flow_count() == 0
    finally:
        settings.capture.flow_idle_timeout = original_timeout


def test_distinct_destination_ports_tracked():
    fm = FlowManager(on_flow_flush=lambda f: None)
    for port in (80, 443, 8080):
        fm.ingest(make_packet("10.0.0.5", "10.0.0.10", 40000 + port, port))
    # These are 3 separate flows (different port pairs), each with 1 dst port
    for flow in fm.snapshot():
        assert len(flow.dst_ports_seen) == 1
