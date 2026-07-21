"""
Unit tests for the Phase 1 rule engine.

These tests build synthetic PacketRecord / Flow objects directly, so they
run anywhere (no root privileges, no real NIC, no Scapy sniffing needed).
This is exactly the kind of test that should pass in CI.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from config import settings  # noqa: E402
from detection.rule_engine import RuleEngine  # noqa: E402
from packet_capture.models import Flow, PacketRecord, Protocol  # noqa: E402


def make_tcp_packet(src_ip, dst_ip, dst_port, syn=True, ack=False, src_port=40000):
    return PacketRecord(
        timestamp=time.time(),
        protocol=Protocol.TCP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length=60,
        ttl=64,
        flag_syn=syn,
        flag_ack=ack,
    )


def make_icmp_packet(src_ip, dst_ip):
    return PacketRecord(
        timestamp=time.time(),
        protocol=Protocol.ICMP,
        src_ip=src_ip,
        dst_ip=dst_ip,
        length=60,
        ttl=64,
    )


def make_arp_packet(sender_ip, sender_mac):
    return PacketRecord(
        timestamp=time.time(),
        protocol=Protocol.ARP,
        src_ip=sender_ip,
        dst_ip="0.0.0.0",
        length=42,
        arp_sender_ip=sender_ip,
        arp_sender_mac=sender_mac,
    )


def make_dns_packet(src_ip, qname):
    return PacketRecord(
        timestamp=time.time(),
        protocol=Protocol.DNS,
        src_ip=src_ip,
        dst_ip="8.8.8.8",
        src_port=53000,
        dst_port=53,
        length=90,
        dns_qname=qname,
        dns_is_query=True,
    )


def test_port_scan_detected():
    settings.rules.port_scan_distinct_ports = 5
    engine = RuleEngine()
    attacker, victim = "10.0.0.5", "10.0.0.10"

    detections = []
    for port in range(1, 8):
        detections += engine.process_packet(
            make_tcp_packet(attacker, victim, port, syn=True, ack=False)
        )

    assert any(d.attack_type == "Port Scan" for d in detections)
    d = next(d for d in detections if d.attack_type == "Port Scan")
    assert d.source_ip == attacker
    assert d.confidence > 0
    assert "distinct_destination_ports" in d.evidence


def test_host_discovery_detected():
    settings.rules.host_discovery_distinct_hosts = 4
    engine = RuleEngine()
    attacker = "10.0.0.5"

    detections = []
    for i in range(6):
        detections += engine.process_packet(make_icmp_packet(attacker, f"10.0.0.{i+1}"))

    assert any(d.attack_type == "Host Discovery (Ping Sweep)" for d in detections)


def test_ssh_bruteforce_detected():
    settings.rules.ssh_bruteforce_attempts = 5
    engine = RuleEngine()
    attacker, victim = "10.0.0.5", "10.0.0.20"

    detections = []
    for _ in range(7):
        detections += engine.process_packet(make_tcp_packet(attacker, victim, 22, syn=True, ack=False))

    assert any(d.attack_type == "SSH Brute Force" for d in detections)


def test_arp_spoof_detected():
    settings.rules.arp_spoof_mac_changes = 2
    engine = RuleEngine()
    gateway_ip = "192.168.1.1"

    detections = []
    detections += engine.process_packet(make_arp_packet(gateway_ip, "AA:AA:AA:AA:AA:AA"))
    detections += engine.process_packet(make_arp_packet(gateway_ip, "BB:BB:BB:BB:BB:BB"))

    assert any(d.attack_type == "ARP Spoofing" for d in detections)


def test_dns_tunneling_long_qname_detected():
    engine = RuleEngine()
    attacker = "10.0.0.5"
    # High-entropy (36-symbol alphabet, ~5.0 bits/char) leaf label, well
    # over the length threshold - simulates an actual encoded payload,
    # not just a long-but-readable CDN-style hostname.
    long_label = "lfxctncsbpcdp3eiw8uo9b4kfel3guxntcchyplvqk2zius50k9ep1frby1u5lzvuq48rxczx93.exfil.example.com"
    assert len(long_label) >= settings.rules.dns_tunnel_query_len_threshold

    detections = engine.process_packet(make_dns_packet(attacker, long_label))
    assert any(d.attack_type == "DNS Tunneling" for d in detections)


def test_data_exfiltration_flow_detected():
    settings.rules.exfil_bytes_out_threshold = 1000
    engine = RuleEngine()

    flow = Flow(
        key=(("10.0.0.5", 40000), ("203.0.113.9", 443), "TCP"),
        protocol=Protocol.TCP,
        src_ip="10.0.0.5",
        dst_ip="203.0.113.9",
        src_port=40000,
        dst_port=443,
    )
    flow.start_time = time.time() - 5
    flow.last_seen = time.time()
    flow.fwd_bytes = 5000
    flow.byte_count = 5000
    flow.packet_count = 10

    detections = engine.process_flow(flow)
    assert any(d.attack_type == "Data Exfiltration" for d in detections)


def test_no_false_positive_on_normal_traffic():
    """A handful of ordinary packets between two hosts should not trigger anything."""
    engine = RuleEngine()
    detections = []
    detections += engine.process_packet(make_tcp_packet("10.0.0.5", "10.0.0.10", 443, syn=True, ack=False))
    detections += engine.process_packet(make_tcp_packet("10.0.0.10", "10.0.0.5", 40000, syn=True, ack=True))
    assert detections == []


def test_dedup_suppresses_repeat_emissions():
    settings.rules.port_scan_distinct_ports = 3
    engine = RuleEngine()
    attacker, victim = "10.0.0.5", "10.0.0.10"

    all_detections = []
    for port in range(1, 6):
        all_detections += engine.process_packet(make_tcp_packet(attacker, victim, port))
    # Trigger again immediately - should be suppressed by the dedup cooldown.
    for port in range(6, 9):
        all_detections += engine.process_packet(make_tcp_packet(attacker, victim, port))

    port_scan_detections = [d for d in all_detections if d.attack_type == "Port Scan"]
    assert len(port_scan_detections) == 1
